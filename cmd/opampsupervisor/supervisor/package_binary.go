// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"

	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/config"
)

type binarySwitchState struct {
	Phase      string `json:"phase"`
	WasRunning bool   `json:"was_running"`
}

func (s *Supervisor) managedBinaryPath() string {
	name := "collector"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(s.config.Storage.Directory, "managed", name)
}

func (s *Supervisor) binarySwitchPath() string {
	return filepath.Join(s.config.Storage.Directory, "managed", "switch.json")
}

func (s *Supervisor) binaryBackupPath() string {
	return s.managedBinaryPath() + ".previous"
}

// prepareManagedBinary seeds a writable Collector executable from the
// installer-owned binary once, then keeps remote upgrades across Supervisor
// restarts. A later installer upgrade does not overwrite a remotely selected
// binary; the next OAS offer determines the desired version.
func (s *Supervisor) prepareManagedBinary() error {
	active := s.managedBinaryPath()
	if err := os.MkdirAll(filepath.Dir(active), 0o700); err != nil {
		return err
	}
	if err := s.recoverManagedBinary(); err != nil {
		return err
	}
	if _, statErr := os.Stat(active); errors.Is(statErr, os.ErrNotExist) {
		if copyErr := copyExecutable(s.config.Agent.Executable, active); copyErr != nil {
			return fmt.Errorf("seed managed Collector executable: %w", copyErr)
		}
	} else if statErr != nil {
		return statErr
	}
	s.config.Agent.Executable = active
	return nil
}

func copyExecutable(source, dest string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("collector executable must be a regular file")
	}
	temp, err := os.CreateTemp(filepath.Dir(dest), ".collector-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := io.Copy(temp, input); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), dest)
}

func (s *Supervisor) recoverManagedBinary() error {
	data, err := os.ReadFile(s.binarySwitchPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state binarySwitchState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("read binary switch journal: %w", err)
	}
	if generationData, err := os.ReadFile(filepath.Join(s.config.Storage.Directory, "packages", "generation.json")); err == nil {
		var generation packageGenerationJournal
		if decodeErr := json.Unmarshal(generationData, &generation); decodeErr != nil {
			return fmt.Errorf("read package generation journal: %w", decodeErr)
		}
		if generation.Phase == "committed" {
			state.Phase = "committed"
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	active, backup := s.managedBinaryPath(), s.binaryBackupPath()
	if state.Phase != "committed" {
		if _, err := os.Stat(backup); err == nil {
			if err := os.Remove(active); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := os.Rename(backup, active); err != nil {
				return err
			}
		}
	} else if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(s.binarySwitchPath())
}

func (s *Supervisor) writeBinarySwitchPhase(phase string) error {
	return s.writeBinarySwitchState(binarySwitchState{Phase: phase})
}

func (s *Supervisor) writeBinarySwitchState(state binarySwitchState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writePackageFileAtomic(s.binarySwitchPath(), data)
}

// installAgentBinary is the lifecycle hook used by PR 52751's package manager.
// The Supervisor stays alive while the Collector is switched and checked.
func (s *Supervisor) installAgentBinary(ctx context.Context, stagedPath string) error {
	s.binaryMu.Lock()
	defer s.binaryMu.Unlock()
	if s.commander == nil {
		return errors.New("collector commander is not ready")
	}
	state, ok := s.cfgState.Load().(*configState)
	if !ok || state.configMapIsEmpty {
		return errors.New("collector configuration is required to verify a binary update")
	}
	if err := func() error {
		s.configWriteMu.Lock()
		defer s.configWriteMu.Unlock()
		if err := s.removePreviousCollectorIdentity(); err != nil {
			return fmt.Errorf("remove previous Collector identity: %w", err)
		}
		if err := s.writeAgentConfig(); err != nil {
			return fmt.Errorf("write Collector configuration before binary update: %w", err)
		}
		return nil
	}(); err != nil {
		return err
	}
	active, backup := s.managedBinaryPath(), s.binaryBackupPath()
	info, err := os.Stat(stagedPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("staged Collector executable is empty or not regular")
	}
	wasRunning := s.commander.IsRunning()
	if err := s.writeBinarySwitchState(binarySwitchState{Phase: "switching", WasRunning: wasRunning}); err != nil {
		return err
	}
	s.agentRestarting.Store(true)
	defer s.agentRestarting.Store(false)
	s.resetAgentReady()
	if err := s.commander.Stop(ctx); err != nil {
		_ = os.Remove(s.binarySwitchPath())
		return fmt.Errorf("stop previous Collector: %w", err)
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		if wasRunning {
			return errors.Join(err, s.startManagedCollector())
		}
		return err
	}
	if err := os.Rename(active, backup); err != nil {
		if wasRunning {
			return errors.Join(fmt.Errorf("back up Collector executable: %w", err), s.startManagedCollector())
		}
		return fmt.Errorf("back up Collector executable: %w", err)
	}
	if err := os.Rename(stagedPath, active); err != nil {
		restoreErr := os.Rename(backup, active)
		if wasRunning && restoreErr == nil {
			restoreErr = s.startManagedCollector()
		}
		return errors.Join(fmt.Errorf("publish Collector executable: %w", err), restoreErr)
	}
	// The replacement process must outlive the offer's cancellation context.
	startErr := s.startManagedCollector()
	if startErr == nil {
		startErr = s.waitForAgentReady()
	}
	if startErr != nil {
		_ = s.commander.Stop(ctx)
		if restoreErr := os.Remove(active); restoreErr != nil && !errors.Is(restoreErr, os.ErrNotExist) {
			return errors.Join(startErr, restoreErr)
		}
		if restoreErr := os.Rename(backup, active); restoreErr != nil {
			return errors.Join(startErr, fmt.Errorf("restore previous Collector: %w", restoreErr))
		}
		if wasRunning {
			if restoreErr := s.startManagedCollector(); restoreErr != nil {
				return errors.Join(startErr, fmt.Errorf("restart previous Collector: %w", restoreErr))
			}
		}
		_ = os.Remove(s.binarySwitchPath())
		return fmt.Errorf("new Collector failed startup: %w", startErr)
	}
	return nil
}

// removePreviousCollectorIdentity prevents a replacement binary from
// inheriting service.name and service.version through the previous process's
// AgentDescription-derived telemetry resource. The replacement reports its
// own identity after it starts.
func (s *Supervisor) removePreviousCollectorIdentity() error {
	state, ok := s.cfgState.Load().(*configState)
	if !ok {
		return errors.New("collector configuration is not available")
	}

	conf, err := config.NewConfFromYAML([]byte(state.mergedConfig))
	if err != nil {
		return err
	}

	const attributesPath = "service::telemetry::resource::attributes"
	if attributes, attributesOK := conf.Get(attributesPath).([]any); attributesOK {
		filtered := make([]any, 0, len(attributes))
		for _, attribute := range attributes {
			value, valueOK := attribute.(map[string]any)
			name, nameOK := value["name"].(string)
			if valueOK && nameOK && (name == "service.name" || name == "service.version") {
				continue
			}
			filtered = append(filtered, attribute)
		}
		conf.Delete(attributesPath)
		if len(filtered) > 0 {
			if err := conf.Merge(confmap.NewFromStringMap(map[string]any{
				"service": map[string]any{
					"telemetry": map[string]any{
						"resource": map[string]any{"attributes": filtered},
					},
				},
			})); err != nil {
				return err
			}
		}
	}
	conf.Delete("service::telemetry::resource::service.name")
	conf.Delete("service::telemetry::resource::service.version")

	merged, err := config.MarshalConfToYAML(conf)
	if err != nil {
		return err
	}
	s.cfgState.Store(&configState{
		mergedConfig:     string(merged),
		configMapIsEmpty: state.configMapIsEmpty,
	})
	return nil
}

// A Collector process uses the Supervisor lifetime, not an individual
// package offer's lifetime, so canceling a superseded offer cannot stop it.
func (s *Supervisor) startManagedCollector() error {
	return s.commander.Start(s.runCtx)
}

// commitAgentBinary is called after the package ledger contains the running
// version. A crash before this point rolls back to the previous executable.
func (s *Supervisor) commitAgentBinary() error {
	s.binaryMu.Lock()
	defer s.binaryMu.Unlock()
	if err := s.writeBinarySwitchPhase("committed"); err != nil {
		return err
	}
	if err := os.Remove(s.binaryBackupPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.telemetrySettings.Logger.Warn("Could not remove previous Collector executable", zap.Error(err))
		return nil
	}
	if err := os.Remove(s.binarySwitchPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.telemetrySettings.Logger.Warn("Could not clear committed binary switch journal", zap.Error(err))
	}
	return nil
}

func (s *Supervisor) rollbackAgentBinary() error {
	s.binaryMu.Lock()
	defer s.binaryMu.Unlock()
	data, err := os.ReadFile(s.binarySwitchPath())
	if err != nil {
		return err
	}
	var state binarySwitchState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	s.agentRestarting.Store(true)
	defer s.agentRestarting.Store(false)
	if err := s.commander.Stop(s.runCtx); err != nil {
		return err
	}
	if err := os.Remove(s.managedBinaryPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(s.binaryBackupPath(), s.managedBinaryPath()); err != nil {
		return err
	}
	if state.WasRunning {
		if err := s.startManagedCollector(); err != nil {
			return err
		}
	}
	return os.Remove(s.binarySwitchPath())
}
