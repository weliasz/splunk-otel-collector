// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/open-telemetry/opamp-go/protobufs"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/addon"
)

const addonConfigRole = "addon-config"

// addonConfigs extracts addon configuration from a remote config. An entry
// configures an addon when its role is addonConfigRole; its key is the addon's
// package name, "<type>:<name>", so the same key identifies the addon in
// PackagesAvailable, PackageStatuses and the config map.
//
// The role, not the key's shape, decides what is addon configuration. Config
// map keys are free-form, and a Collector config entry whose key happened to
// look like "file:base.yaml" must not be taken for addon configuration.
func addonConfigs(remoteConfig *protobufs.AgentRemoteConfig) map[string][]byte {
	configs := map[string][]byte{}
	for name, entry := range remoteConfig.GetConfig().GetConfigMap() {
		if entry.GetRole() == addonConfigRole {
			configs[name] = entry.GetBody()
		}
	}
	return configs
}

// reconcileAddons configures and starts installed addons against the latest
// remote config, reports the outcome to the server, and returns whether any of
// them needs the Collector restarted.
func (s *Supervisor) reconcileAddons(ctx context.Context) addon.Effect {
	if s.addons == nil {
		return addon.Effect{}
	}

	remoteConfig := s.remoteConfig.Load()
	result, err := s.addons.Reconcile(ctx, addonConfigs(remoteConfig))
	if err != nil {
		s.telemetrySettings.Logger.Error("Could not reconcile all addons", zap.Error(err))
	}

	s.reportAddonConfigErrors(remoteConfig, result.ConfigErrors)
	s.updateAddonEffectiveConfig(ctx)

	return result.Effect
}

// addonConfigError records that addons rejected the configuration offered in
// the remote config with the given hash.
type addonConfigError struct {
	hash    []byte
	message string
}

// reportAddonConfigErrors reports addons rejecting their configuration as a
// FAILED RemoteConfigStatus. The error is tied to the hash of the remote config
// it was found in, so that it keeps a later APPLIED for the same config from
// hiding it (see saveAndReportConfigStatus), and stops applying once a new
// config arrives.
func (s *Supervisor) reportAddonConfigErrors(remoteConfig *protobufs.AgentRemoteConfig, errs map[string]error) {
	if !s.config.Capabilities.AcceptsRemoteConfig || remoteConfig == nil {
		return
	}

	if len(errs) > 0 {
		names := make([]string, 0, len(errs))
		for name := range errs {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, fmt.Sprintf("addon %q rejected its configuration: %v", name, errs[name]))
		}
		message := strings.Join(parts, "; ")

		s.addonConfigErr.Store(&addonConfigError{hash: bytes.Clone(remoteConfig.GetConfigHash()), message: message})
		s.saveAndReportConfigStatus(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, message)
		return
	}

	// The addons now accept the current config. If the reported failure was
	// ours, nothing else is wrong with this config, so it is applied.
	previous := s.addonConfigErr.Swap(nil)
	if previous == nil || !bytes.Equal(previous.hash, remoteConfig.GetConfigHash()) {
		return
	}
	last := s.persistentState.GetLastRemoteConfigStatus()
	if last != nil &&
		last.GetStatus() == protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED &&
		last.GetErrorMessage() == previous.message &&
		bytes.Equal(last.GetLastRemoteConfigHash(), previous.hash) {
		s.saveAndReportConfigStatus(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, "")
	}
}

// updateAddonEffectiveConfig tells the OpAMP client the effective config changed
// when the configuration addons run with changed.
func (s *Supervisor) updateAddonEffectiveConfig(ctx context.Context) {
	applied := s.addons.AppliedConfigs()

	s.addonEffectiveMu.Lock()
	changed := !maps.EqualFunc(applied, s.addonEffective, bytes.Equal)
	s.addonEffective = applied
	s.addonEffectiveMu.Unlock()

	if !changed || s.opampClient == nil {
		return
	}
	if err := s.opampClient.UpdateEffectiveConfig(ctx); err != nil {
		s.telemetrySettings.Logger.Error("The OpAMP client failed to update the effective config", zap.Error(err))
	}
}

// withAddonEffectiveConfig adds the configuration each addon runs with to an
// effective config, under the same key and role it is offered with in the
// remote config. The given config is not modified.
func (s *Supervisor) withAddonEffectiveConfig(cfg *protobufs.EffectiveConfig) *protobufs.EffectiveConfig {
	s.addonEffectiveMu.Lock()
	applied := maps.Clone(s.addonEffective)
	s.addonEffectiveMu.Unlock()

	if len(applied) == 0 {
		return cfg
	}

	out := &protobufs.EffectiveConfig{}
	if cfg != nil {
		out = proto.Clone(cfg).(*protobufs.EffectiveConfig)
	}
	if out.ConfigMap == nil {
		out.ConfigMap = &protobufs.AgentConfigMap{}
	}
	if out.ConfigMap.ConfigMap == nil {
		out.ConfigMap.ConfigMap = map[string]*protobufs.AgentConfigObject{}
	}

	offered := s.remoteConfig.Load().GetConfig().GetConfigMap()
	for name, body := range applied {
		out.ConfigMap.ConfigMap[name] = &protobufs.AgentConfigObject{
			Body:        body,
			ContentType: offered[name].GetContentType(),
			Role:        addonConfigRole,
		}
	}
	return out
}

// signalAgentRestart asks the agent loop to restart the Collector. The signal
// is coalesced, so concurrent requests cause a single restart.
func (s *Supervisor) signalAgentRestart() {
	select {
	case s.hasNewConfig <- struct{}{}:
	default:
	}
}

// startAddons loads the addons installed by a previous run and reconciles
// them against the persisted remote config. It runs before the Collector is
// first started, so addons the Collector reads are in place when it starts and
// their restart requests can be ignored.
func (s *Supervisor) startAddons(ctx context.Context) {
	if s.packageOffers == nil {
		return
	}
	if err := s.packageOffers.loadInstalledAddons(ctx); err != nil {
		s.telemetrySettings.Logger.Error("Could not load previously installed addons", zap.Error(err))
	}
	_ = s.reconcileAddons(ctx)
}

// stopAddons shuts down every addon. Called during shutdown so that the
// Supervisor does not leave orphaned children behind, which is the failure
// mode that made in-Collector subprocess management unworkable.
func (s *Supervisor) stopAddons(ctx context.Context) {
	if s.addons == nil {
		return
	}
	if err := s.addons.Shutdown(ctx); err != nil {
		s.telemetrySettings.Logger.Error("Could not shut down all addons", zap.Error(err))
	}
}
