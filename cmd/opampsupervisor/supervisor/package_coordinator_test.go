// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
	"go.uber.org/zap"

	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/addon"
	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/addon/fileaddon"
	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/commander"
	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/config"
)

type testBinaryInstaller struct{ active string }

func (i testBinaryInstaller) installAgentBinary(_ context.Context, staged string) error {
	if err := os.Remove(i.active); err != nil {
		return err
	}
	return os.Rename(staged, i.active)
}

type failingBinaryInstaller struct{}

func (failingBinaryInstaller) installAgentBinary(context.Context, string) error {
	return errors.New("new Collector did not start")
}

func newTestPackageCoordinator(t *testing.T, dir, binary string) (*packageCoordinator, *packageManager) {
	t.Helper()
	state, err := loadOrCreatePersistentState(filepath.Join(dir, "state.yaml"), "", zap.NewNop())
	require.NoError(t, err)
	top, err := newPackageManager(zap.NewNop(), binary, dir, "local", state, config.AgentPackage{}, testBinaryInstaller{binary})
	require.NoError(t, err)
	manager, err := addon.NewManager(zap.NewNop(), fileaddon.NewFactory())
	require.NoError(t, err)
	coordinator, err := newPackageCoordinator(zap.NewNop(), dir, top, manager, config.AgentPackage{}, nil)
	require.NoError(t, err)
	return coordinator, top
}

func packageOffer(typ protobufs.PackageType, version, url string, data []byte) *protobufs.PackageAvailable {
	sum := sha256.Sum256(data)
	return &protobufs.PackageAvailable{
		Type: typ, Version: version, Hash: []byte("identity:" + version),
		File: &protobufs.DownloadableFile{DownloadUrl: url, ContentHash: sum[:]},
	}
}

type packageTestTransport func(*http.Request) (*http.Response, error)

func (f packageTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPackageDownloadAllowsConfiguredHTTPHost(t *testing.T) {
	content := []byte("artifact")
	file := packageOffer(protobufs.PackageType_PackageType_Addon, "1", "http://192.0.2.1:8000/test.txt", content).File
	c := &packageCoordinator{root: t.TempDir()}
	requests := 0
	c.client = &http.Client{Transport: packageTestTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		require.Equal(t, file.DownloadUrl, r.URL.String())
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(content))}, nil
	})}

	_, err := c.download(t.Context(), "file:smoke", file)
	require.ErrorContains(t, err, "allow_http_hosts")
	c.allowHTTPHosts = []string{"192.0.2.1:9000"}
	_, err = c.download(t.Context(), "file:smoke", file)
	require.ErrorContains(t, err, "allow_http_hosts")
	require.Zero(t, requests)

	c.allowHTTPHosts = []string{"192.0.2.1:8000"}
	path, err := c.download(t.Context(), "file:smoke", file)
	require.NoError(t, err)
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, content, stored)
	require.Equal(t, 1, requests)
}

func TestPackageDownloadValidatesRedirectTargets(t *testing.T) {
	content := []byte("redirected artifact")
	file := packageOffer(protobufs.PackageType_PackageType_Addon, "1", "https://packages.example.com/test.txt", content).File
	file.Headers = &protobufs.Headers{Headers: []*protobufs.Header{{Key: "X-Download-Token", Value: "test-token"}}}
	c := &packageCoordinator{root: t.TempDir()}
	const target = "http://192.0.2.1:8000/test.txt"
	requests := 0
	c.client = &http.Client{
		CheckRedirect: c.checkDownloadRedirect,
		Transport: packageTestTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			if r.URL.String() == file.DownloadUrl {
				require.Equal(t, "test-token", r.Header.Get("X-Download-Token"))
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": {target}},
					Body:       http.NoBody,
				}, nil
			}
			require.Equal(t, target, r.URL.String())
			require.Empty(t, r.Header.Get("X-Download-Token"))
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(content))}, nil
		}),
	}
	_, err := c.download(t.Context(), "file:smoke", file)
	require.ErrorContains(t, err, "agent.package.allow_http")
	require.Equal(t, 1, requests)

	c.allowHTTP = true
	path, err := c.download(t.Context(), "file:smoke", file)
	require.NoError(t, err)
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, content, stored)
	require.Equal(t, 3, requests)
}

func TestPackageCoordinatorMixedOfferAndRemoval(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "collector")
	require.NoError(t, os.WriteFile(binary, []byte("old"), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/collector":
			_, _ = w.Write([]byte("new"))
		case "/geoip.mmdb":
			_, _ = w.Write([]byte("database"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	c, top := newTestPackageCoordinator(t, dir, binary)
	offer := &protobufs.PackagesAvailable{
		AllPackagesHash: []byte("generation-1"),
		Packages: map[string]*protobufs.PackageAvailable{
			"":           packageOffer(protobufs.PackageType_PackageType_TopLevel, "2", server.URL+"/collector", []byte("new")),
			"file:geoip": packageOffer(protobufs.PackageType_PackageType_Addon, "1", server.URL+"/geoip.mmdb", []byte("database")),
		},
	}
	effect, err := c.Reconcile(t.Context(), offer, nil)
	require.NoError(t, err)
	require.True(t, effect.BinarySwitched)
	actual, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.Equal(t, "new", string(actual))
	actual, err = os.ReadFile(filepath.Join(c.addonDir("file:geoip"), "geoip.mmdb"))
	require.NoError(t, err)
	require.Equal(t, "database", string(actual))
	statuses, err := top.LastReportedStatuses()
	require.NoError(t, err)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_Installed, statuses.Packages[""].Status)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_Installed, statuses.Packages["file:geoip"].Status)
	require.Equal(t, []byte("generation-1"), statuses.ServerProvidedAllPackagesHash)

	// The persisted ledger and package statuses survive a Supervisor restart.
	reloaded, _ := newTestPackageCoordinator(t, dir, binary)
	require.NoError(t, reloaded.loadInstalledAddons(t.Context()))
	require.Equal(t, "2", reloaded.ledger.Packages[""].Version)
	require.Equal(t, "1", reloaded.ledger.Packages["file:geoip"].Version)

	// An omitted field is unchanged; a present empty assignment removes only
	// remotely managed addons, never the running Collector executable.
	_, err = reloaded.Reconcile(t.Context(), nil, nil)
	require.NoError(t, err)
	effect, err = reloaded.Reconcile(t.Context(), &protobufs.PackagesAvailable{AllPackagesHash: []byte("generation-2")}, nil)
	require.NoError(t, err)
	require.True(t, effect.RestartProcess)
	require.NoFileExists(t, reloaded.addonDir("file:geoip"))
	require.FileExists(t, binary)
	require.Contains(t, reloaded.ledger.Packages, "")
	require.NotContains(t, reloaded.ledger.Packages, "file:geoip")
}

func TestPackageCoordinatorRejectsBadContentWithoutReplacingAddon(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "collector")
	require.NoError(t, os.WriteFile(binary, []byte("old"), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("first"))
	}))
	defer server.Close()
	c, top := newTestPackageCoordinator(t, dir, binary)
	name := "file:geoip"
	first := packageOffer(protobufs.PackageType_PackageType_Addon, "1", server.URL+"/geoip.mmdb", []byte("first"))
	_, err := c.Reconcile(t.Context(), &protobufs.PackagesAvailable{AllPackagesHash: []byte("one"), Packages: map[string]*protobufs.PackageAvailable{name: first}}, nil)
	require.NoError(t, err)

	bad := packageOffer(protobufs.PackageType_PackageType_Addon, "2", server.URL+"/geoip.mmdb", []byte("different"))
	_, err = c.Reconcile(t.Context(), &protobufs.PackagesAvailable{AllPackagesHash: []byte("two"), Packages: map[string]*protobufs.PackageAvailable{name: bad}}, nil)
	require.ErrorContains(t, err, "SHA-256 does not match")
	actual, err := os.ReadFile(filepath.Join(c.addonDir(name), "geoip.mmdb"))
	require.NoError(t, err)
	require.Equal(t, "first", string(actual))
	statuses, err := top.LastReportedStatuses()
	require.NoError(t, err)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, statuses.Packages[name].Status)
	require.Equal(t, "1", statuses.Packages[name].AgentHasVersion)
	require.Equal(t, "2", statuses.Packages[name].ServerOfferedVersion)
	require.True(t, bytes.Equal(first.Hash, statuses.Packages[name].AgentHasHash))
}

func TestAddonRoleDoesNotBecomeCollectorYAML(t *testing.T) {
	remote := &protobufs.AgentRemoteConfig{Config: &protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigObject{
		"file:geoip": {Role: addonConfigRole, Body: []byte("state = enabled")},
		"":           {Body: []byte("receivers: {}")},
	}}}
	require.Equal(t, map[string][]byte{"file:geoip": []byte("state = enabled")}, addonConfigs(remote))
	s := &Supervisor{config: config.Supervisor{Capabilities: config.Capabilities{AcceptsRemoteConfig: true}}}
	require.Len(t, s.createRemoteConfigComposers(remote), 2) // YAML and required resource attributes
}

func TestManagedBinaryRecoversInterruptedSwitch(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "packaged-collector")
	require.NoError(t, os.WriteFile(seed, []byte("old"), 0o600))
	s := &Supervisor{config: config.Supervisor{
		Agent: config.Agent{Executable: seed}, Storage: config.Storage{Directory: dir},
	}}
	require.NoError(t, s.prepareManagedBinary())
	active := s.managedBinaryPath()
	actual, err := os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, "old", string(actual))

	require.NoError(t, s.writeBinarySwitchPhase("switching"))
	require.NoError(t, os.Rename(active, s.binaryBackupPath()))
	require.NoError(t, os.WriteFile(active, []byte("new"), 0o600))
	require.NoError(t, s.recoverManagedBinary())
	actual, err = os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, "old", string(actual))
	require.NoFileExists(t, s.binarySwitchPath())

	require.NoError(t, s.writeBinarySwitchPhase("committed"))
	require.NoError(t, os.Rename(active, s.binaryBackupPath()))
	require.NoError(t, os.WriteFile(active, []byte("new"), 0o600))
	require.NoError(t, s.recoverManagedBinary())
	actual, err = os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, "new", string(actual))
	require.NoFileExists(t, s.binaryBackupPath())
}

func TestRemovePreviousCollectorIdentity(t *testing.T) {
	tests := map[string]string{
		"declarative attributes": `
service:
  telemetry:
    resource:
      attributes:
        - name: service.name
          value: otelcol
        - name: service.version
          value: v0.165.1
        - name: service.instance.id
          value: instance-id
        - name: deployment.environment
          value: test
`,
		"legacy attributes": `
service:
  telemetry:
    resource:
      service.name: otelcol
      service.version: v0.165.1
      service.instance.id: instance-id
      deployment.environment: test
`,
	}

	for name, mergedConfig := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Supervisor{cfgState: &atomic.Value{}}
			s.cfgState.Store(&configState{mergedConfig: mergedConfig, configMapIsEmpty: true})

			require.NoError(t, s.removePreviousCollectorIdentity())

			state := s.cfgState.Load().(*configState)
			require.True(t, state.configMapIsEmpty)
			conf, err := config.NewConfFromYAML([]byte(state.mergedConfig))
			require.NoError(t, err)
			assert.False(t, conf.IsSet("service::telemetry::resource::service.name"))
			assert.False(t, conf.IsSet("service::telemetry::resource::service.version"))

			resource, ok := conf.Get("service::telemetry::resource").(map[string]any)
			require.True(t, ok)
			var resourceCfg otelconftelemetry.ResourceConfig
			require.NoError(t, confmap.NewFromStringMap(resource).Unmarshal(&resourceCfg))

			attributeValues := make(map[string]any, len(resourceCfg.Attributes)+len(resourceCfg.LegacyAttributes))
			for _, attribute := range resourceCfg.Attributes {
				attributeValues[attribute.Name] = attribute.Value
			}
			for attribute, value := range resourceCfg.LegacyAttributes {
				attributeValues[attribute] = value
			}
			assert.NotContains(t, attributeValues, "service.name")
			assert.NotContains(t, attributeValues, "service.version")
			assert.Equal(t, "instance-id", attributeValues["service.instance.id"])
			assert.Equal(t, "test", attributeValues["deployment.environment"])
		})
	}
}

func TestManagedBinaryRollsBackWhenNewProcessIsNotReady(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test uses a POSIX shell executable")
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "packaged-collector")
	require.NoError(t, os.WriteFile(seed, []byte("#!/bin/sh\nexit 0\n"), 0o700)) // #nosec G306 -- test executable
	s := &Supervisor{
		config: config.Supervisor{Agent: config.Agent{
			Executable: seed, BootstrapTimeout: 100 * time.Millisecond, StopGracePeriod: 100 * time.Millisecond,
		}, Storage: config.Storage{Directory: dir}},
		runCtx:         t.Context(),
		agentReadyChan: make(chan struct{}, 1),
		cfgState:       &atomic.Value{},
	}
	s.cfgState.Store(&configState{mergedConfig: "receivers: {}", configMapIsEmpty: false})
	require.NoError(t, s.prepareManagedBinary())
	command, err := commander.NewCommander(zap.NewNop(), filepath.Join(dir, "collector.log"), s.config.Agent)
	require.NoError(t, err)
	s.commander = command
	staged := filepath.Join(dir, "staged")
	require.NoError(t, os.WriteFile(staged, []byte("#!/bin/sh\nexit 9\n"), 0o700)) // #nosec G306 -- test executable
	require.ErrorContains(t, s.installAgentBinary(t.Context(), staged), "new Collector failed startup")
	actual, err := os.ReadFile(s.managedBinaryPath())
	require.NoError(t, err)
	require.Equal(t, "#!/bin/sh\nexit 0\n", string(actual))
	require.NoFileExists(t, s.binarySwitchPath())
}

func TestPackageCoordinatorRollsBackAddonWhenCollectorFails(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "collector")
	require.NoError(t, os.WriteFile(binary, []byte("old"), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collector" {
			_, _ = w.Write([]byte("new"))
		} else {
			_, _ = w.Write([]byte("database"))
		}
	}))
	defer server.Close()
	c, top := newTestPackageCoordinator(t, dir, binary)
	top.am = failingBinaryInstaller{}
	offer := &protobufs.PackagesAvailable{AllPackagesHash: []byte("mixed"), Packages: map[string]*protobufs.PackageAvailable{
		"":           packageOffer(protobufs.PackageType_PackageType_TopLevel, "2", server.URL+"/collector", []byte("new")),
		"file:geoip": packageOffer(protobufs.PackageType_PackageType_Addon, "1", server.URL+"/geoip.mmdb", []byte("database")),
	}}
	_, err := c.Reconcile(t.Context(), offer, nil)
	require.ErrorContains(t, err, "new Collector did not start")
	require.NotContains(t, c.ledger.Packages, "file:geoip")
	require.NoFileExists(t, c.addonDir("file:geoip"))
	statuses, err := top.LastReportedStatuses()
	require.NoError(t, err)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, statuses.Packages["file:geoip"].Status)
	require.Contains(t, statuses.Packages["file:geoip"].ErrorMessage, "rolled back")
	actual, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.Equal(t, "old", string(actual))
}

func TestPackageCoordinatorDoesNotSwitchCollectorWhenAddonFails(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "collector")
	require.NoError(t, os.WriteFile(binary, []byte("old"), 0o600))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collector" {
			_, _ = w.Write([]byte("new"))
		} else {
			_, _ = w.Write([]byte("unexpected"))
		}
	}))
	defer server.Close()
	c, top := newTestPackageCoordinator(t, dir, binary)
	offer := &protobufs.PackagesAvailable{AllPackagesHash: []byte("mixed"), Packages: map[string]*protobufs.PackageAvailable{
		"":           packageOffer(protobufs.PackageType_PackageType_TopLevel, "2", server.URL+"/collector", []byte("new")),
		"file:geoip": packageOffer(protobufs.PackageType_PackageType_Addon, "1", server.URL+"/geoip.mmdb", []byte("expected")),
	}}
	_, err := c.Reconcile(t.Context(), offer, nil)
	require.ErrorContains(t, err, "SHA-256 does not match")
	actual, err := os.ReadFile(binary)
	require.NoError(t, err)
	require.Equal(t, "old", string(actual))
	require.NotContains(t, c.ledger.Packages, "file:geoip")
	statuses, err := top.LastReportedStatuses()
	require.NoError(t, err)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, statuses.Packages[""].Status)
	require.Equal(t, protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed, statuses.Packages["file:geoip"].Status)
}

func TestPackageCoordinatorRecoversAddonGenerationAfterCrash(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "collector")
	require.NoError(t, os.WriteFile(binary, []byte("old"), 0o600))
	c, _ := newTestPackageCoordinator(t, dir, binary)
	name := "file:geoip"
	final := c.addonDir(name)
	require.NoError(t, os.MkdirAll(final, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(final, "geoip.mmdb"), []byte("old"), 0o600))
	c.ledger.Packages[name] = &installedPackage{Type: protobufs.PackageType_PackageType_Addon, Hash: []byte("old"), Version: "1"}
	require.NoError(t, c.persist())
	require.NoError(t, c.beginGeneration())
	require.NoError(t, c.touchAddon(name))
	require.NoError(t, os.Rename(final, final+".old"))
	require.NoError(t, os.MkdirAll(final, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(final, "geoip.mmdb"), []byte("new"), 0o600))
	c.ledger.Packages[name] = &installedPackage{Type: protobufs.PackageType_PackageType_Addon, Hash: []byte("new"), Version: "2"}
	require.NoError(t, c.persist())

	recovered, _ := newTestPackageCoordinator(t, dir, binary)
	require.Equal(t, "1", recovered.ledger.Packages[name].Version)
	actual, err := os.ReadFile(filepath.Join(final, "geoip.mmdb"))
	require.NoError(t, err)
	require.Equal(t, "old", string(actual))
	require.NoFileExists(t, recovered.generationPath())
}
