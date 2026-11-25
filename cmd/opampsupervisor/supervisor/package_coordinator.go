// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor/supervisor/addon"
)

const maxDownloadBytes int64 = 128 << 20

type installedPackage struct {
	Type        protobufs.PackageType `json:"type"`
	Hash        []byte                `json:"hash"`
	Version     string                `json:"version"`
	ContentHash []byte                `json:"content_hash"`
}

type packageLedger struct {
	Version  int                          `json:"version"`
	Packages map[string]*installedPackage `json:"packages"`
}

type packageGenerationJournal struct {
	Phase    string                       `json:"phase"`
	Previous map[string]*installedPackage `json:"previous"`
	Touched  []string                     `json:"touched"`
}

// packageCoordinator owns the complete offer. The SDK's package syncer cannot
// wait for addon configuration or preserve a failed removal in its inventory,
// so OnMessage reconciles the offer here and publishes the resulting snapshot.
type packageCoordinator struct {
	mu             sync.Mutex
	logger         *zap.Logger
	root           string
	top            *packageManager
	addons         *addon.Manager
	ledger         packageLedger
	generation     *packageGenerationJournal
	client         *http.Client
	publish        func(*protobufs.PackageStatuses)
	allowHTTPHosts []string
}

func newPackageCoordinator(logger *zap.Logger, storageDir string, top *packageManager, addons *addon.Manager, allowHTTPHosts []string, publish func(*protobufs.PackageStatuses)) (*packageCoordinator, error) {
	root := filepath.Join(storageDir, "packages")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create package storage: %w", err)
	}
	c := &packageCoordinator{
		logger: logger,
		root:   root,
		top:    top,
		addons: addons,
		ledger: packageLedger{Version: 1, Packages: map[string]*installedPackage{}},
		client: &http.Client{
			Timeout: 2 * time.Minute,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("package download redirects are not allowed")
			},
		},
		publish:        publish,
		allowHTTPHosts: allowHTTPHosts,
	}
	data, err := os.ReadFile(c.ledgerPath())
	if err == nil {
		if decodeErr := json.Unmarshal(data, &c.ledger); decodeErr != nil {
			return nil, fmt.Errorf("decode package ledger: %w", decodeErr)
		}
		if c.ledger.Version != 1 || c.ledger.Packages == nil {
			return nil, errors.New("unsupported package ledger version")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read package ledger: %w", err)
	}
	if err := c.recoverGeneration(); err != nil {
		return nil, err
	}
	if record := c.ledger.Packages[agentPackageKey]; record != nil {
		top.topLevelHash = bytes.Clone(record.Hash)
		top.topLevelVersion = record.Version
	}
	return c, nil
}

func (c *packageCoordinator) ledgerPath() string { return filepath.Join(c.root, "ledger.json") }

func (c *packageCoordinator) generationPath() string { return filepath.Join(c.root, "generation.json") }

func cloneInstalledPackages(source map[string]*installedPackage) map[string]*installedPackage {
	cloned := make(map[string]*installedPackage, len(source))
	for name, record := range source {
		value := *record
		value.Hash = bytes.Clone(record.Hash)
		value.ContentHash = bytes.Clone(record.ContentHash)
		cloned[name] = &value
	}
	return cloned
}

func (c *packageCoordinator) writeGeneration() error {
	data, err := json.Marshal(c.generation)
	if err != nil {
		return err
	}
	return writePackageFileAtomic(c.generationPath(), data)
}

func (c *packageCoordinator) beginGeneration() error {
	c.generation = &packageGenerationJournal{Phase: "pending", Previous: cloneInstalledPackages(c.ledger.Packages)}
	if err := c.writeGeneration(); err != nil {
		c.generation = nil
		return err
	}
	return nil
}

func (c *packageCoordinator) touchAddon(name string) error {
	if c.generation == nil || slices.Contains(c.generation.Touched, name) {
		return nil
	}
	c.generation.Touched = append(c.generation.Touched, name)
	return c.writeGeneration()
}

func (c *packageCoordinator) recoverGeneration() error {
	data, err := os.ReadFile(c.generationPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal packageGenerationJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return fmt.Errorf("decode package generation journal: %w", err)
	}
	if journal.Previous == nil {
		return errors.New("package generation journal is missing previous state")
	}
	for _, name := range journal.Touched {
		final := c.addonDir(name)
		backup := final + ".old"
		removed := final + ".removed"
		if journal.Phase == "committed" {
			if err := os.RemoveAll(backup); err != nil {
				return err
			}
			if err := os.RemoveAll(removed); err != nil {
				return err
			}
			if c.ledger.Packages[name] == nil {
				if err := os.RemoveAll(c.packageDir(name)); err != nil {
					return err
				}
			}
			continue
		}
		if _, err := os.Stat(backup); err == nil {
			if err := os.RemoveAll(final); err != nil {
				return err
			}
			if err := os.Rename(backup, final); err != nil {
				return err
			}
		} else if _, err := os.Stat(removed); err == nil {
			if err := os.Rename(removed, final); err != nil {
				return err
			}
		} else if journal.Previous[name] == nil {
			if err := os.RemoveAll(final); err != nil {
				return err
			}
		}
	}
	if journal.Phase != "committed" {
		c.ledger.Packages = cloneInstalledPackages(journal.Previous)
		if err := c.persist(); err != nil {
			return err
		}
	}
	return os.Remove(c.generationPath())
}

func (c *packageCoordinator) finishGeneration(ctx context.Context, committed bool) error {
	if c.generation == nil {
		return nil
	}
	if committed {
		c.generation.Phase = "committed"
		if err := c.writeGeneration(); err != nil {
			return err
		}
	} else {
		touched := slices.Clone(c.generation.Touched)
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		for _, name := range touched {
			_ = c.addons.Unload(rollbackCtx, name)
		}
		if err := c.recoverGeneration(); err != nil {
			return err
		}
		for _, name := range touched {
			if c.ledger.Packages[name] != nil {
				if err := c.addons.Load(rollbackCtx, name, c.addonDir(name)); err != nil {
					return err
				}
			}
		}
		c.generation = nil
		return nil
	}
	if err := c.recoverGeneration(); err != nil {
		return err
	}
	c.generation = nil
	return nil
}

func (c *packageCoordinator) persist() error {
	data, err := json.Marshal(c.ledger)
	if err != nil {
		return err
	}
	return writePackageFileAtomic(c.ledgerPath(), data)
}

func writePackageFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".opamp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (c *packageCoordinator) packageDir(name string) string {
	sum := sha256.Sum256([]byte(name))
	return filepath.Join(c.root, hex.EncodeToString(sum[:]))
}

func (c *packageCoordinator) addonDir(name string) string {
	return filepath.Join(c.packageDir(name), "files")
}

func (c *packageCoordinator) cachePath(name string, hash []byte) string {
	return filepath.Join(c.packageDir(name), "content-"+hex.EncodeToString(hash))
}

func (c *packageCoordinator) loadInstalledAddons(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for name, record := range c.ledger.Packages {
		if record.Type != protobufs.PackageType_PackageType_Addon {
			continue
		}
		if err := c.recoverAddon(name); err != nil {
			errs = append(errs, fmt.Errorf("recover addon %q: %w", name, err))
			continue
		}
		if err := c.addons.Load(ctx, name, c.addonDir(name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Reconcile handles a complete packages_available assignment. A nil offer is
// never passed here: omitted fields leave the previous assignment untouched.
func (c *packageCoordinator) Reconcile(ctx context.Context, offer *protobufs.PackagesAvailable, configs map[string][]byte) (addon.Effect, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != nil && c.generation.Phase == "pending" {
		if err := c.finishGeneration(ctx, false); err != nil {
			return addon.Effect{}, fmt.Errorf("recover previous package generation: %w", err)
		}
	}
	if c.generation != nil && c.generation.Phase == "committed" {
		if transaction, ok := c.top.am.(interface{ commitAgentBinary() error }); ok {
			if err := transaction.commitAgentBinary(); err != nil {
				return addon.Effect{}, fmt.Errorf("finish previous Collector switch: %w", err)
			}
		}
		if err := c.finishGeneration(ctx, true); err != nil {
			return addon.Effect{}, fmt.Errorf("finish previous package generation: %w", err)
		}
	}
	if offer == nil {
		return addon.Effect{}, nil
	}
	if err := ctx.Err(); err != nil {
		return addon.Effect{}, err
	}
	if len(offer.GetAllPackagesHash()) == 0 {
		err := errors.New("packages_available.all_packages_hash is required")
		c.report(&protobufs.PackageStatuses{ErrorMessage: err.Error()})
		return addon.Effect{}, err
	}
	statuses := &protobufs.PackageStatuses{
		Packages:                      map[string]*protobufs.PackageStatus{},
		ServerProvidedAllPackagesHash: bytes.Clone(offer.GetAllPackagesHash()),
	}
	for name, record := range c.ledger.Packages {
		statuses.Packages[name] = &protobufs.PackageStatus{
			Name: name, AgentHasHash: bytes.Clone(record.Hash), AgentHasVersion: record.Version,
			Status: protobufs.PackageStatusEnum_PackageStatusEnum_Installed,
		}
	}
	topOffer := offer.Packages[agentPackageKey]
	if topOffer != nil && topOffer.Type == protobufs.PackageType_PackageType_TopLevel {
		record := c.ledger.Packages[agentPackageKey]
		if record == nil || !bytes.Equal(record.Hash, topOffer.Hash) || record.Version != topOffer.Version || !c.installedExists(agentPackageKey, record.Type) {
			if err := c.beginGeneration(); err != nil {
				statuses.ErrorMessage = err.Error()
				c.report(statuses)
				return addon.Effect{}, err
			}
		}
	}

	var effect addon.Effect
	var errs []error
	if c.generation != nil {
		for name, record := range cloneInstalledPackages(c.ledger.Packages) {
			if cancelErr := ctx.Err(); cancelErr != nil {
				errs = append(errs, cancelErr)
				break
			}
			if record.Type != protobufs.PackageType_PackageType_Addon || offer.Packages[name] != nil {
				continue
			}
			if err := c.touchAddon(name); err != nil {
				errs = append(errs, err)
				continue
			}
			e, err := c.removeAddon(ctx, name)
			if err != nil {
				errs = append(errs, fmt.Errorf("remove addon %q: %w", name, err))
				continue
			}
			effect = effect.Merge(e)
			delete(statuses.Packages, name)
		}
	}
	names := make([]string, 0, len(offer.GetPackages()))
	for name := range offer.GetPackages() {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		if a == agentPackageKey {
			return 1
		}
		if b == agentPackageKey {
			return -1
		}
		return strings.Compare(a, b)
	})
	topCount := 0
	addonsConfiguredBeforeSwitch := false
	for _, name := range names {
		if cancelErr := ctx.Err(); cancelErr != nil {
			errs = append(errs, cancelErr)
			break
		}
		available := offer.Packages[name]
		status := statuses.Packages[name]
		if status == nil {
			status = &protobufs.PackageStatus{Name: name}
			statuses.Packages[name] = status
		}
		status.ServerOfferedHash = bytes.Clone(available.GetHash())
		status.ServerOfferedVersion = available.GetVersion()
		if available.GetType() == protobufs.PackageType_PackageType_TopLevel {
			topCount++
		}
		if err := c.validateOffer(name, available, topCount); err != nil {
			status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed
			status.ErrorMessage = err.Error()
			errs = append(errs, fmt.Errorf("package %q: %w", name, err))
			continue
		}
		if name == agentPackageKey && c.generation != nil && len(errs) != 0 {
			status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed
			status.ErrorMessage = "combined package generation contains a failed addon"
			continue
		}
		record := c.ledger.Packages[name]
		if record != nil && record.Type == available.Type && bytes.Equal(record.Hash, available.Hash) && record.Version == available.Version && c.installedExists(name, record.Type) {
			continue
		}
		status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_Downloading
		c.report(statuses)
		path, err := c.download(ctx, name, available.File)
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_Installing
			c.report(statuses)
			switch available.Type {
			case protobufs.PackageType_PackageType_TopLevel:
				if !addonsConfiguredBeforeSwitch {
					result, reconcileErr := c.addons.Reconcile(ctx, configs)
					effect = effect.Merge(result.Effect)
					if reconcileErr != nil {
						c.logger.Warn("Addon configuration was rejected before Collector switch", zap.Error(reconcileErr))
					}
					addonsConfiguredBeforeSwitch = true
				}
				err = c.installTopLevel(ctx, name, available, path)
				if err == nil {
					effect.BinarySwitched = true
				}
			case protobufs.PackageType_PackageType_Addon:
				var e addon.Effect
				if touchErr := c.touchAddon(name); touchErr != nil {
					err = touchErr
				} else {
					e, err = c.installAddon(ctx, name, available, path, configs[name])
				}
				effect = effect.Merge(e)
			}
		}
		if err != nil {
			status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed
			status.ErrorMessage = err.Error()
			errs = append(errs, fmt.Errorf("package %q: %w", name, err))
			c.report(statuses)
			continue
		}
		status.Status = protobufs.PackageStatusEnum_PackageStatusEnum_Installed
		status.ErrorMessage = ""
		status.AgentHasHash = bytes.Clone(available.Hash)
		status.AgentHasVersion = available.Version
		if c.generation == nil {
			c.report(statuses)
		}
	}

	for name, record := range cloneInstalledPackages(c.ledger.Packages) {
		if c.generation != nil {
			break
		}
		if cancelErr := ctx.Err(); cancelErr != nil {
			errs = append(errs, cancelErr)
			break
		}
		if record.Type != protobufs.PackageType_PackageType_Addon || offer.Packages[name] != nil {
			continue
		}
		e, err := c.removeAddon(ctx, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("remove addon %q: %w", name, err))
			continue
		}
		effect = effect.Merge(e)
		delete(statuses.Packages, name)
	}
	if c.generation != nil {
		if !effect.BinarySwitched {
			previous := cloneInstalledPackages(c.generation.Previous)
			if err := c.finishGeneration(ctx, false); err != nil {
				errs = append(errs, fmt.Errorf("roll back combined package generation: %w", err))
			}
			for name := range statuses.Packages {
				if name == agentPackageKey {
					continue
				}
				if old := previous[name]; old != nil {
					statuses.Packages[name].AgentHasHash = bytes.Clone(old.Hash)
					statuses.Packages[name].AgentHasVersion = old.Version
				} else {
					statuses.Packages[name].AgentHasHash = nil
					statuses.Packages[name].AgentHasVersion = ""
				}
				if statuses.Packages[name].Status == protobufs.PackageStatusEnum_PackageStatusEnum_Installed && offer.Packages[name] != nil {
					statuses.Packages[name].Status = protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed
					statuses.Packages[name].ErrorMessage = "rolled back with failed Collector update"
				}
			}
			for name, old := range previous {
				if old.Type == protobufs.PackageType_PackageType_Addon && statuses.Packages[name] == nil {
					statuses.Packages[name] = &protobufs.PackageStatus{
						Name: name, AgentHasHash: bytes.Clone(old.Hash), AgentHasVersion: old.Version,
						Status: protobufs.PackageStatusEnum_PackageStatusEnum_Installed,
					}
				}
			}
			effect = addon.Effect{}
		} else {
			c.generation.Phase = "committed"
			if err := c.writeGeneration(); err != nil {
				errs = append(errs, err)
				if transaction, ok := c.top.am.(interface{ rollbackAgentBinary() error }); ok {
					errs = append(errs, transaction.rollbackAgentBinary())
				}
				if rollbackErr := c.finishGeneration(ctx, false); rollbackErr != nil {
					errs = append(errs, rollbackErr)
				}
				effect = addon.Effect{}
				statuses.Packages[agentPackageKey].Status = protobufs.PackageStatusEnum_PackageStatusEnum_InstallFailed
				statuses.Packages[agentPackageKey].ErrorMessage = "could not commit package generation"
				if stateErr := c.restoreTopPackageState(statuses.Packages[agentPackageKey]); stateErr != nil {
					errs = append(errs, stateErr)
				}
			} else {
				binaryCommitted := true
				if transaction, ok := c.top.am.(interface{ commitAgentBinary() error }); ok {
					if err := transaction.commitAgentBinary(); err != nil {
						c.logger.Warn("Binary switch cleanup will be retried", zap.Error(err))
						binaryCommitted = false
					}
				}
				if binaryCommitted {
					if err := c.finishGeneration(ctx, true); err != nil {
						c.logger.Warn("Package generation cleanup will continue on next startup", zap.Error(err))
					}
				}
			}
		}
	}
	if len(errs) == 0 {
		if err := c.top.SetAllPackagesHash(offer.AllPackagesHash); err != nil {
			errs = append(errs, err)
		}
	}
	c.report(statuses)
	return effect, errors.Join(errs...)
}

func (c *packageCoordinator) restoreTopPackageState(status *protobufs.PackageStatus) error {
	if old := c.ledger.Packages[agentPackageKey]; old != nil {
		status.AgentHasHash = bytes.Clone(old.Hash)
		status.AgentHasVersion = old.Version
		return c.top.SetPackageState(agentPackageKey, types.PackageState{Exists: true, Type: old.Type, Hash: old.Hash, Version: old.Version})
	}
	hash, err := fileSHA256(c.top.agentPath)
	if err != nil {
		return err
	}
	status.AgentHasHash = hash
	status.AgentHasVersion = ""
	return c.top.SetPackageState(agentPackageKey, types.PackageState{Exists: true, Type: protobufs.PackageType_PackageType_TopLevel, Hash: hash})
}

func (c *packageCoordinator) report(statuses *protobufs.PackageStatuses) {
	snapshot := proto.Clone(statuses).(*protobufs.PackageStatuses)
	if err := c.top.SetLastReportedStatuses(snapshot); err != nil {
		c.logger.Error("Could not persist package statuses", zap.Error(err))
	}
	if c.publish != nil {
		c.publish(snapshot)
	}
}

func (c *packageCoordinator) validateOffer(name string, available *protobufs.PackageAvailable, topCount int) error {
	if available == nil || available.GetFile() == nil {
		return errors.New("package file is required")
	}
	if len(available.GetHash()) == 0 || available.GetVersion() == "" {
		return errors.New("package hash and version are required")
	}
	if len(available.File.GetContentHash()) != sha256.Size {
		return errors.New("package file content_hash must be SHA-256")
	}
	switch available.Type {
	case protobufs.PackageType_PackageType_TopLevel:
		if name != agentPackageKey || topCount != 1 {
			return errors.New("only one top-level Collector package with the empty key is supported")
		}
	case protobufs.PackageType_PackageType_Addon:
		return c.addons.Supports(name)
	default:
		return fmt.Errorf("unsupported package type %v", available.Type)
	}
	return nil
}

func (c *packageCoordinator) installedExists(name string, typ protobufs.PackageType) bool {
	path := c.addonDir(name)
	if typ == protobufs.PackageType_PackageType_TopLevel {
		path = c.top.agentPath
	}
	_, err := os.Stat(path)
	return err == nil
}

func (c *packageCoordinator) download(ctx context.Context, name string, file *protobufs.DownloadableFile) (string, error) {
	path := c.cachePath(name, file.ContentHash)
	if sum, err := fileSHA256(path); err == nil && bytes.Equal(sum, file.ContentHash) {
		return path, nil
	}
	u, err := url.Parse(file.GetDownloadUrl())
	if err != nil || u.Host == "" {
		return "", errors.New("invalid package download URL")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !c.allowsHTTP(u)) {
		return "", errors.New("package downloads require HTTPS unless the HTTP host is loopback or listed in agent.package.allow_http_hosts")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	for _, h := range file.GetHeaders().GetHeaders() {
		if h == nil || !validPackageHeader(h.GetKey(), h.GetValue()) {
			return "", errors.New("invalid package download header")
		}
		req.Header.Add(h.Key, h.Value)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("package download returned HTTP %d", resp.StatusCode)
	}
	if mkdirErr := os.MkdirAll(filepath.Dir(path), 0o700); mkdirErr != nil {
		return "", mkdirErr
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, hasher), io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxDownloadBytes {
		return "", fmt.Errorf("package exceeds maximum download size of %d bytes", maxDownloadBytes)
	}
	if !bytes.Equal(hasher.Sum(nil), file.ContentHash) {
		return "", errors.New("downloaded package SHA-256 does not match content_hash")
	}
	if err := temp.Sync(); err != nil {
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

func (c *packageCoordinator) allowsHTTP(u *url.URL) bool {
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() {
		return true
	}
	return slices.ContainsFunc(c.allowHTTPHosts, func(allowed string) bool {
		return strings.EqualFold(allowed, u.Host)
	})
}

func validPackageHeader(key, value string) bool {
	return key != "" && !strings.ContainsAny(key, " \t\r\n:") && !strings.ContainsAny(value, "\r\n")
}

func (c *packageCoordinator) installTopLevel(ctx context.Context, name string, available *protobufs.PackageAvailable, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := c.top.UpdateContent(ctx, name, available.File.DownloadUrl, f, available.File.ContentHash, available.File.Signature); err != nil {
		return err
	}
	previous := c.ledger.Packages[name]
	c.ledger.Packages[name] = &installedPackage{Type: available.Type, Hash: bytes.Clone(available.Hash), Version: available.Version, ContentHash: bytes.Clone(available.File.ContentHash)}
	if err := c.persist(); err != nil {
		c.ledger.Packages[name] = previous
		if transaction, ok := c.top.am.(interface{ rollbackAgentBinary() error }); ok {
			return errors.Join(err, transaction.rollbackAgentBinary())
		}
		return err
	}
	if err := c.top.SetPackageState(name, packageStateForOffer(available)); err != nil {
		c.ledger.Packages[name] = previous
		persistErr := c.persist()
		if rollback, ok := c.top.am.(interface{ rollbackAgentBinary() error }); ok {
			return errors.Join(err, persistErr, rollback.rollbackAgentBinary())
		}
		return errors.Join(err, persistErr)
	}
	// A combined generation commits the binary only after its addon ledger and
	// rollback journal have been committed together.
	if c.generation != nil {
		return nil
	}
	if transaction, ok := c.top.am.(interface{ commitAgentBinary() error }); ok {
		if err := transaction.commitAgentBinary(); err != nil {
			c.ledger.Packages[name] = previous
			persistErr := c.persist()
			var rollbackErr error
			if rollback, ok := c.top.am.(interface{ rollbackAgentBinary() error }); ok {
				rollbackErr = rollback.rollbackAgentBinary()
			}
			if previous != nil {
				_ = c.top.SetPackageState(name, types.PackageState{Exists: true, Type: previous.Type, Hash: previous.Hash, Version: previous.Version})
			}
			return errors.Join(err, persistErr, rollbackErr)
		}
	}
	return nil
}

func packageStateForOffer(available *protobufs.PackageAvailable) types.PackageState {
	return types.PackageState{
		Exists: true, Type: available.Type,
		Hash: bytes.Clone(available.Hash), Version: available.Version,
	}
}

func (c *packageCoordinator) installAddon(ctx context.Context, name string, available *protobufs.PackageAvailable, path string, config []byte) (addon.Effect, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return addon.Effect{}, err
	}
	final := c.addonDir(name)
	stage := final + ".new"
	backup := final + ".old"
	if err := os.RemoveAll(stage); err != nil {
		return addon.Effect{}, err
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return addon.Effect{}, err
	}
	defer os.RemoveAll(stage)
	if err := c.addons.Install(ctx, name, stage, content, available.File.DownloadUrl, available.File.Signature); err != nil {
		return addon.Effect{}, err
	}
	if err := c.addons.Prepare(ctx, name, stage, config); err != nil {
		return addon.Effect{}, err
	}
	if err := ctx.Err(); err != nil {
		return addon.Effect{}, err
	}
	if err := c.addons.Unload(ctx, name); err != nil {
		return addon.Effect{}, err
	}
	if err := os.RemoveAll(backup); err != nil {
		return addon.Effect{}, err
	}
	if _, err := os.Stat(final); err == nil {
		if err := os.Rename(final, backup); err != nil {
			return addon.Effect{}, err
		}
	}
	if err := os.Rename(stage, final); err != nil {
		_ = os.Rename(backup, final)
		return addon.Effect{}, err
	}
	if err := c.addons.Load(ctx, name, final); err != nil {
		_ = os.RemoveAll(final)
		_ = os.Rename(backup, final)
		if previous := c.ledger.Packages[name]; previous != nil {
			_ = c.addons.Load(ctx, name, final)
		}
		return addon.Effect{}, err
	}
	previous := c.ledger.Packages[name]
	c.ledger.Packages[name] = &installedPackage{Type: available.Type, Hash: bytes.Clone(available.Hash), Version: available.Version, ContentHash: bytes.Clone(available.File.ContentHash)}
	if err := c.persist(); err != nil {
		c.ledger.Packages[name] = previous
		_ = c.addons.Unload(ctx, name)
		_ = os.RemoveAll(final)
		_ = os.Rename(backup, final)
		if previous != nil {
			_ = c.addons.Load(ctx, name, final)
		}
		return addon.Effect{}, err
	}
	if c.generation == nil {
		if err := os.RemoveAll(backup); err != nil {
			c.logger.Warn("Could not remove addon backup", zap.String("addon", name), zap.Error(err))
		}
	}
	return addon.Effect{}, nil
}

func (c *packageCoordinator) removeAddon(ctx context.Context, name string) (addon.Effect, error) {
	effect, err := c.addons.Remove(ctx, name)
	if err != nil {
		return addon.Effect{}, err
	}
	final := c.addonDir(name)
	backup := final + ".removed"
	if err := os.Rename(final, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return addon.Effect{}, err
	}
	previous := c.ledger.Packages[name]
	delete(c.ledger.Packages, name)
	if err := c.persist(); err != nil {
		c.ledger.Packages[name] = previous
		_ = os.Rename(backup, final)
		return addon.Effect{}, err
	}
	if c.generation == nil {
		if err := os.RemoveAll(c.packageDir(name)); err != nil {
			c.logger.Warn("Could not remove retired addon data", zap.String("addon", name), zap.Error(err))
		}
	}
	return effect, nil
}

func (c *packageCoordinator) recoverAddon(name string) error {
	final := c.addonDir(name)
	backup := final + ".old"
	if _, err := os.Stat(backup); err == nil {
		if _, err := os.Stat(final); errors.Is(err, os.ErrNotExist) {
			return os.Rename(backup, final)
		}
		return os.RemoveAll(backup)
	}
	return nil
}
