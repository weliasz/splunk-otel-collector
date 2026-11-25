# Upstream source

This module copies `cmd/opampsupervisor` from
`github.com/open-telemetry/opentelemetry-collector-contrib` at tag `v0.165.1`
(commit `6083b2c53d78b21d0925b703194aaed920c01af5`). The upstream source is
licensed under Apache-2.0; its `LICENSE`, copyright notices, tests, fixtures,
and generated metadata remain here.

The directory matches contrib's `cmd/opampsupervisor` layout. Its root is a
`main` package, while `supervisor/` is a public package that other
distributions can import. Keeping the upstream directory structure makes
future patch comparisons and rebases simpler.

Change 1 made the changes needed to publish the supervisor as an
independently importable Splunk module:

- Change the module path to
  `github.com/signalfx/splunk-otel-collector/cmd/opampsupervisor` and rewrite
  imports, import comments, and the test linker path for this module.
- Remove upstream's local `replace` directives for sibling contrib modules;
  those replacements do not propagate to a consuming module. The published
  versions in `go.mod` are the dependencies.
- Use the distribution's Go toolchain version. Keep the upstream telemetry
  instrumentation names so the module relocation does not rename existing
  signals.
- Keep the upstream field layout during the import. The module Makefile skips
  the repository's struct reordering formatter, and the root lint config
  excludes findings already present in this upstream snapshot. Addon packages
  added later remain subject to the normal lint checks.

Change 2 ports the top-level archive, verifier and persistent package manager
from [upstream PR 52751](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/52751).
It also ports the addon factory and lifecycle foundation from
[PR 52730](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/52730),
excluding that prototype's JMX type. The distribution adds the downloader,
package coordinator, generic `file` addon, managed Collector executable,
binary rollback, and addon removal/configuration reporting. These local pieces
are separate from the copied upstream source for comparison during rebases.

For an upstream refresh, first compare the corresponding upstream
`cmd/opampsupervisor` tree with this module after reversing the module-path
mapping and removing this module's local files. Compare the upstream package
PRs with the corresponding ported files, then reapply only the distribution
changes that upstream does not provide. The root `make opampsupervisor` target
builds this module.
