import json
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from supply_scan.acquire import (
    AcquireError,
    build_clone_command,
    build_clone_environment,
    clone_git_config_args,
    delete_tree,
    materialize_scan_manifests,
    normalize_target,
    open_workspace,
    parse_remote_heads,
    sanitize_git_url,
)
from supply_scan.inventory import Package, dedupe, is_scan_manifest_relpath, scan_tree
from supply_scan.cache import DiskCache, NullCache
import supply_scan.match as match
from supply_scan.match import Finding, annotate, cvss_v3_score, hydrate, query_osv, range_contains, version_tuple
from supply_scan.osv_zip import read_advisory_from_zip
from supply_scan.cli import main
from supply_scan.compare import compare_reports
from supply_scan.scans import list_scans, load_scan, save_scan
from supply_scan.serve import compare_response
from supply_scan.ignore import read_ignores, set_ignored
from supply_scan.report import Snapshot, exit_code, render_json, render_text
from supply_scan.serve import ignore_response
from supply_scan.run import TargetSpec, run_batch, run_scan
from supply_scan.locate import find_folder
from supply_scan.serve import _branch_list_error, batch_scan_response, branches_response, locate_response, scan_response


CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {
            "dependencies": {"lodash": "^4.17.20"},
            "devDependencies": {"vitest": "^1.0.0"},
        },
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/vitest": {"version": "1.6.0", "dev": True},
        "node_modules/picocolors": {"version": "1.0.0"},
    },
}

# Transitive entries omit "dev" on purpose. The label has to come from the graph.
NPM_DEV_TREE = {
    "lockfileVersion": 3,
    "packages": {
        "": {
            "dependencies": {"lib": "^1.0.0", "app": "*"},
            "optionalDependencies": {"opt": "^1.0.0"},
            "peerDependencies": {"peer": "^1.0.0"},
            "devDependencies": {"vitest": "^1.0.0", "tool": "^1.0.0"},
        },
        "node_modules/app": {"resolved": "packages/app", "link": True},
        "packages/app": {
            "dependencies": {"app-lib": "^1.0.0", "nested-ws": "1.0.0"},
            "devDependencies": {"app-test": "^1.0.0"},
        },
        "packages/app/node_modules/nested-ws": {"version": "1.0.0"},
        "node_modules/lib": {
            "version": "1.0.0",
            "dependencies": {
                "shared": "^2.0.0",
                "tool": "^1.0.0",
                "nested-prod": "1.2.0",
            },
        },
        "node_modules/lib/node_modules/nested-prod": {"version": "1.2.0"},
        "node_modules/shared": {"version": "2.0.0"},
        "node_modules/tool": {
            "version": "1.0.0",
            "dependencies": {"lib": "^1.0.0"},
        },
        "node_modules/opt": {"version": "1.0.0"},
        "node_modules/peer": {"version": "1.0.0"},
        "node_modules/vitest": {
            "version": "1.6.0",
            "dependencies": {
                "only-dev": "^3.0.0",
                "shared": "^1.0.0",
                "@scope/devtool": "^1.0.0",
            },
        },
        "node_modules/vitest/node_modules/shared": {"version": "1.0.0"},
        "node_modules/only-dev": {
            "version": "3.0.0",
            "dependencies": {"only-dev-nested": "^4.0.0", "shared": "^2.0.0"},
        },
        "node_modules/only-dev-nested": {"version": "4.0.0"},
        "node_modules/@scope/devtool": {
            "version": "1.0.0",
            "dependencies": {"under-scope": "1.0.0"},
        },
        "node_modules/@scope/devtool/node_modules/under-scope": {"version": "1.0.0"},
        "node_modules/app-lib": {
            "version": "1.0.0",
            "dependencies": {"app-lib-trans": "^1.0.0"},
        },
        "node_modules/app-lib-trans": {"version": "1.0.0"},
        "node_modules/app-test": {
            "version": "1.0.0",
            "dependencies": {"app-test-trans": "^1.0.0"},
        },
        "node_modules/app-test-trans": {"version": "1.0.0"},
        "node_modules/orphan-dev": {"version": "0.0.1", "dev": True},
        "node_modules/orphan-optional": {"version": "0.0.1", "devOptional": True},
        "node_modules/orphan": {"version": "0.0.1"},
    },
}

PNPM = """
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.6.0

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-abc}

  vitest@1.6.0:
    resolution: {integrity: sha512-def}
    dev: true

  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-ghi}
"""

PNPM_V6 = """
lockfileVersion: '6.0'

specifiers:
  lodash: ^4.17.20
  vitest: ^1.0.0

dependencies:
  lodash:
    specifier: ^4.17.20
    version: 4.17.20

devDependencies:
  vitest:
    specifier: ^1.0.0
    version: 1.6.0

packages:

  /lodash@4.17.20:
    resolution: {integrity: sha512-abc}

  /vitest@1.6.0:
    resolution: {integrity: sha512-def}
    dev: true

  /@scope/pkg@1.2.3:
    resolution: {integrity: sha512-ghi}
"""

# lockfile v5 stores /name/version and a flat `name: version` dependency line.
PNPM_V5 = """
lockfileVersion: 5.4

specifiers:
  lodash: ^4.17.20
  vitest: ^1.0.0

dependencies:
  lodash: 4.17.20

devDependencies:
  vitest: 1.6.0

packages:

  /lodash/4.17.20:
    resolution: {integrity: sha512-abc}
    dev: false

  /vitest/1.6.0:
    resolution: {integrity: sha512-def}
    dev: true

  /@scope/pkg/1.2.3:
    resolution: {integrity: sha512-ghi}
    dev: false
"""

# One key matches the known shape and one is the older /name/version key.
PNPM_MIXED = """
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20
      vitest:
        specifier: ^1.0.0
        version: 1.6.0

packages:

  lodash@4.17.20:
    resolution: {integrity: sha512-abc}

  /vitest/1.6.0:
    resolution: {integrity: sha512-def}
"""

GO_MOD = """
module example.com/app

go 1.22

require (
    github.com/foo/bar v1.2.3
    github.com/foo/baz v0.1.0 // indirect
)

require github.com/solo/mod v1.0.0
"""

GO_REPLACE = """
module example.com/app

go 1.22

require (
    github.com/local/mod v1.0.0
    github.com/forked/mod v0.5.0
    github.com/same/mod v1.0.0
    github.com/untouched/mod v1.2.3 // indirect
)

replace (
    github.com/local/mod => "../local/mod"
    github.com/forked/mod => github.com/other/mod v1.4.0
    github.com/same/mod => github.com/same/mod v1.9.0
)

replace github.com/untouched/mod v0.1.0 => github.com/untouched/mod v9.0.0
"""

UV = """
[[package]]
name = "urllib3"
version = "2.2.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "Requests" },
]
"""

CARGO_LOCK = """
[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.152"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.155"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "leftpad"
version = "0.1.0"
source = "git+https://github.com/example/leftpad#abcdef"
"""

CARGO_TOML = """
[dependencies]
serde1 = { package = "serde", version = "1" }

[target.'cfg(unix)'.dependencies]
libc = "0.2"
"""

CARGO_RENAME_ONLY = """
[dependencies]
serde1 = { package = "serde", version = "1" }
"""


def _advisory(
    fixed="4.17.21",
    osv_id="GHSA-1",
    cve="CVE-2021-1",
    severity=CRITICAL,
    events=None,
    ecosystem="npm",
    name="lodash",
):
    if events is None:
        events = [{"introduced": "0"}, {"fixed": fixed}]
    vuln = {
        "id": osv_id,
        "summary": "example",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "SEMVER", "events": events}],
        }],
    }
    if cve:
        vuln["aliases"] = [cve]
    if severity:
        vuln["severity"] = [{"type": "CVSS_V3", "score": severity}]
    return vuln


class InventoryTests(unittest.TestCase):
    def test_npm_lock_marks_direct_dev_and_transitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
            Path(tmp, "packages", "app").mkdir(parents=True)
            Path(tmp, "packages", "app", "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0"}}),
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["lodash"].version, "4.17.20")
        self.assertTrue(found["lodash"].direct)
        self.assertFalse(found["lodash"].dev)
        self.assertTrue(found["vitest"].dev)
        self.assertFalse(found["picocolors"].direct)
        self.assertFalse(found["picocolors"].dev)
        self.assertNotIn("express", found)

    def test_npm_dev_only_transitive_is_dev_and_does_not_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package-lock.json").write_text(json.dumps(NPM_DEV_TREE), encoding="utf-8")
            found = {(pkg.name, pkg.version): pkg for pkg in scan_tree(Path(tmp))}

        def pkg(name, version):
            self.assertIn((name, version), found)
            return found[(name, version)]

        lib = pkg("lib", "1.0.0")
        self.assertTrue(lib.direct)
        self.assertFalse(lib.dev)
        vitest = pkg("vitest", "1.6.0")
        self.assertTrue(vitest.direct)
        self.assertTrue(vitest.dev)

        only = pkg("only-dev", "3.0.0")
        self.assertFalse(only.direct)
        self.assertTrue(only.dev)
        nested = pkg("only-dev-nested", "4.0.0")
        self.assertFalse(nested.direct)
        self.assertTrue(nested.dev)
        self.assertTrue(pkg("@scope/devtool", "1.0.0").dev)
        self.assertFalse(pkg("@scope/devtool", "1.0.0").direct)
        self.assertTrue(pkg("under-scope", "1.0.0").dev)
        self.assertFalse(pkg("under-scope", "1.0.0").direct)

        shared_prod = pkg("shared", "2.0.0")
        self.assertFalse(shared_prod.direct)
        self.assertFalse(shared_prod.dev)
        shared_dev = pkg("shared", "1.0.0")
        self.assertFalse(shared_dev.direct)
        self.assertTrue(shared_dev.dev)

        tool = pkg("tool", "1.0.0")
        self.assertTrue(tool.direct)
        self.assertFalse(tool.dev)
        self.assertTrue(pkg("opt", "1.0.0").direct)
        self.assertFalse(pkg("opt", "1.0.0").dev)
        self.assertTrue(pkg("peer", "1.0.0").direct)
        self.assertFalse(pkg("peer", "1.0.0").dev)

        self.assertTrue(pkg("app-lib", "1.0.0").direct)
        self.assertFalse(pkg("app-lib", "1.0.0").dev)
        self.assertFalse(pkg("app-lib-trans", "1.0.0").direct)
        self.assertFalse(pkg("app-lib-trans", "1.0.0").dev)
        self.assertTrue(pkg("nested-ws", "1.0.0").direct)
        self.assertFalse(pkg("nested-ws", "1.0.0").dev)
        self.assertTrue(pkg("app-test", "1.0.0").direct)
        self.assertTrue(pkg("app-test", "1.0.0").dev)
        self.assertFalse(pkg("app-test-trans", "1.0.0").direct)
        self.assertTrue(pkg("app-test-trans", "1.0.0").dev)
        self.assertFalse(pkg("nested-prod", "1.2.0").direct)
        self.assertFalse(pkg("nested-prod", "1.2.0").dev)

        self.assertTrue(pkg("orphan-dev", "0.0.1").dev)
        self.assertTrue(pkg("orphan-optional", "0.0.1").dev)
        self.assertFalse(pkg("orphan", "0.0.1").dev)
        self.assertFalse(pkg("orphan", "0.0.1").direct)

        only.vulns = [Finding("GHSA-dev", None, "high", "", "3.0.1", "vulnerability", True)]
        self.assertEqual(exit_code([only, lib], strict=False), 0)
        self.assertEqual(exit_code([only], strict=True), 1)
        tool.vulns = [Finding("GHSA-tool", None, "high", "", "1.0.1", "vulnerability", True)]
        self.assertEqual(exit_code([tool], strict=False), 1)

    def test_package_json_range_is_unchecked_without_a_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0", "left-pad": "1.2.3"}}),
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["express"].unchecked_reason, "version is a range, no lockfile")
        self.assertIsNone(found["left-pad"].unchecked_reason)
        self.assertEqual(found["left-pad"].version, "1.2.3")

    def test_pnpm_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pnpm-lock.yaml").write_text(PNPM, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertTrue(found["lodash"].direct)
        self.assertFalse(found["lodash"].dev)
        self.assertEqual(found["lodash"].version, "4.17.20")
        self.assertTrue(found["vitest"].dev)
        self.assertEqual(found["vitest"].version, "1.6.0")
        self.assertEqual(found["@scope/pkg"].version, "1.2.3")
        self.assertFalse(found["@scope/pkg"].direct)
        self.assertIsNone(found["@scope/pkg"].unchecked_reason)

    def test_pnpm_v6_lock_resolves_the_same_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pnpm-lock.yaml").write_text(PNPM_V6, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(set(found), {"lodash", "vitest", "@scope/pkg"})
        self.assertTrue(found["lodash"].direct)
        self.assertFalse(found["lodash"].dev)
        self.assertEqual(found["lodash"].version, "4.17.20")
        self.assertTrue(found["vitest"].dev)
        self.assertEqual(found["vitest"].version, "1.6.0")
        self.assertEqual(found["@scope/pkg"].version, "1.2.3")
        self.assertFalse(found["@scope/pkg"].direct)
        self.assertIsNone(found["@scope/pkg"].unchecked_reason)

    def test_pnpm_lock_unknown_shape_is_one_unchecked_row(self):
        for text in (PNPM_V5, PNPM_MIXED):
            with self.subTest(text=text.splitlines()[1]):
                with tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "pnpm-lock.yaml").write_text(text, encoding="utf-8")
                    found = scan_tree(Path(tmp))
                self.assertEqual(len(found), 1)
                row = found[0]
                self.assertEqual(row.manifest, "pnpm-lock.yaml")
                self.assertEqual(row.name, "pnpm-lock.yaml")
                self.assertIsNone(row.version)
                self.assertEqual(row.unchecked_reason, "pnpm lockfile shape was not recognised")
                self.assertNotIn("lodash", {pkg.name for pkg in found})

    def test_yarn_classic_lock_resolves_ranges_and_holds_other_sources(self):
        lock = """
# yarn lockfile v1

"@scope/pkg@^1.2.3":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz#abc"
  integrity sha512-abc

left-pad@git+https://github.com/stevemao/left-pad.git:
  version "1.2.0"
  resolved "git+https://github.com/stevemao/left-pad.git#abc"

local@file:./local:
  version "0.0.1"
  resolved "file:./local"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#def"
  integrity sha512-def
  dependencies:
    "@scope/pkg" "^1.2.3"
    something "^1.0.0"

something@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/something/-/something-1.0.0.tgz#ghi"

string-width-cjs@npm:string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#jkl"

vite@^5.0.0:
  version "5.0.0"
  resolved "https://registry.yarnpkg.com/vite/-/vite-5.0.0.tgz#mno"

vitest@^1.6.0:
  version "1.6.0"
  resolved "https://registry.yarnpkg.com/vitest/-/vitest-1.6.0.tgz#pqr"
  dependencies:
    something "^1.0.0"
    vite "^5.0.0"
"""
        package = {
            "dependencies": {
                "lodash": "^4.17.21",
                "left-pad": "git+https://github.com/stevemao/left-pad.git",
                "local": "file:./local",
                "string-width-cjs": "npm:string-width@^4.2.0",
            },
        }
        child = {"dependencies": {"express": "^4.18.0"}, "devDependencies": {"vitest": "^1.6.0"}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yarn.lock").write_text(lock, encoding="utf-8")
            (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
            (root / "packages" / "app").mkdir(parents=True)
            (root / "packages" / "app" / "package.json").write_text(json.dumps(child), encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        self.assertNotIn("express", found)
        lodash = found["lodash"]
        self.assertEqual(lodash.ecosystem, "npm")
        self.assertEqual(lodash.version, "4.17.21")
        self.assertEqual(lodash.manifest, "yarn.lock")
        self.assertTrue(lodash.direct)
        self.assertFalse(lodash.dev)
        self.assertIsNone(lodash.unchecked_reason)
        scope = found["@scope/pkg"]
        self.assertEqual(scope.version, "1.2.3")
        self.assertFalse(scope.direct)
        self.assertFalse(scope.dev)
        shared = found["something"]
        self.assertFalse(shared.direct)
        self.assertFalse(shared.dev)
        self.assertEqual(shared.version, "1.0.0")
        width = found["string-width"]
        self.assertEqual(width.version, "4.2.3")
        self.assertTrue(width.direct)
        self.assertFalse(width.dev)
        self.assertEqual(width.alias, "string-width-cjs")
        self.assertIsNone(width.unchecked_reason)
        vitest = found["vitest"]
        self.assertTrue(vitest.direct)
        self.assertTrue(vitest.dev)
        self.assertEqual(vitest.version, "1.6.0")
        vite = found["vite"]
        self.assertFalse(vite.direct)
        self.assertTrue(vite.dev)
        self.assertEqual(vite.version, "5.0.0")
        self.assertIn("git source", found["left-pad"].unchecked_reason)
        self.assertTrue(found["left-pad"].direct)
        self.assertEqual(found["left-pad"].version, "1.2.0")
        self.assertIn("file source", found["local"].unchecked_reason)
        self.assertTrue(found["local"].direct)
        vite.vulns = [Finding("GHSA-dev", None, "high", "", "5.0.1", "vulnerability", True)]
        self.assertEqual(exit_code([vite], strict=False), 0)

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.ecosystem, pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("npm", "lodash", "4.17.21"), seen)
        self.assertIn(("npm", "string-width", "4.2.3"), seen)
        self.assertIn(("npm", "vitest", "1.6.0"), seen)
        self.assertIn(("npm", "vite", "5.0.0"), seen)
        sent = {name for _ecosystem, name, _version in seen}
        self.assertNotIn("left-pad", sent)
        self.assertNotIn("local", sent)
        self.assertNotIn("string-width-cjs", sent)

    def test_yarn_berry_lock_resolves_ranges_and_holds_other_sources(self):
        lock = """
__metadata:
  version: 6
  cacheKey: 8

"@scope/pkg@npm:^1.2.3":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    lodash: ^4.17.21
  languageName: unknown
  linkType: soft

"left-pad@git+https://github.com/stevemao/left-pad.git":
  version: 1.2.0
  resolution: "left-pad@https://github.com/stevemao/left-pad.git#abc"
  languageName: node
  linkType: hard

"local@file:./local":
  version: 0.0.1
  resolution: "local@file:./local"
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  dependencies:
    "@scope/pkg": ^1.2.3
    something: ^1.0.0
  languageName: node
  linkType: hard

"patched@patch:patched@npm%3A1.2.3#./.yarn/patches/patched.patch":
  version: 1.2.3
  resolution: "patched@patch:patched@npm%3A1.2.3#./.yarn/patches/patched.patch"
  languageName: node
  linkType: hard

"portal@portal:./portal":
  version: 0.0.0-use.local
  resolution: "portal@portal:./portal"
  languageName: unknown
  linkType: soft

"something@npm:^1.0.0":
  version: 1.0.0
  resolution: "something@npm:1.0.0"
  languageName: node
  linkType: hard

"ui@workspace:packages/ui":
  version: 0.0.0-use.local
  resolution: "ui@workspace:packages/ui"
  languageName: unknown
  linkType: soft

"vite@npm:^5.0.0":
  version: 5.0.0
  resolution: "vite@npm:5.0.0"
  languageName: node
  linkType: hard

"vitest@npm:^1.6.0":
  version: 1.6.0
  resolution: "vitest@npm:1.6.0"
  dependencies:
    something: ^1.0.0
    vite: ^5.0.0
  languageName: node
  linkType: hard
"""
        package = {
            "dependencies": {
                "lodash": "^4.17.21",
                "left-pad": "git+https://github.com/stevemao/left-pad.git",
                "local": "file:./local",
                "ui": "workspace:packages/ui",
                "portal": "portal:./portal",
                "patched": "patch:patched@npm%3A1.2.3#./.yarn/patches/patched.patch",
            },
            "devDependencies": {"vitest": "^1.6.0"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yarn.lock").write_text(lock, encoding="utf-8")
            (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
            (root / "packages" / "app").mkdir(parents=True)
            (root / "packages" / "app" / "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0"}}),
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        self.assertNotIn("express", found)
        self.assertNotIn("6", {pkg.version for pkg in found.values()})
        lodash = found["lodash"]
        self.assertEqual(lodash.version, "4.17.21")
        self.assertEqual(lodash.manifest, "yarn.lock")
        self.assertTrue(lodash.direct)
        self.assertFalse(lodash.dev)
        self.assertIsNone(lodash.unchecked_reason)
        self.assertEqual(found["@scope/pkg"].version, "1.2.3")
        self.assertFalse(found["@scope/pkg"].direct)
        self.assertFalse(found["@scope/pkg"].dev)
        self.assertFalse(found["something"].dev)
        self.assertTrue(found["vitest"].direct)
        self.assertTrue(found["vitest"].dev)
        self.assertFalse(found["vite"].direct)
        self.assertTrue(found["vite"].dev)
        self.assertIn("workspace source", found["demo"].unchecked_reason)
        self.assertFalse(found["demo"].direct)
        self.assertEqual(found["demo"].version, "0.0.0-use.local")
        self.assertIn("workspace source", found["ui"].unchecked_reason)
        self.assertTrue(found["ui"].direct)
        self.assertIn("git source", found["left-pad"].unchecked_reason)
        self.assertTrue(found["left-pad"].direct)
        self.assertIn("file source", found["local"].unchecked_reason)
        self.assertIn("portal source", found["portal"].unchecked_reason)
        self.assertTrue(found["portal"].direct)
        self.assertIn("patch source", found["patched"].unchecked_reason)
        self.assertTrue(found["patched"].direct)
        self.assertEqual(found["patched"].version, "1.2.3")

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.ecosystem, pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("npm", "lodash", "4.17.21"), seen)
        self.assertIn(("npm", "@scope/pkg", "1.2.3"), seen)
        self.assertIn(("npm", "vitest", "1.6.0"), seen)
        sent = {name for _ecosystem, name, _version in seen}
        self.assertNotIn("demo", sent)
        self.assertNotIn("ui", sent)
        self.assertNotIn("left-pad", sent)
        self.assertNotIn("local", sent)
        self.assertNotIn("portal", sent)
        self.assertNotIn("patched", sent)

    def test_yarn_lock_is_read_alongside_other_javascript_locks(self):
        yarn = """
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yarn.lock").write_text(yarn, encoding="utf-8")
            (root / "package-lock.json").write_text(
                json.dumps({"dependencies": {"left-pad": {"version": "1.2.3"}}}),
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        self.assertEqual(set(found), {"left-pad", "lodash"})
        self.assertEqual(found["left-pad"].version, "1.2.3")
        self.assertEqual(found["left-pad"].manifest, "package-lock.json")
        self.assertEqual(found["lodash"].version, "4.17.21")
        self.assertEqual(found["lodash"].manifest, "yarn.lock")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "yarn.lock").write_text(yarn, encoding="utf-8")
            (root / "pnpm-lock.yaml").write_text(PNPM, encoding="utf-8")
            packages = scan_tree(root)
            by_name: dict[str, list[Package]] = {}
            for pkg in packages:
                by_name.setdefault(pkg.name, []).append(pkg)
        self.assertIn("vitest", by_name)
        lodash = sorted(by_name["lodash"], key=lambda pkg: pkg.version or "")
        self.assertEqual([pkg.version for pkg in lodash], ["4.17.20", "4.17.21"])
        self.assertEqual({pkg.manifest for pkg in lodash}, {"pnpm-lock.yaml", "yarn.lock"})

    def test_yarn_lock_unknown_shape_is_one_unchecked_row(self):
        texts = (
            "hello: world\n",
            "# yarn lockfile v1\n\nlodash@^1:\n  version \"1.0.0\"\n  version: 1.0.0\n",
            "# yarn lockfile v1\n\n\tlodash@^1:\n",
        )
        for text in texts:
            with self.subTest(text=text.splitlines()[0]):
                with tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "yarn.lock").write_text(text, encoding="utf-8")
                    found = scan_tree(Path(tmp))
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].manifest, "yarn.lock")
                self.assertEqual(found[0].unchecked_reason, "yarn lockfile shape was not recognised")
                self.assertNotIn("lodash", {pkg.name for pkg in found})

    def test_gradle_lock_resolves_modules_and_catalog_keeps_the_rest(self):
        lock = """
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath,testCompileClasspath
org.junit.jupiter:junit-jupiter:5.10.2=testCompileClasspath,testRuntimeClasspath
com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.+=compileClasspath
empty=annotationProcessor,checkstyle
"""
        catalog = """
[versions]
guava = "31.1-jre"
junit = "5.10.2"
dynamic = "1.+"
rich = { strictly = "[1.0, 2.0[", prefer = "1.5.0" }

[libraries]
guava = { module = "com.google.guava:guava", version.ref = "guava" }
short = "com.google.guava:guava:31.1-jre"
junit = { group = "org.junit.jupiter", name = "junit-jupiter", version.ref = "junit" }
slf4j = { module = "org.slf4j:slf4j-api", version = "2.0.9" }
commons = { module = "org.apache.commons:commons-lang3", version = "3.14.0" }
dynamic-lib = { module = "org.slf4j:slf4j-simple", version.ref = "dynamic" }
rich-lib = { group = "com.example", name = "rich", version = { strictly = "[1.0, 2.0[", prefer = "1.5.0" } }
rich-ref = { module = "com.example:rich-ref", version.ref = "rich" }
absent = { module = "com.example:absent", version.ref = "no-such" }
bare = { module = "com.example:bare" }

[bundles]
used = ["guava", "junit"]

[plugins]
spring = { id = "org.springframework.boot", version = "3.2.5" }
range-plugin = { id = "com.example.plugin", version = "1.+" }
no-version = { id = "com.example.missing" }
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(catalog, encoding="utf-8")
            (root / "gradle.lockfile").write_text(lock, encoding="utf-8")
            (root / "build.gradle").write_text(
                "dependencies { implementation 'com.google.guava:guava:1.0.0' }\n",
                encoding="utf-8",
            )
            app = root / "app"
            app.mkdir()
            (app / "build.gradle.kts").write_text(
                'dependencies { implementation("org.slf4j:slf4j-api:9.9.9") }\n',
                encoding="utf-8",
            )
            rows = scan_tree(root)
        found = {pkg.name: pkg for pkg in rows}

        self.assertEqual(len(rows), 13)
        self.assertEqual(len(found), 13)
        guava = found["com.google.guava:guava"]
        self.assertEqual(guava.version, "31.1-jre")
        self.assertEqual(guava.ecosystem, "Maven")
        self.assertTrue(guava.direct)
        self.assertFalse(guava.dev)
        self.assertEqual(guava.alias, "guava, short")
        self.assertEqual(guava.manifest, "gradle.lockfile")
        self.assertIsNone(guava.unchecked_reason)
        junit = found["org.junit.jupiter:junit-jupiter"]
        self.assertEqual(junit.version, "5.10.2")
        self.assertTrue(junit.direct)
        self.assertTrue(junit.dev)
        self.assertEqual(junit.alias, "junit")
        self.assertIsNone(junit.unchecked_reason)
        failure = found["com.google.guava:failureaccess"]
        self.assertEqual(failure.version, "1.0.1")
        self.assertFalse(failure.direct)
        self.assertFalse(failure.dev)
        self.assertIsNone(failure.unchecked_reason)
        slf4j = found["org.slf4j:slf4j-api"]
        self.assertEqual(slf4j.version, "1.+")
        self.assertTrue(slf4j.direct)
        self.assertEqual(slf4j.unchecked_reason, "version is a range, no lockfile")
        commons = found["org.apache.commons:commons-lang3"]
        self.assertEqual(commons.version, "3.14.0")
        self.assertTrue(commons.direct)
        self.assertFalse(commons.dev)
        self.assertEqual(commons.manifest, "gradle/libs.versions.toml")
        self.assertIsNone(commons.unchecked_reason)
        dynamic = found["org.slf4j:slf4j-simple"]
        self.assertEqual(dynamic.version, "1.+")
        self.assertEqual(dynamic.alias, "dynamic-lib")
        self.assertEqual(dynamic.unchecked_reason, "version is a range, no lockfile")
        self.assertIsNone(found["com.example:rich"].version)
        self.assertEqual(found["com.example:rich"].unchecked_reason, "version is a range, no lockfile")
        self.assertEqual(found["com.example:rich-ref"].unchecked_reason, "version is a range, no lockfile")
        self.assertEqual(found["com.example:absent"].unchecked_reason, "version is not written in the repo")
        self.assertEqual(found["com.example:bare"].unchecked_reason, "version is not written in the repo")
        spring = found["org.springframework.boot"]
        self.assertEqual(spring.version, "3.2.5")
        self.assertEqual(spring.alias, "spring")
        self.assertEqual(spring.unchecked_reason, "Gradle plugin, not a Maven module")
        self.assertEqual(found["com.example.plugin"].version, "1.+")
        self.assertEqual(found["com.example.plugin"].unchecked_reason, "version is a range, no lockfile")
        self.assertIsNone(found["com.example.missing"].version)
        self.assertEqual(found["com.example.missing"].unchecked_reason, "version is not written in the repo")
        self.assertNotIn("build.gradle", found)
        self.assertNotIn("app/build.gradle.kts", found)
        self.assertNotIn("1.0.0", {pkg.version for pkg in found.values()})
        self.assertNotIn("9.9.9", {pkg.version for pkg in found.values()})

    def test_gradle_catalog_literals_cover_a_script_without_a_lock(self):
        catalog = """
[libraries]
guava = { module = "com.google.guava:guava", version = "31.1-jre" }
plain = "org.apache.commons:commons-lang3:3.14.0"
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(catalog, encoding="utf-8")
            (root / "libs.versions.toml").write_text(
                '[libraries]\nextra = { module = "org.slf4j:slf4j-api", version = "2.0.9" }\n',
                encoding="utf-8",
            )
            (root / "build.gradle").write_text(
                "dependencies { implementation 'com.google.guava:guava:1.0.0' }\n",
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        self.assertEqual(set(found), {"com.google.guava:guava", "org.apache.commons:commons-lang3"})
        self.assertEqual(found["com.google.guava:guava"].version, "31.1-jre")
        self.assertTrue(found["com.google.guava:guava"].direct)
        self.assertEqual(found["com.google.guava:guava"].manifest, "gradle/libs.versions.toml")
        self.assertEqual(found["org.apache.commons:commons-lang3"].version, "3.14.0")
        self.assertNotIn("org.slf4j:slf4j-api", found)

    def test_gradle_script_without_a_lock_or_literal_catalog_is_unchecked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "build.gradle").write_text(
                "dependencies { implementation 'com.google.guava:guava:31.1-jre' }\n",
                encoding="utf-8",
            )
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(
                '[libraries]\nslf4j = { module = "org.slf4j:slf4j-api", version = "1.+" }\n',
                encoding="utf-8",
            )
            app = root / "app"
            app.mkdir()
            (app / "build.gradle.kts").write_text("dependencies {}\n", encoding="utf-8")
            found = scan_tree(root)
        by_name = {pkg.name: pkg for pkg in found}
        self.assertEqual(set(by_name), {
            "org.slf4j:slf4j-api",
            "build.gradle",
            "app/build.gradle.kts",
        })
        self.assertEqual(by_name["org.slf4j:slf4j-api"].version, "1.+")
        self.assertEqual(by_name["org.slf4j:slf4j-api"].unchecked_reason, "version is a range, no lockfile")
        self.assertEqual(by_name["build.gradle"].unchecked_reason, "Gradle script, no lockfile")
        self.assertIsNone(by_name["build.gradle"].version)
        self.assertEqual(by_name["app/build.gradle.kts"].unchecked_reason, "Gradle script, no lockfile")
        self.assertNotIn("31.1-jre", {pkg.version for pkg in found})

    def test_gradle_subproject_lock_uses_the_root_catalog(self):
        catalog = """
[libraries]
guava = { module = "com.google.guava:guava", version = "31.1-jre" }
"""
        lock = """
# This is a Gradle generated file for dependency locking.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
com.google.guava:failureaccess:1.0.1=runtimeClasspath
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text(catalog, encoding="utf-8")
            app = root / "app"
            app.mkdir()
            (app / "gradle.lockfile").write_text(lock, encoding="utf-8")
            (app / "build.gradle").write_text("dependencies {}\n", encoding="utf-8")
            rows = scan_tree(root)
        found = {pkg.name: pkg for pkg in rows}
        self.assertEqual(len(rows), 2)
        self.assertEqual(found["com.google.guava:guava"].manifest, "app/gradle.lockfile")
        self.assertTrue(found["com.google.guava:guava"].direct)
        self.assertEqual(found["com.google.guava:guava"].alias, "guava")
        self.assertFalse(found["com.google.guava:failureaccess"].direct)
        self.assertEqual(found["com.google.guava:failureaccess"].manifest, "app/gradle.lockfile")
        self.assertNotIn("app/build.gradle", found)

    def test_gradle_lock_unknown_shape_is_one_unchecked_row(self):
        texts = (
            "com.google.guava:guava:31.1-jre=compileClasspath\nnot a lock line\n",
            "com.google.guava: guava:31.1-jre=compileClasspath\n",
            "[]\n",
        )
        for text in texts:
            with self.subTest(text=text.splitlines()[0]):
                with tempfile.TemporaryDirectory() as tmp:
                    Path(tmp, "gradle.lockfile").write_text(text, encoding="utf-8")
                    found = scan_tree(Path(tmp))
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].manifest, "gradle.lockfile")
                self.assertEqual(found[0].unchecked_reason, "gradle lockfile shape was not recognised")
                self.assertNotIn("com.google.guava:guava", {pkg.name for pkg in found})

    def test_version_catalog_unknown_shape_is_one_unchecked_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gradle").mkdir()
            (root / "gradle" / "libs.versions.toml").write_text("not = [\n", encoding="utf-8")
            broken = scan_tree(root)
            (root / "gradle" / "libs.versions.toml").write_text('tool = "nope"\n', encoding="utf-8")
            foreign = scan_tree(root)
        self.assertEqual(broken[0].manifest, "gradle/libs.versions.toml")
        self.assertEqual(broken[0].unchecked_reason, "could not parse gradle/libs.versions.toml")
        self.assertEqual(foreign[0].unchecked_reason, "version catalog was not recognised")

    def test_pom_reads_versions_written_in_the_repo(self):
        parent = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>${revision}</version>
  <properties>
    <revision>1.0.0</revision>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
      </dependency>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>5.10.2</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
        child = """<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>app</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${missing.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>[2.0,3.0)</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pom.xml").write_text(parent, encoding="utf-8")
            (root / "app").mkdir()
            (root / "app" / "pom.xml").write_text(child, encoding="utf-8")
            rows = scan_tree(root)
        found = {(pkg.manifest, pkg.name): pkg for pkg in rows}
        guava = found[("app/pom.xml", "com.google.guava:guava")]
        self.assertEqual(guava.version, "31.1-jre")
        self.assertTrue(guava.direct)
        self.assertFalse(guava.dev)
        self.assertIsNone(guava.unchecked_reason)
        commons = found[("app/pom.xml", "org.apache.commons:commons-lang3")]
        self.assertEqual(commons.version, "3.14.0")
        self.assertIsNone(commons.unchecked_reason)
        slf4j = found[("app/pom.xml", "org.slf4j:slf4j-api")]
        self.assertEqual(slf4j.version, "2.0.9")
        self.assertIsNone(slf4j.unchecked_reason)
        lib = found[("app/pom.xml", "com.example:lib")]
        self.assertEqual(lib.version, "1.0.0")
        self.assertIsNone(lib.unchecked_reason)
        bom = found[("pom.xml", "org.junit:junit-bom")]
        self.assertEqual(bom.version, "5.10.2")
        self.assertIsNone(bom.unchecked_reason)
        missing = found[("app/pom.xml", "junit:junit")]
        self.assertEqual(missing.version, "${missing.version}")
        self.assertTrue(missing.dev)
        self.assertEqual(missing.unchecked_reason, "version is not written in the repo")
        self.assertEqual(missing.alias, "missing.version")
        log4j = found[("app/pom.xml", "org.apache.logging.log4j:log4j-api")]
        self.assertEqual(log4j.version, "[2.0,3.0)")
        self.assertEqual(log4j.unchecked_reason, "version is a range, no lockfile")
        jupiter = found[("app/pom.xml", "org.junit.jupiter:junit-jupiter")]
        self.assertTrue(jupiter.dev)
        self.assertEqual(jupiter.unchecked_reason, "version is not written in the repo")
        self.assertEqual(jupiter.alias, "org.junit:junit-bom")
        text = render_text(Snapshot("app", None, None, rows))
        self.assertLess(text.index("unchecked:"), text.index("unrecognised names:"))
        tail = text.split("unrecognised names:", 1)[1]
        self.assertIn("missing.version", tail)
        self.assertIn("org.junit:junit-bom", tail)
        self.assertNotIn("guava.version", tail)
        report = json.loads(render_json(Snapshot("app", None, None, rows)))
        self.assertEqual(report["unrecognised_names"], ["missing.version", "org.junit:junit-bom"])

    def test_pom_missing_parent_keeps_the_parent_name(self):
        text = """
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version>
    <relativePath/>
  </parent>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-simple</artifactId>
    </dependency>
  </dependencies>
</project>
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pom.xml").write_text(text, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["com.google.guava:guava"].version, "31.1-jre")
        self.assertIsNone(found["com.google.guava:guava"].unchecked_reason)
        simple = found["org.slf4j:slf4j-simple"]
        self.assertEqual(simple.unchecked_reason, "version is not written in the repo")
        self.assertEqual(simple.alias, "org.springframework.boot:spring-boot-starter-parent")
        report = render_text(Snapshot("app", None, None, list(found.values())))
        self.assertTrue(report.strip().endswith("org.springframework.boot:spring-boot-starter-parent"))

    def test_pom_unknown_shape_is_one_unchecked_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pom.xml").write_text("<project><dependencies></project>", encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].manifest, "pom.xml")
        self.assertEqual(found[0].unchecked_reason, "could not parse pom.xml")

    def test_composer_lock_resolves_releases_and_holds_the_rest(self):
        lock = {
            "packages": [
                {
                    "name": "monolog/monolog",
                    "version": "v3.5.0",
                    "source": {"type": "git", "url": "https://github.com/Seldaek/monolog.git", "reference": "a"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/Seldaek/monolog/zipball/a", "reference": "a"},
                },
                {
                    "name": "symfony/console",
                    "version": "v6.4.8",
                    "source": {"type": "git", "url": "https://github.com/symfony/console.git", "reference": "b"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/symfony/console/zipball/b", "reference": "b"},
                },
                {
                    "name": "psr/log",
                    "version": "3.0.0",
                    "source": {"type": "git", "url": "https://github.com/php-fig/log.git", "reference": "c"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/php-fig/log/zipball/c", "reference": "c"},
                },
                {
                    "name": "acme/branch",
                    "version": "2.0.x-dev",
                    "source": {"type": "git", "url": "https://github.com/acme/branch.git", "reference": "d"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/acme/branch/zipball/d", "reference": "d"},
                },
                {
                    "name": "acme/dev",
                    "version": "dev-main",
                    "source": {"type": "git", "url": "https://github.com/acme/dev.git", "reference": "e"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/acme/dev/zipball/e", "reference": "e"},
                },
                {
                    "name": "acme/git",
                    "version": "1.4.0",
                    "source": {"type": "git", "url": "https://github.com/acme/git.git", "reference": "f"},
                },
            ],
            "packages-dev": [
                {
                    "name": "phpunit/phpunit",
                    "version": "10.5.20",
                    "source": {"type": "git", "url": "https://github.com/sebastianbergmann/phpunit.git", "reference": "g"},
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/sebastianbergmann/phpunit/zipball/g", "reference": "g"},
                },
                {
                    "name": "sebastian/diff",
                    "version": "5.1.1",
                    "dist": {"type": "zip", "url": "https://api.github.com/repos/sebastianbergmann/diff/zipball/h", "reference": "h"},
                },
            ],
        }
        composer = {
            "require": {
                "php": "^8.2",
                "Monolog/monolog": "^3.0",
                "symfony/console": "^6.4",
                "acme/git": "1.4.0",
            },
            "require-dev": {
                "phpunit/phpunit": "^10.5",
                "acme/dev": "dev-main",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "composer.lock").write_text(json.dumps(lock), encoding="utf-8")
            Path(tmp, "composer.json").write_text(json.dumps(composer), encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        monolog = found["monolog/monolog"]
        self.assertEqual(monolog.ecosystem, "Packagist")
        self.assertEqual(monolog.version, "v3.5.0")
        self.assertTrue(monolog.direct)
        self.assertFalse(monolog.dev)
        self.assertIsNone(monolog.unchecked_reason)
        console = found["symfony/console"]
        self.assertTrue(console.direct)
        self.assertFalse(console.dev)
        self.assertEqual(console.version, "v6.4.8")
        self.assertIsNone(console.unchecked_reason)
        transitive = found["psr/log"]
        self.assertFalse(transitive.direct)
        self.assertFalse(transitive.dev)
        self.assertEqual(transitive.version, "3.0.0")
        phpunit = found["phpunit/phpunit"]
        self.assertTrue(phpunit.direct)
        self.assertTrue(phpunit.dev)
        self.assertEqual(phpunit.version, "10.5.20")
        self.assertIsNone(phpunit.unchecked_reason)
        diff = found["sebastian/diff"]
        self.assertFalse(diff.direct)
        self.assertTrue(diff.dev)
        self.assertIsNone(diff.unchecked_reason)
        self.assertIn("branch", found["acme/branch"].unchecked_reason)
        self.assertFalse(found["acme/branch"].direct)
        self.assertIn("dev version", found["acme/dev"].unchecked_reason)
        self.assertTrue(found["acme/dev"].direct)
        self.assertTrue(found["acme/dev"].dev)
        self.assertIn("git source", found["acme/git"].unchecked_reason)
        self.assertTrue(found["acme/git"].direct)
        self.assertEqual(found["acme/git"].version, "1.4.0")

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.ecosystem, pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("Packagist", "monolog/monolog", "v3.5.0"), seen)
        self.assertIn(("Packagist", "phpunit/phpunit", "10.5.20"), seen)
        self.assertIn(("Packagist", "psr/log", "3.0.0"), seen)
        sent = {name for _ecosystem, name, _version in seen}
        self.assertNotIn("acme/branch", sent)
        self.assertNotIn("acme/dev", sent)
        self.assertNotIn("acme/git", sent)

    def test_broken_composer_lock_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "composer.lock").write_text("{", encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertIn("could not parse", found[0].unchecked_reason)

    def test_pubspec_lock_queries_hosted_and_holds_other_sources(self):
        lock = """
# Generated by pub
packages:
  async:
    dependency: transitive
    description:
      name: async
      sha256: abc
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
  collection:
    dependency: "direct main"
    description:
      name: collection
      sha256: def
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  lints:
    dependency: "direct dev"
    description:
      name: lints
      sha256: ghi
      url: "https://pub.dev"
    source: hosted
    version: "3.0.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  path_pkg:
    dependency: "direct dev"
    description:
      path: "../path_pkg"
      relative: true
    source: path
    version: "0.1.0"
  git_pkg:
    dependency: transitive
    description:
      url: "https://github.com/example/git_pkg.git"
      ref: main
      resolved-ref: abc123
    source: git
    version: "0.2.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
"""
        yaml = """
name: app
dependencies:
  collection: 1.18.0
  extra: 9.9.9
dev_dependencies:
  lints: ^3.0.0
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pubspec.lock").write_text(lock, encoding="utf-8")
            (root / "pubspec.yaml").write_text(yaml, encoding="utf-8")
            (root / "pkg").mkdir()
            (root / "pkg" / "pubspec.yaml").write_text(
                "name: pkg\ndependencies:\n  only_child: 1.2.3\n",
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        self.assertNotIn("extra", found)
        self.assertNotIn("only_child", found)
        self.assertNotIn("dart", found)
        collection = found["collection"]
        self.assertEqual(collection.ecosystem, "Pub")
        self.assertEqual(collection.version, "1.18.0")
        self.assertTrue(collection.direct)
        self.assertFalse(collection.dev)
        self.assertIsNone(collection.unchecked_reason)
        async_pkg = found["async"]
        self.assertFalse(async_pkg.direct)
        self.assertFalse(async_pkg.dev)
        self.assertEqual(async_pkg.version, "2.11.0")
        self.assertIsNone(async_pkg.unchecked_reason)
        lints = found["lints"]
        self.assertTrue(lints.direct)
        self.assertTrue(lints.dev)
        self.assertEqual(lints.version, "3.0.0")
        self.assertIsNone(lints.unchecked_reason)
        self.assertIn("sdk source", found["flutter"].unchecked_reason)
        self.assertTrue(found["flutter"].direct)
        self.assertFalse(found["flutter"].dev)
        self.assertIn("path source", found["path_pkg"].unchecked_reason)
        self.assertTrue(found["path_pkg"].direct)
        self.assertTrue(found["path_pkg"].dev)
        self.assertIn("git source", found["git_pkg"].unchecked_reason)
        self.assertFalse(found["git_pkg"].direct)
        self.assertEqual(found["git_pkg"].version, "0.2.0")

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.ecosystem, pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("Pub", "collection", "1.18.0"), seen)
        self.assertIn(("Pub", "async", "2.11.0"), seen)
        self.assertIn(("Pub", "lints", "3.0.0"), seen)
        sent = {name for _ecosystem, name, _version in seen}
        self.assertNotIn("flutter", sent)
        self.assertNotIn("path_pkg", sent)
        self.assertNotIn("git_pkg", sent)

    def test_pubspec_yaml_without_a_lock_keeps_ranges(self):
        text = """
name: app
environment:
  sdk: ^3.0.0
dependencies:
  collection: 1.18.0
  http: ^1.2.0
  flutter:
    sdk: flutter
  git_pkg:
    git:
      url: https://github.com/example/git_pkg.git
dev_dependencies:
  lints: ^3.0.0
  test: 1.25.0
  path_pkg:
    path: ../path_pkg
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "pubspec.yaml").write_text(text, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertNotIn("app", found)
        self.assertNotIn("sdk", found)
        collection = found["collection"]
        self.assertEqual(collection.version, "1.18.0")
        self.assertTrue(collection.direct)
        self.assertFalse(collection.dev)
        self.assertIsNone(collection.unchecked_reason)
        http = found["http"]
        self.assertEqual(http.unchecked_reason, "version is a range, no lockfile")
        self.assertTrue(http.direct)
        self.assertFalse(http.dev)
        self.assertEqual(http.version, "^1.2.0")
        self.assertIn("sdk source", found["flutter"].unchecked_reason)
        self.assertTrue(found["flutter"].direct)
        self.assertIn("git source", found["git_pkg"].unchecked_reason)
        lints = found["lints"]
        self.assertEqual(lints.unchecked_reason, "version is a range, no lockfile")
        self.assertTrue(lints.dev)
        test = found["test"]
        self.assertEqual(test.version, "1.25.0")
        self.assertTrue(test.direct)
        self.assertTrue(test.dev)
        self.assertIsNone(test.unchecked_reason)
        self.assertIn("path source", found["path_pkg"].unchecked_reason)
        self.assertTrue(found["path_pkg"].dev)

    def test_gemfile_lock_queries_rubygems_and_holds_other_sources(self):
        lock = """
GIT
  remote: https://github.com/acme/git_pkg.git
  revision: abcdef
  branch: main
  specs:
    git_pkg (0.2.0)
      rake

PATH
  remote: vendor/path_pkg
  specs:
    path_pkg (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.1.3)
      rack (>= 2.2.0)
    json (2.7.1)
    json (2.7.1-java)
    minitest (5.20.0)
    nokogiri (1.16.5)
      racc (~> 1.4)
    nokogiri (1.16.5-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)
    rack (3.0.8)
    rails (7.1.3)
      actionpack (= 7.1.3)
      rake (= 13.2.1)
    rake (13.2.1)
    rubocop (1.60.2)
      json (~> 2.7)
      minitest (~> 5.20)
  remote: https://gems.example.com/
  specs:
    sidekiq-pro (7.1.0)

PLATFORMS
  ruby
  x86_64-linux

DEPENDENCIES
  rails (~> 7.1)
  nokogiri
  path_pkg!
  git_pkg!
  rake
  rubocop
  sidekiq-pro

RUBY VERSION
   ruby 3.2.2p53

BUNDLED WITH
   2.5.3
"""
        gemfile = """
source "https://rubygems.org"

gem "rails", "~> 7.1"
gem "nokogiri"
gem "path_pkg", path: "vendor/path_pkg"
gem "git_pkg", git: "https://github.com/acme/git_pkg.git"
gem "sidekiq-pro", source: "https://gems.example.com"
gem "missing", "9.9.9" # not in the lock

group :development, :test do
  gem "rubocop", require: false
end

group :test do
  gem "rake"
end
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Gemfile.lock").write_text(lock, encoding="utf-8")
            (root / "Gemfile").write_text(gemfile, encoding="utf-8")
            (root / "extra").mkdir()
            (root / "extra" / "Gemfile").write_text(
                'gem "only_child", "1.2.3"\ngem "child_rails", "~> 7.0"\n',
                encoding="utf-8",
            )
            packages = scan_tree(root)
        found = {pkg.name: pkg for pkg in packages}
        self.assertNotIn("missing", found)
        rails = found["rails"]
        self.assertEqual(rails.ecosystem, "RubyGems")
        self.assertEqual(rails.version, "7.1.3")
        self.assertTrue(rails.direct)
        self.assertFalse(rails.dev)
        self.assertIsNone(rails.unchecked_reason)
        self.assertEqual(found["rails"].manifest, "Gemfile.lock")
        actionpack = found["actionpack"]
        self.assertFalse(actionpack.direct)
        self.assertFalse(actionpack.dev)
        self.assertEqual(actionpack.version, "7.1.3")
        self.assertIsNone(actionpack.unchecked_reason)
        nokogiri = found["nokogiri"]
        self.assertEqual(nokogiri.version, "1.16.5")
        self.assertTrue(nokogiri.direct)
        self.assertFalse(nokogiri.dev)
        self.assertIsNone(nokogiri.unchecked_reason)
        self.assertEqual(
            [pkg.version for pkg in packages if pkg.name == "nokogiri"],
            ["1.16.5"],
        )
        racc = found["racc"]
        self.assertFalse(racc.direct)
        self.assertFalse(racc.dev)
        self.assertEqual(racc.version, "1.7.3")
        rake = found["rake"]
        self.assertTrue(rake.direct)
        self.assertFalse(rake.dev)
        self.assertEqual(rake.version, "13.2.1")
        self.assertIsNone(rake.unchecked_reason)
        rubocop = found["rubocop"]
        self.assertTrue(rubocop.direct)
        self.assertTrue(rubocop.dev)
        self.assertEqual(rubocop.version, "1.60.2")
        self.assertIsNone(rubocop.unchecked_reason)
        minitest = found["minitest"]
        self.assertFalse(minitest.direct)
        self.assertTrue(minitest.dev)
        self.assertEqual(minitest.version, "5.20.0")
        json = found["json"]
        self.assertEqual(json.version, "2.7.1")
        self.assertFalse(json.direct)
        self.assertTrue(json.dev)
        self.assertIn("git source", found["git_pkg"].unchecked_reason)
        self.assertTrue(found["git_pkg"].direct)
        self.assertEqual(found["git_pkg"].version, "0.2.0")
        self.assertIn("path source", found["path_pkg"].unchecked_reason)
        self.assertTrue(found["path_pkg"].direct)
        self.assertIn("gem source", found["sidekiq-pro"].unchecked_reason)
        self.assertTrue(found["sidekiq-pro"].direct)
        self.assertFalse(found["sidekiq-pro"].dev)
        only_child = found["only_child"]
        self.assertEqual(only_child.version, "1.2.3")
        self.assertEqual(only_child.manifest, "extra/Gemfile")
        self.assertIsNone(only_child.unchecked_reason)
        child_rails = found["child_rails"]
        self.assertEqual(child_rails.manifest, "extra/Gemfile")
        self.assertEqual(child_rails.unchecked_reason, "version is a range, no lockfile")

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.ecosystem, pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("RubyGems", "rails", "7.1.3"), seen)
        self.assertIn(("RubyGems", "nokogiri", "1.16.5"), seen)
        self.assertIn(("RubyGems", "rake", "13.2.1"), seen)
        self.assertIn(("RubyGems", "rubocop", "1.60.2"), seen)
        self.assertIn(("RubyGems", "minitest", "5.20.0"), seen)
        self.assertIn(("RubyGems", "only_child", "1.2.3"), seen)
        sent = {name for _ecosystem, name, _version in seen}
        self.assertNotIn("git_pkg", sent)
        self.assertNotIn("path_pkg", sent)
        self.assertNotIn("sidekiq-pro", sent)
        self.assertNotIn("1.16.5-x86_64-linux", {version for _eco, _name, version in seen})

    def test_gemfile_without_a_lock_keeps_ranges(self):
        text = """
source "https://rubygems.org"
gem "rake", "13.2.1"
gem("rails", "~> 7.1")
gem "git_pkg", github: "acme/git_pkg"
group :test do
  gem "minitest", "5.20.0"
end
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Gemfile").write_text(text, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        rake = found["rake"]
        self.assertEqual(rake.version, "13.2.1")
        self.assertTrue(rake.direct)
        self.assertFalse(rake.dev)
        self.assertIsNone(rake.unchecked_reason)
        rails = found["rails"]
        self.assertEqual(rails.unchecked_reason, "version is a range, no lockfile")
        self.assertFalse(rails.dev)
        self.assertIn("git source", found["git_pkg"].unchecked_reason)
        minitest = found["minitest"]
        self.assertEqual(minitest.version, "5.20.0")
        self.assertTrue(minitest.dev)
        self.assertIsNone(minitest.unchecked_reason)

    def test_broken_gemfile_lock_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Gemfile.lock").write_text("this is not a lock\n", encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertIn("could not parse", found[0].unchecked_reason)

    def test_go_mod_keeps_exact_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text(GO_MOD, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["github.com/foo/bar"].version, "v1.2.3")
        self.assertTrue(found["github.com/foo/bar"].direct)
        self.assertFalse(found["github.com/foo/baz"].direct)
        self.assertTrue(found["github.com/solo/mod"].direct)

    def test_go_replace_uses_the_copy_that_is_built(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text(GO_REPLACE, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        local = found["github.com/local/mod"]
        forked = found["github.com/forked/mod"]
        same = found["github.com/same/mod"]
        untouched = found["github.com/untouched/mod"]
        self.assertIn("replaced", local.unchecked_reason)
        self.assertIn("../local/mod", local.unchecked_reason)
        self.assertTrue(local.direct)
        self.assertIn("replaced", forked.unchecked_reason)
        self.assertIn("github.com/other/mod", forked.unchecked_reason)
        self.assertIsNone(same.unchecked_reason)
        self.assertEqual(same.version, "v1.9.0")
        self.assertTrue(same.direct)
        self.assertEqual(untouched.version, "v1.2.3")
        self.assertFalse(untouched.direct)
        self.assertIsNone(untouched.unchecked_reason)

        seen = []

        def fake_batch(chunk):
            seen.extend((pkg.name, pkg.version) for pkg in chunk)
            return [{"vulns": []} for _ in chunk]

        original = match._post_batch
        match._post_batch = fake_batch
        try:
            query_osv(list(found.values()), cache=NullCache())
        finally:
            match._post_batch = original
        self.assertIn(("github.com/same/mod", "v1.9.0"), seen)
        self.assertIn(("github.com/untouched/mod", "v1.2.3"), seen)
        self.assertNotIn("github.com/local/mod", [name for name, _version in seen])
        self.assertNotIn("github.com/forked/mod", [name for name, _version in seen])

    def test_requirements_pin_and_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "requirements.txt").write_text(
                "Requests==2.31.0\nflask>=2\n",
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["requests"].version, "2.31.0")
        self.assertEqual(found["requests"].ecosystem, "PyPI")
        self.assertIsNone(found["requests"].unchecked_reason)
        self.assertIsNotNone(found["flask"].unchecked_reason)

    def test_uv_lock_skips_the_project_and_marks_direct(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "uv.lock").write_text(UV, encoding="utf-8")
            Path(tmp, "pyproject.toml").write_text(
                '[project]\nname = "app"\ndependencies = ["requests>=2"]\n',
                encoding="utf-8",
            )
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertNotIn("app", found)
        self.assertTrue(found["requests"].direct)
        self.assertFalse(found["urllib3"].direct)

    def test_cargo_lock_and_git_dep(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Cargo.lock").write_text(CARGO_LOCK, encoding="utf-8")
            Path(tmp, "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertNotIn("app", found)
        self.assertNotIn("serde1", found)
        serde = found["serde"]
        self.assertTrue(serde.direct)
        self.assertEqual(serde.ecosystem, "crates.io")
        self.assertEqual(serde.alias, "serde1")
        self.assertIsNone(serde.unchecked_reason)
        self.assertTrue(found["libc"].direct)
        self.assertIsNone(found["libc"].alias)
        self.assertIn("git dependency", found["leftpad"].unchecked_reason)
        serde.vulns = [Finding("GHSA-1", None, "high", "example", "1.0.153", "vulnerability", True)]
        text = render_text(Snapshot(".", None, None, [serde]))
        self.assertIn("serde  1.0.152", text)
        self.assertIn("as serde1", text)

    def test_cargo_rename_without_a_lock_uses_the_crate_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "Cargo.toml").write_text(CARGO_RENAME_ONLY, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertNotIn("serde1", found)
        serde = found["serde"]
        self.assertEqual(serde.alias, "serde1")
        self.assertEqual(serde.unchecked_reason, "version is a range, no lockfile")
        text = render_text(Snapshot(".", None, None, [serde]))
        self.assertIn("as serde1", text)
        self.assertNotIn("unrecognised names:", text)

    def test_broken_lock_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package-lock.json").write_text("{", encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertIn("could not parse", found[0].unchecked_reason)

    def test_dedupe_prefers_prod_over_dev(self):
        dev = Package("npm", "lodash", "4.17.20", True, True, "a/package-lock.json")
        prod = Package("npm", "lodash", "4.17.20", True, False, "package-lock.json")
        merged = dedupe([dev, prod])
        self.assertEqual(len(merged), 1)
        self.assertFalse(merged[0].dev)

    def test_added_lockfiles_are_manifests(self):
        self.assertTrue(is_scan_manifest_relpath("gradle/verification-metadata.xml"))
        self.assertFalse(is_scan_manifest_relpath("verification-metadata.xml"))
        self.assertTrue(is_scan_manifest_relpath("app.deps.json"))
        self.assertTrue(is_scan_manifest_relpath("pylock.django.toml"))
        self.assertTrue(is_scan_manifest_relpath(".gitmodules"))
        self.assertTrue(is_scan_manifest_relpath("Pipfile.lock"))

    def test_conan_mix_haskell_and_bun_locks(self):
        conan = json.dumps({
            "version": "0.5",
            "requires": ["zlib/1.2.13#rrev"],
            "build_requires": ["cmake/3.27.0@"],
            "python_requires": ["consumer/1.0"],
        })
        mix = """
%{
  "decimal": {:hex, :decimal, "2.1.1", "abc", [:ecto], [], "hexpm", "def"},
  "git_pkg": {:git, "https://github.com/acme/git_pkg.git", "abc123", []},
}
"""
        freeze = """
constraints: any.base ==4.17.2.0,
             any.bytestring ==0.11.5.3
"""
        stack = """
snapshots:
- completed:
    hackage: bytestring-0.11.5.3@sha256:aaaa,1234
"""
        bun = json.dumps({
            "lockfileVersion": 1,
            "packages": {
                "left-pad": ["left-pad@1.3.0", "", {}, "sha"],
                "@scope/pkg": ["@scope/pkg@2.0.0", "", {}, "sha"],
                "local": ["local@file:../local", "", {}, ""],
                "gitpkg": ["gitpkg@1.0.0#abcdef", "", {}, ""],
            },
        })
        package_json = json.dumps({
            "dependencies": {"left-pad": "1.3.0"},
            "devDependencies": {"@scope/pkg": "2.0.0"},
        })
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "conan.lock").write_text(conan, encoding="utf-8")
            (root / "mix.lock").write_text(mix, encoding="utf-8")
            (root / "cabal.project.freeze").write_text(freeze, encoding="utf-8")
            (root / "stack.yaml.lock").write_text(stack, encoding="utf-8")
            (root / "bun.lock").write_text(bun, encoding="utf-8")
            (root / "package.json").write_text(package_json, encoding="utf-8")
            found = { (pkg.ecosystem, pkg.name): pkg for pkg in scan_tree(root) }
        zlib = found[("ConanCenter", "zlib")]
        self.assertEqual(zlib.version, "1.2.13")
        self.assertTrue(zlib.direct)
        self.assertFalse(zlib.dev)
        self.assertIsNone(zlib.unchecked_reason)
        cmake = found[("ConanCenter", "cmake")]
        self.assertTrue(cmake.dev)
        self.assertEqual(found[("Hex", "decimal")].version, "2.1.1")
        self.assertIn("git source", found[("Hex", "git_pkg")].unchecked_reason)
        self.assertEqual(found[("Hackage", "bytestring")].version, "0.11.5.3")
        self.assertEqual(found[("Hackage", "base")].version, "4.17.2.0")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "cabal.project.freeze").write_text(
                "index-state: hackage.haskell.org 2026-08-10T16:58:32Z\n",
                encoding="utf-8",
            )
            self.assertEqual(scan_tree(Path(tmp)), [])
        left = found[("npm", "left-pad")]
        self.assertEqual(left.version, "1.3.0")
        self.assertTrue(left.direct)
        self.assertFalse(left.dev)
        scoped = found[("npm", "@scope/pkg")]
        self.assertTrue(scoped.dev)
        self.assertEqual(scoped.version, "2.0.0")
        self.assertIn("path source", found[("npm", "local")].unchecked_reason)
        self.assertIn("git source", found[("npm", "gitpkg")].unchecked_reason)

    def test_bun_lock_allows_trailing_commas(self):
        text = """
{
  "lockfileVersion": 1,
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha",],
  },
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "bun.lock").write_text(text, encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "left-pad")
        self.assertEqual(found[0].version, "1.3.0")
        self.assertIsNone(found[0].unchecked_reason)

    def test_nuget_python_r_and_gems_locked(self):
        deps = json.dumps({
            "libraries": {
                "Newtonsoft.Json/13.0.3": {"type": "package", "version": "13.0.3"},
                "App/1.0.0": {"type": "project", "version": "1.0.0"},
            }
        })
        packages_config = """
<packages>
  <package id="jQuery" version="3.7.1" targetFramework="net48" />
</packages>
"""
        packages_lock = json.dumps({
            "version": 1,
            "dependencies": {
                ".NETCoreApp,Version=v8.0": {
                    "Serilog": {"type": "Direct", "requested": "3.1.1", "resolved": "3.1.1"},
                }
            },
        })
        pipfile = json.dumps({
            "default": {"Requests": {"version": "==2.31.0"}},
            "develop": {"pytest": {"version": "==8.1.1"}, "Requests": {"version": "==2.31.0"}},
        })
        pdm = """
lock-version = "4.4"
[[package]]
name = "certifi"
version = "2024.2.2"
groups = ["default"]
[[package]]
name = "pytest"
version = "8.1.1"
groups = ["dev"]
"""
        pylock = """
lock-version = "1.0"
[[packages]]
name = "idna"
version = "3.6"
[[packages]]
name = "app"
directory = { path = "." }
[[packages]]
name = "gitpkg"
vcs = { type = "git", commit-id = "abc123" }
"""
        renv = json.dumps({
            "Packages": {
                "ggplot2": {"Package": "ggplot2", "Version": "3.5.0", "Repository": "CRAN"},
                "localpkg": {"Package": "localpkg", "Version": "0.1.0", "Repository": "local"},
            }
        })
        gems = """
GEM
  remote: https://rubygems.org/
  specs:
    rake (13.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake

BUNDLED WITH
   2.4.0
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deps.json").write_text(deps, encoding="utf-8")
            (root / "editor.deps.json").write_text("{}", encoding="utf-8")
            (root / "packages.config").write_text(packages_config, encoding="utf-8")
            (root / "packages.lock.json").write_text(packages_lock, encoding="utf-8")
            (root / "Pipfile.lock").write_text(pipfile, encoding="utf-8")
            (root / "pdm.lock").write_text(pdm, encoding="utf-8")
            (root / "pylock.toml").write_text(pylock, encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='app'\n", encoding="utf-8")
            (root / "renv.lock").write_text(renv, encoding="utf-8")
            (root / "gems.locked").write_text(gems, encoding="utf-8")
            found = {(pkg.ecosystem, pkg.name): pkg for pkg in scan_tree(root)}
        self.assertEqual(found[("NuGet", "Newtonsoft.Json")].version, "13.0.3")
        self.assertNotIn(("NuGet", "App"), found)
        self.assertNotIn(("NuGet", "editor.deps.json"), found)
        self.assertEqual(found[("NuGet", "jQuery")].version, "3.7.1")
        self.assertTrue(found[("NuGet", "jQuery")].direct)
        self.assertEqual(found[("NuGet", "Serilog")].version, "3.1.1")
        requests = found[("PyPI", "requests")]
        self.assertEqual(requests.version, "2.31.0")
        self.assertFalse(requests.dev)
        self.assertTrue(found[("PyPI", "pytest")].dev)
        self.assertEqual(found[("PyPI", "certifi")].version, "2024.2.2")
        self.assertTrue(found[("PyPI", "certifi")].direct)
        self.assertEqual(found[("PyPI", "idna")].version, "3.6")
        self.assertIn("git source", found[("PyPI", "gitpkg")].unchecked_reason)
        self.assertNotIn(("PyPI", "app"), found)
        self.assertEqual(found[("CRAN", "ggplot2")].version, "3.5.0")
        self.assertIn("not a CRAN release", found[("CRAN", "localpkg")].unchecked_reason)
        self.assertEqual(found[("RubyGems", "rake")].version, "13.1.0")
        self.assertIsNone(found[("RubyGems", "rake")].unchecked_reason)

    def test_dart_config_and_extra_gradle_locks(self):
        package_config = json.dumps({
            "configVersion": 2,
            "packages": [
                {"name": "collection", "rootUri": "file:///cache/hosted/pub.dev/collection-1.18.0"},
                {"name": "app", "rootUri": "../"},
            ],
        })
        buildscript = "com.google.guava:guava:31.1-jre=classpath\n"
        verification = """
<verification-metadata>
  <components>
    <component group="org.slf4j" name="slf4j-api" version="2.0.9"/>
  </components>
</verification-metadata>
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dart = root / ".dart_tool"
            dart.mkdir()
            (dart / "package_config.json").write_text(package_config, encoding="utf-8")
            (root / "buildscript-gradle.lockfile").write_text(buildscript, encoding="utf-8")
            gradle = root / "gradle"
            gradle.mkdir()
            (gradle / "verification-metadata.xml").write_text(verification, encoding="utf-8")
            (root / "build.gradle").write_text("dependencies {}", encoding="utf-8")
            found = {(pkg.ecosystem, pkg.name): pkg for pkg in scan_tree(root)}
        self.assertEqual(found[("Pub", "collection")].version, "1.18.0")
        self.assertIsNone(found[("Pub", "collection")].unchecked_reason)
        self.assertIn("path source", found[("Pub", "app")].unchecked_reason)
        self.assertEqual(found[("Maven", "com.google.guava:guava")].version, "31.1-jre")
        self.assertEqual(found[("Maven", "org.slf4j:slf4j-api")].version, "2.0.9")
        self.assertNotIn(("Maven", "build.gradle"), found)

    def test_broken_new_lock_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "conan.lock").write_text("{", encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertIn("could not parse", found[0].unchecked_reason)

    def test_gitmodules_without_a_commit_is_unchecked(self):
        text = """
[submodule "third_party/libfoo"]
    path = third_party/libfoo
    url = git@github.com:example/libfoo.git
"""
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".gitmodules").write_text(text, encoding="utf-8")
            found = scan_tree(Path(tmp))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ecosystem, "GIT")
        self.assertEqual(found[0].name, "https://github.com/example/libfoo")
        self.assertEqual(found[0].unchecked_reason, "git commit was not read")

    @unittest.skipUnless(shutil.which("git"), "git is not on PATH")
    def test_vendored_checkout_records_its_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vendor = root / "third_party" / "libfoo"
            vendor.mkdir(parents=True)
            (vendor / "README").write_text("hi", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_AUTHOR_NAME"] = "test"
            env["GIT_AUTHOR_EMAIL"] = "test@example.com"
            env["GIT_COMMITTER_NAME"] = "test"
            env["GIT_COMMITTER_EMAIL"] = "test@example.com"
            def git(*args):
                subprocess.run(["git", *args], cwd=vendor, check=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            git("init")
            git("remote", "add", "origin", "https://github.com/example/libfoo.git")
            git("add", "README")
            git("commit", "-m", "init")
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=vendor, env=env, text=True).strip()
            found = {pkg.name: pkg for pkg in scan_tree(root)}
        pinned = found["https://github.com/example/libfoo"]
        self.assertEqual(pinned.ecosystem, "GIT")
        self.assertEqual(pinned.version, sha)
        self.assertIsNone(pinned.unchecked_reason)
        self.assertTrue(pinned.direct)


class OsvZipTests(unittest.TestCase):
    def test_read_advisory_from_cached_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = DiskCache(Path(tmp), ttl_seconds=3600)
            zip_path = cache.root / "osv-zips" / "npm" / "all.zip"
            zip_path.parent.mkdir(parents=True)
            payload = {"id": "GHSA-test", "summary": "from zip"}
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("GHSA-test.json", json.dumps(payload))
            body = read_advisory_from_zip("GHSA-test", "npm", cache)
            self.assertEqual(body, payload)
            self.assertIsNone(read_advisory_from_zip("GHSA-missing", "npm", cache))


class MatchTests(unittest.TestCase):
    def test_cvss_critical_vector(self):
        self.assertEqual(cvss_v3_score(CRITICAL), 9.8)

    def test_range_reintroduced(self):
        events = [
            {"introduced": "0"},
            {"fixed": "1.2.0"},
            {"introduced": "1.4.0"},
            {"fixed": "1.4.2"},
        ]
        self.assertTrue(range_contains("1.0.0", events))
        self.assertFalse(range_contains("1.3.0", events))
        self.assertTrue(range_contains("1.4.1", events))
        self.assertFalse(range_contains("1.4.2", events))

    def test_local_range_can_drop_api_hit(self):
        package = Package("npm", "lodash", "1.0.0", True, False, "package-lock.json")
        annotate([package], [{
            "vulns": [_advisory("4.17.21", events=[{"introduced": "0"}, {"fixed": "1"}])],
        }])
        self.assertEqual(package.vulns, [])

    def test_alias_records_group_to_one_finding(self):
        package = Package("npm", "lodash", "4.17.20", True, False, "package-lock.json")
        ghsa = _advisory("4.17.21", osv_id="GHSA-1", cve="CVE-2021-1")
        ghsa["aliases"] = ["CVE-2021-1", "OSV-1"]
        duplicate = _advisory("4.17.21", osv_id="OSV-1", cve=None)
        duplicate["aliases"] = ["GHSA-1", "CVE-2021-1"]
        annotate([package], [{"vulns": [ghsa, duplicate]}])
        self.assertEqual(len(package.vulns), 1)
        self.assertEqual(package.vulns[0].osv_id, "GHSA-1")
        self.assertIn("OSV-1", package.vulns[0].related_ids)

    def test_range_unsorted_events(self):
        events = [
            {"introduced": "0"},
            {"introduced": "2.1.0"},
            {"fixed": "1"},
            {"last_affected": "3.1.9"},
        ]
        for version, affected in (
            ("1.0.0", False),
            ("2.0.1", False),
            ("3.1.9", True),
            ("3.2.0", False),
        ):
            self.assertEqual(range_contains(version, events), affected, version)

    def test_recommend_is_the_highest_fix(self):
        package = Package("npm", "lodash", "4.17.20", True, False, "package-lock.json")
        annotate([package], [{
            "vulns": [
                _advisory("4.17.21"),
                _advisory("4.17.23", osv_id="GHSA-2", cve="CVE-2021-2"),
            ]
        }])
        self.assertEqual(package.recommend, "4.17.23")
        self.assertEqual(package.vulns[0].severity, "critical")
        self.assertEqual(package.vulns[0].cve, "CVE-2021-1")

    def test_batch_ids_are_replaced_with_full_advisories(self):
        full = _advisory("4.17.21", osv_id="GHSA-1")

        def fetch(osv_id):
            self.assertEqual(osv_id, "GHSA-1")
            return full

        hydrated = hydrate([{"vulns": [{"id": "GHSA-1"}]}], fetch)
        package = Package("npm", "lodash", "4.17.20", True, False, "package-lock.json")
        annotate([package], hydrated)
        self.assertEqual(package.recommend, "4.17.21")
        self.assertEqual(package.vulns[0].severity, "critical")

    def test_two_stub_ids_are_fetched_together(self):
        entered = threading.Barrier(2)
        calls = []
        lock = threading.Lock()

        def fetch(osv_id):
            with lock:
                calls.append(osv_id)
            entered.wait(timeout=2)
            return _advisory(osv_id=osv_id)

        hydrated = hydrate(
            [{"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}, {"id": "GHSA-1"}]}],
            fetch,
        )
        self.assertEqual(sorted(calls), ["GHSA-1", "GHSA-2"])
        bodies = hydrated[0]["vulns"]
        self.assertEqual([body["id"] for body in bodies], ["GHSA-1", "GHSA-2", "GHSA-1"])
        self.assertIn("affected", bodies[0])
        self.assertIn("affected", bodies[1])
        self.assertIs(bodies[0], bodies[2])

    def test_withdrawn_and_unfixed(self):
        package = Package("npm", "lodash", "1.0.0", True, False, "package-lock.json")
        withdrawn = _advisory("9.9.9", osv_id="GHSA-old")
        withdrawn["withdrawn"] = "2024-01-01T00:00:00Z"
        unfixed = _advisory(events=[{"introduced": "0"}, {"last_affected": "1.0.0"}])
        annotate([package], [{"vulns": [withdrawn, unfixed]}])
        self.assertEqual(len(package.vulns), 1)
        self.assertIsNone(package.vulns[0].fixed_in)
        self.assertIsNone(package.recommend)

    def test_exit_code_ignores_dev_until_strict(self):
        prod = Package("npm", "left-pad", "1.0.0", True, False, "package-lock.json")
        dev = Package("npm", "vitest", "1.0.0", True, True, "package-lock.json")
        dev.vulns = [Finding("GHSA-dev", None, "high", "", "1.0.1", "vulnerability", True)]
        self.assertEqual(exit_code([dev], strict=False), 0)
        self.assertEqual(exit_code([dev], strict=True), 1)
        prod.vulns = [Finding("MAL-1", None, "unknown", "", None, "malware", True)]
        self.assertEqual(exit_code([prod], strict=False), 1)

    def _increasing(self, ecosystem, versions):
        keys = []
        for version in versions:
            key = version_tuple(version, ecosystem)
            self.assertIsNotNone(key, version)
            keys.append(key)
        for earlier, later in zip(keys, keys[1:]):
            self.assertLess(earlier, later)

    def _same(self, ecosystem, versions):
        keys = [version_tuple(version, ecosystem) for version in versions]
        self.assertTrue(all(key is not None for key in keys), versions)
        for key in keys[1:]:
            self.assertEqual(keys[0], key)

    def test_semver_orders_a_pre_release_before_the_release(self):
        chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0-rc.2",
            "1.0.0-rc.10",
            "1.0.0",
        ]
        for ecosystem in ("npm", "Go", "crates.io", "Pub"):
            self._increasing(ecosystem, chain)
            self._same(ecosystem, ["1.0", "1.0.0", "1.0.0+build"])
        self._increasing("npm", ["1.0.0-1", "1.0.0-a"])
        self._increasing("Go", ["v1.0.0-rc.1", "v1.0.0"])
        self.assertIsNone(version_tuple("1.0.0-rc.01", "npm"))
        self.assertIsNone(version_tuple("1.0.0-rc_1", "npm"))
        self.assertIsNone(version_tuple("1.0.0-rc.1"))

    def test_packagist_sorts_stability_the_way_composer_does(self):
        self._increasing("Packagist", [
            "1.0.0-dev",
            "1.0.0-alpha",
            "1.0.0-beta",
            "1.0.0-RC2",
            "1.0.0-RC10",
            "1.0.0",
            "1.0.0-p1",
        ])
        self._same("Packagist", ["1.0.0-alpha", "1.0.0-a", "v1.0.0-alpha"])
        self._same("Packagist", ["1.0.0-beta", "1.0.0-b"])
        self._same("Packagist", ["1.0.0-RC", "1.0.0-rc"])
        self._same("Packagist", ["1.0.0-p1", "1.0.0-pl1", "1.0.0-patch1"])
        self._same("Packagist", ["1.2", "1.2.0", "1.2.0.0", "1.2.0+build"])
        self._same("Packagist", ["v3.5.0", "3.5.0"])
        self.assertIsNone(version_tuple("1.0.0-alpha.beta", "Packagist"))
        package = Package("Packagist", "monolog/monolog", "1.0.0-alpha", True, False, "composer.lock")
        annotate([package], [{"vulns": [
            _advisory("1.0.0-RC2", ecosystem="Packagist", name="monolog/monolog", osv_id="GHSA-1", cve=None),
            _advisory("1.0.0-RC10", ecosystem="Packagist", name="monolog/monolog", osv_id="GHSA-2", cve=None),
        ]}])
        self.assertEqual(package.recommend, "1.0.0-RC10")

    def test_pypi_sorts_the_way_pep_440_does(self):
        self._increasing("PyPI", [
            "1.0.0.dev1",
            "1.0.0a1",
            "1.0.0b1",
            "1.0.0rc1",
            "1.0.0",
            "1.0.0.post1",
        ])
        self._same("PyPI", ["1.0", "1.0.0"])
        self._same("PyPI", ["1.0.0rc1", "1.0.0.rc.1", "1.0.0rc.1"])
        self.assertLess(version_tuple("1.0.0", "PyPI"), version_tuple("1.0.0+ubuntu", "PyPI"))
        self.assertLess(version_tuple("2.0", "PyPI"), version_tuple("1!1.0", "PyPI"))
        self.assertIsNone(version_tuple("v1.0.0", "PyPI"))

    def test_rubygems_sorts_a_letter_before_a_number(self):
        self._increasing("RubyGems", [
            "1.0.0.alpha",
            "1.0.0.beta2",
            "1.0.0.beta9",
            "1.0.0.beta10",
            "1.0.0.rc1",
            "1.0.0",
        ])
        self.assertLess(version_tuple("1.0.0-rc1", "RubyGems"), version_tuple("1.0.0", "RubyGems"))
        self._same("RubyGems", ["1.0", "1.0.0"])
        self.assertIsNone(version_tuple("1.0.0+1", "RubyGems"))

    def test_maven_sorts_qualifiers_around_the_release(self):
        self._increasing("Maven", ["1-snapshot", "1", "1-sp", "1-jre"])
        self._increasing("Maven", ["1-rc1", "1", "1-ga1", "1-sp"])
        self._same("Maven", ["1", "1.0", "1.0.0", "1.ga", "1-ga", "1-ga0", "1-0", "1_0"])
        self._same("Maven", ["1-a1", "1-alpha-1"])
        self._same("Maven", ["1.0-alpha1", "1.0-ALPHA1"])
        self._same("Maven", ["1.foo", "1-foo"])
        self._increasing("Maven", ["1.foo", "1-1", "1.1"])
        self._increasing("Maven", ["1-foo2", "1-foo10"])
        self._increasing("Maven", ["31.1", "31.1-jre"])
        self._increasing("Maven", ["1.K", "1.7"])
        self._increasing("Maven", ["5.aardvark", "5.zebra"])
        self.assertNotEqual(version_tuple("1.0.0+1", "Maven"), version_tuple("1.0.0", "Maven"))
        package = Package("Maven", "com.google.guava:guava", "31.0", True, False, "pom.xml")
        annotate([package], [{"vulns": [
            _advisory(
                "31.1-jre", ecosystem="Maven", name="com.google.guava:guava", osv_id="GHSA-1", cve=None,
            ),
            _advisory(
                "32.0.0-jre", ecosystem="Maven", name="com.google.guava:guava", osv_id="GHSA-2", cve=None,
            ),
        ]}])
        self.assertEqual(package.vulns[0].fixed_in, "31.1-jre")
        self.assertEqual(package.recommend, "32.0.0-jre")

    def test_pre_release_fixes_collapse_to_one_upgrade(self):
        package = Package("npm", "lodash", "1.0.0-beta.1", True, False, "package-lock.json")
        annotate([package], [{"vulns": [{
            "id": "GHSA-1",
            "summary": "example",
            "aliases": ["CVE-2021-1"],
            "severity": [{"type": "CVSS_V3", "score": CRITICAL}],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0-rc.1"}]},
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0-rc.2"}]},
                ],
            }],
        }]}])
        self.assertTrue(package.vulns[0].precise)
        self.assertEqual(package.vulns[0].fixed_in, "1.0.0-rc.2")
        self.assertEqual(package.recommend, "1.0.0-rc.2")

        higher = Package("npm", "lodash", "1.0.0-beta.1", True, False, "package-lock.json")
        annotate([higher], [{"vulns": [
            _advisory("1.0.0-rc.2"),
            _advisory("1.0.0", osv_id="GHSA-2", cve="CVE-2021-2"),
        ]}])
        self.assertEqual(higher.recommend, "1.0.0")

    def test_an_unparsed_fix_is_listed_on_its_own(self):
        package = Package("npm", "lodash", "0.9.0", True, False, "package-lock.json")
        annotate([package], [{"vulns": [_advisory(events=[
            {"introduced": "0"},
            {"fixed": "1.0.0-rc.01"},
            {"introduced": "1.0.0"},
            {"fixed": "1.2.0"},
        ])]}])
        self.assertFalse(package.vulns[0].precise)
        self.assertEqual(package.vulns[0].fixed_in, "1.0.0-rc.01, 1.2.0")
        self.assertIsNone(package.recommend)


class AcquireTests(unittest.TestCase):
    def test_remote_heads_keep_the_default_first_in_meaning(self):
        text = (
            "ref: refs/heads/main\tHEAD\n"
            "abc\trefs/heads/develop\n"
            "def\trefs/heads/main\n"
            "ghi\trefs/heads/feature/scan\n"
        )
        branches, default = parse_remote_heads(text)
        self.assertEqual(branches, ["develop", "main", "feature/scan"])
        self.assertEqual(default, "main")

    def test_bare_host_uses_https(self):
        self.assertEqual(
            normalize_target("github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )
        self.assertEqual(
            normalize_target("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )
        self.assertEqual(
            normalize_target("http://github.com/org/repo.git"),
            "http://github.com/org/repo.git",
        )
        self.assertEqual(
            normalize_target("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git",
        )
        self.assertEqual(normalize_target(r"C:\repos\app"), r"C:\repos\app")

    def test_branch_list_adds_https(self):
        with patch("supply_scan.serve.list_remote_branches", return_value=(["main"], "main")) as listed:
            code, body = branches_response({"target": "github.com/org/repo"})
        self.assertEqual(code, 200)
        listed.assert_called_once_with("https://github.com/org/repo", None)
        self.assertEqual(body["default"], "main")

    def test_picked_folder_is_scanned_in_the_browser(self):
        payload = {
            "target": "app",
            "branch": "main",
            "commit": "abc1234",
            "files": [{
                "path": "package.json",
                "text": json.dumps({"dependencies": {"left-pad": "1.2.3"}}),
            }],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        self.assertEqual(body["target"], "app")
        self.assertEqual(body["branch"], "main")
        self.assertEqual(body["commit"], "abc1234")
        self.assertEqual(body["packages"][0]["name"], "left-pad")
        self.assertEqual(body["packages"][0]["manifest"], "package.json")

    def test_picked_folder_accepts_composer_lock(self):
        payload = {
            "target": "php-app",
            "files": [
                {
                    "path": "composer.json",
                    "text": json.dumps({"require": {"monolog/monolog": "^3.0"}}),
                },
                {
                    "path": "composer.lock",
                    "text": json.dumps({
                        "packages": [{
                            "name": "monolog/monolog",
                            "version": "v3.5.0",
                            "dist": {"type": "zip", "url": "https://example.test/monolog.zip", "reference": "a"},
                        }],
                        "packages-dev": [],
                    }),
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        self.assertEqual(body["packages"][0]["name"], "monolog/monolog")
        self.assertEqual(body["packages"][0]["ecosystem"], "Packagist")
        self.assertEqual(body["packages"][0]["manifest"], "composer.lock")
        self.assertTrue(body["packages"][0]["direct"])

    def test_picked_folder_accepts_pubspec_lock(self):
        payload = {
            "target": "dart-app",
            "files": [
                {
                    "path": "pubspec.yaml",
                    "text": "name: app\ndependencies:\n  collection: ^1.18.0\n",
                },
                {
                    "path": "pubspec.lock",
                    "text": """
packages:
  collection:
    dependency: "direct main"
    description:
      name: collection
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
""",
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        self.assertEqual(len(body["packages"]), 1)
        self.assertEqual(body["packages"][0]["name"], "collection")
        self.assertEqual(body["packages"][0]["ecosystem"], "Pub")
        self.assertEqual(body["packages"][0]["version"], "1.18.0")
        self.assertEqual(body["packages"][0]["manifest"], "pubspec.lock")
        self.assertTrue(body["packages"][0]["direct"])

    def test_picked_folder_accepts_gemfile_lock(self):
        payload = {
            "target": "ruby-app",
            "files": [
                {
                    "path": "Gemfile",
                    "text": 'gem "nokogiri", "~> 1.16"\n',
                },
                {
                    "path": "Gemfile.lock",
                    "text": """
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.5-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)

DEPENDENCIES
  nokogiri

BUNDLED WITH
   2.5.3
""",
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        by_name = {package["name"]: package for package in body["packages"]}
        self.assertEqual(set(by_name), {"nokogiri", "racc"})
        self.assertEqual(by_name["nokogiri"]["ecosystem"], "RubyGems")
        self.assertEqual(by_name["nokogiri"]["version"], "1.16.5")
        self.assertEqual(by_name["nokogiri"]["manifest"], "Gemfile.lock")
        self.assertTrue(by_name["nokogiri"]["direct"])
        self.assertFalse(by_name["racc"]["direct"])

    def test_picked_folder_accepts_yarn_lock(self):
        payload = {
            "target": "js-app",
            "files": [
                {
                    "path": "package.json",
                    "text": json.dumps({"dependencies": {"lodash": "^4.17.21"}}),
                },
                {
                    "path": "yarn.lock",
                    "text": """
# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"
""",
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        self.assertEqual(len(body["packages"]), 1)
        self.assertEqual(body["packages"][0]["name"], "lodash")
        self.assertEqual(body["packages"][0]["ecosystem"], "npm")
        self.assertEqual(body["packages"][0]["version"], "4.17.21")
        self.assertEqual(body["packages"][0]["manifest"], "yarn.lock")
        self.assertTrue(body["packages"][0]["direct"])

    def test_picked_folder_accepts_pom(self):
        payload = {
            "target": "java-app",
            "files": [
                {
                    "path": "pom.xml",
                    "text": """
<project>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${missing.version}</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
""",
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        by_name = {package["name"]: package for package in body["packages"]}
        self.assertEqual(by_name["com.google.guava:guava"]["ecosystem"], "Maven")
        self.assertEqual(by_name["com.google.guava:guava"]["version"], "31.1-jre")
        self.assertEqual(by_name["com.google.guava:guava"]["manifest"], "pom.xml")
        self.assertIsNone(by_name["com.google.guava:guava"]["unchecked_reason"])
        self.assertEqual(by_name["junit:junit"]["unchecked_reason"], "version is not written in the repo")
        self.assertTrue(by_name["junit:junit"]["dev"])
        self.assertEqual(body["unrecognised_names"], ["missing.version"])

    def test_picked_folder_accepts_gradle_lock_and_catalog(self):
        payload = {
            "target": "java-app",
            "files": [
                {
                    "path": "gradle/libs.versions.toml",
                    "text": """
[libraries]
guava = { module = "com.google.guava:guava", version = "31.1-jre" }
commons = { module = "org.apache.commons:commons-lang3", version = "3.14.0" }
slf4j = { module = "org.slf4j:slf4j-api", version = "1.+" }
""",
                },
                {
                    "path": "gradle.lockfile",
                    "text": """
# This is a Gradle generated file for dependency locking.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.junit.jupiter:junit-jupiter:5.10.2=testCompileClasspath,testRuntimeClasspath
com.google.guava:failureaccess:1.0.1=runtimeClasspath
""",
                },
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        by_name = {package["name"]: package for package in body["packages"]}
        self.assertEqual(by_name["com.google.guava:guava"]["ecosystem"], "Maven")
        self.assertEqual(by_name["com.google.guava:guava"]["version"], "31.1-jre")
        self.assertEqual(by_name["com.google.guava:guava"]["manifest"], "gradle.lockfile")
        self.assertTrue(by_name["com.google.guava:guava"]["direct"])
        self.assertFalse(by_name["com.google.guava:guava"]["dev"])
        self.assertTrue(by_name["org.junit.jupiter:junit-jupiter"]["dev"])
        self.assertFalse(by_name["com.google.guava:failureaccess"]["direct"])
        self.assertEqual(by_name["org.apache.commons:commons-lang3"]["version"], "3.14.0")
        self.assertEqual(by_name["org.apache.commons:commons-lang3"]["manifest"], "gradle/libs.versions.toml")
        self.assertEqual(by_name["org.slf4j:slf4j-api"]["unchecked_reason"], "version is a range, no lockfile")
        self.assertIsNone(by_name["com.google.guava:guava"]["unchecked_reason"])

    def test_picked_folder_drops_paths_outside_the_folder(self):
        payload = {
            "target": "app",
            "files": [
                {"path": "../outside.json", "text": "{}"},
                {"path": "notes.txt", "text": "no"},
                {"path": "pkg/go.mod", "text": "module example.com/pkg\n\ngo 1.22\n\nrequire example.com/dep v1.2.3\n"},
            ],
        }
        with patch("supply_scan.run.query_osv"):
            code, body = scan_response(payload)
        self.assertEqual(code, 200)
        names = [package["name"] for package in body["packages"]]
        self.assertEqual(names, ["example.com/dep"])
        self.assertEqual(body["packages"][0]["manifest"], "pkg/go.mod")

    def test_branch_list_rejects_a_path(self):
        code, body = branches_response({"target": "C:/not/a/url"})
        self.assertEqual(code, 400)
        self.assertIn("git URL", body["error"])

    def test_url_allowlist(self):
        self.assertEqual(
            sanitize_git_url("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )
        with self.assertRaises(AcquireError):
            sanitize_git_url("https://github.com/org/repo.git && calc.exe")

    def test_clone_command_uses_no_checkout_and_hardening(self):
        target = Path("C:/temp/supply-scan-repos/demo_ab12cd34")
        cmd = build_clone_command("https://github.com/org/repo.git", target, "main")
        self.assertIn("--no-checkout", cmd)
        self.assertIn("--depth", cmd)
        self.assertEqual(cmd[cmd.index("--depth") + 1], "1")
        for flag in clone_git_config_args():
            self.assertIn(flag, cmd)
        self.assertIn("-b", cmd)
        self.assertEqual(cmd[cmd.index("-b") + 1], "main")
        env = build_clone_environment()
        self.assertNotIn("GIT_CONFIG_NOSYSTEM", env)
        self.assertNotIn("GIT_TERMINAL_PROMPT", env)
        self.assertNotIn("credential.helper=", " ".join(cmd))

    def test_partial_manifest_tree_matches_a_full_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
            Path(root, "packages", "app").mkdir(parents=True)
            Path(root, "packages", "app", "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0"}}),
                encoding="utf-8",
            )
            full = scan_tree(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            Path(root, "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
            Path(root, "packages", "app").mkdir(parents=True)
            Path(root, "packages", "app", "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0"}}),
                encoding="utf-8",
            )
            partial = scan_tree(root)

        def key(pkg):
            return (
                pkg.ecosystem,
                pkg.name,
                pkg.version,
                pkg.direct,
                pkg.dev,
                pkg.manifest,
                pkg.unchecked_reason,
            )

        self.assertEqual(sorted(key(p) for p in full), sorted(key(p) for p in partial))

    def test_no_checkout_clone_materializes_manifests(self):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            origin.mkdir()
            (origin / "go.mod").write_text(GO_MOD, encoding="utf-8")
            (origin / "readme.txt").write_text("not a manifest", encoding="utf-8")
            git_env = {
                **os.environ,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            }
            subprocess.run(["git", "init"], cwd=origin, check=True, env=git_env)
            subprocess.run(
                ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "add", "."],
                cwd=origin,
                check=True,
                env=git_env,
            )
            subprocess.run(
                ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-m", "init"],
                cwd=origin,
                check=True,
                env=git_env,
            )

            clone_dir = Path(tmp) / "clone"
            subprocess.run(
                ["git", "clone", "--no-checkout", str(origin), str(clone_dir)],
                check=True,
                env=git_env,
            )
            self.assertFalse((clone_dir / "readme.txt").exists())
            materialize_scan_manifests(clone_dir)
            self.assertTrue((clone_dir / "go.mod").exists())
            self.assertFalse((clone_dir / "readme.txt").exists())
            found = scan_tree(clone_dir)
            self.assertEqual(found[0].ecosystem, "Go")

    def test_local_directory_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text(GO_MOD, encoding="utf-8")
            with open_workspace(tmp) as workspace:
                self.assertFalse(workspace.cloned)
                found = scan_tree(workspace.path)
            self.assertTrue(Path(tmp).exists())
            self.assertEqual(found[0].ecosystem, "Go")

    def test_readonly_git_objects_are_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo" / ".git" / "objects"
            target.mkdir(parents=True)
            blob = target / "abc"
            blob.write_text("x", encoding="utf-8")
            os.chmod(blob, stat.S_IREAD)
            delete_tree(Path(tmp) / "repo")
            self.assertFalse((Path(tmp) / "repo").exists())


class CacheTests(unittest.TestCase):
    def test_query_and_advisory_are_reused_until_they_expire(self):
        clock = {"now": 1_000.0}
        with tempfile.TemporaryDirectory() as tmp:
            cache = DiskCache(Path(tmp), ttl_seconds=10, now=lambda: clock["now"])
            cache.put_query("npm", "lodash", "4.17.20", {"vulns": [{"id": "GHSA-1"}]})
            cache.put_advisory("GHSA-1", {"id": "GHSA-1", "summary": "old"})
            self.assertEqual(cache.get_query("npm", "lodash", "4.17.20")["vulns"][0]["id"], "GHSA-1")
            self.assertEqual(cache.get_advisory("GHSA-1")["summary"], "old")
            clock["now"] = 1_020.0
            self.assertIsNone(cache.get_query("npm", "lodash", "4.17.20"))
            self.assertIsNone(cache.get_advisory("GHSA-1"))


class RunScanTests(unittest.TestCase):
    def test_page_scan_matches_the_cli_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package.json").write_text(
                json.dumps({"dependencies": {"express": "^4.18.0"}}),
                encoding="utf-8",
            )
            out = Path(tmp, "supply-scan-report.json")
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                status = main([tmp, "--json", str(out), "--no-cache"])
            report = run_scan(tmp, use_cache=False)
            self.assertEqual(report.pop("exit_code"), status)
            self.assertEqual(report, json.loads(out.read_text(encoding="utf-8")))
            code, body = scan_response({"target": tmp, "branch": "", "strict": False})
            self.assertEqual(code, 200)
            self.assertEqual(body["exit_code"], status)
            body.pop("exit_code")
            self.assertEqual(body, report)

    def test_strict_changes_the_exit_code_only(self):
        def plant(packages, cache=None):
            packages[0].vulns = [Finding("GHSA-dev", None, "high", "", "1.2.4", "vulnerability", True)]

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "package.json").write_text(
                json.dumps({"devDependencies": {"left-pad": "1.2.3"}}),
                encoding="utf-8",
            )
            with patch("supply_scan.run.query_osv", plant):
                loose = run_scan(tmp, strict=False, use_cache=False)
                strict = run_scan(tmp, strict=True, use_cache=False)
            self.assertEqual(loose["exit_code"], 0)
            self.assertEqual(strict["exit_code"], 1)
            loose.pop("exit_code")
            strict.pop("exit_code")
            self.assertEqual(loose, strict)

    def test_missing_directory_uses_the_cli_sentence(self):
        missing = str(Path(tempfile.gettempdir()) / "supply-scan-missing-dir")
        code, body = scan_response({"target": missing})
        self.assertEqual(code, 400)
        self.assertEqual(body["error"], f"Not a directory: {missing}")

    def test_ignore_is_saved_and_does_not_change_the_exit_code(self):
        def plant(packages, cache=None):
            packages[0].vulns = [Finding("GHSA-dev", None, "high", "", "1.2.4", "vulnerability", True)]

        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            tree.mkdir()
            Path(tree, "package.json").write_text(
                json.dumps({"dependencies": {"left-pad": "1.2.3"}}),
                encoding="utf-8",
            )
            ignore_file = Path(tmp) / "ignore.json"
            saved = set_ignored(
                {
                    "ecosystem": "npm",
                    "name": "left-pad",
                    "version": "1.2.3",
                    "id": "GHSA-dev",
                },
                True,
                ignore_file,
            )
            self.assertEqual(len(saved), 1)
            again = set_ignored(
                {
                    "ecosystem": "npm",
                    "name": "left-pad",
                    "version": "1.2.3",
                    "id": "GHSA-dev",
                },
                True,
                ignore_file,
            )
            self.assertEqual(again, saved)
            self.assertEqual(read_ignores(ignore_file), saved)
            with patch("supply_scan.run.query_osv", plant):
                report = run_scan(str(tree), strict=False, use_cache=False)
            self.assertEqual(report["exit_code"], 1)
            self.assertEqual(read_ignores(ignore_file), saved)
            cleared = set_ignored(
                {
                    "ecosystem": "npm",
                    "name": "left-pad",
                    "version": "1.2.3",
                    "id": "GHSA-dev",
                },
                False,
                ignore_file,
            )
            self.assertEqual(cleared, [])

    def test_ignore_request_needs_an_advisory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ignore.json"
            with patch("supply_scan.ignore.default_ignore_path", return_value=path):
                missing, body = ignore_response("POST", {"ignored": True, "name": "lodash"})
                saved, payload = ignore_response(
                    "POST",
                    {
                        "ignored": True,
                        "ecosystem": "npm",
                        "name": "lodash",
                        "version": "4.17.20",
                        "id": "GHSA-1",
                    },
                )
                listed, again = ignore_response("GET")
            self.assertEqual(missing, 400)
            self.assertIn("advisory", body["error"])
            self.assertEqual(saved, 200)
            self.assertEqual(payload["ignores"][0]["id"], "GHSA-1")
            self.assertEqual(listed, 200)
            self.assertEqual(again["ignores"], payload["ignores"])

    def test_blank_target_is_rejected(self):
        code, body = scan_response({"target": "  "})
        self.assertEqual(code, 400)
        self.assertIn("git URL", body["error"])

    def test_scan_progress_reports_file_and_byte_rates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")
            (root / "notes.txt").write_text("hello", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "skip.js").write_text("nope", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("skip", encoding="utf-8")
            expected_bytes = (root / "requirements.txt").lstat().st_size + (root / "notes.txt").lstat().st_size
            events = []
            scan_tree(root, events.append)
        counts = [event for event in events if event["phase"] == "count"]
        reads = [event for event in events if event["phase"] == "read"]
        self.assertTrue(counts)
        self.assertEqual(counts[-1]["files_done"], 2)
        self.assertEqual(counts[-1]["files_total"], 0)
        self.assertEqual(counts[-1]["bytes_done"], expected_bytes)
        self.assertEqual(reads[0]["files_done"], 0)
        self.assertEqual(reads[0]["files_total"], 2)
        self.assertEqual(reads[0]["bytes_done"], 0)
        self.assertEqual(reads[0]["bytes_total"], expected_bytes)
        self.assertEqual(reads[-1]["files_done"], 2)
        self.assertEqual(reads[-1]["files_total"], 2)
        self.assertEqual(reads[-1]["bytes_done"], expected_bytes)
        self.assertEqual(reads[-1]["bytes_total"], expected_bytes)
        self.assertEqual([event["files_done"] for event in reads], sorted(event["files_done"] for event in reads))
        self.assertEqual([event["bytes_done"] for event in reads], sorted(event["bytes_done"] for event in reads))
        self.assertLess(events.index(counts[-1]), events.index(reads[0]))

    def test_scan_progress_moves_before_the_tree_is_finished(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(45):
                (root / f"file-{index}.txt").write_text("x" * (index + 1), encoding="utf-8")
            expected_bytes = sum((root / f"file-{index}.txt").lstat().st_size for index in range(45))
            events = []
            scan_tree(root, events.append)
        reads = [event for event in events if event["phase"] == "read"]
        partial = [event for event in reads if 0 < event["files_done"] < event["files_total"]]
        self.assertTrue(partial)
        self.assertEqual(partial[0]["files_total"], 45)
        self.assertLess(partial[0]["bytes_done"], partial[0]["bytes_total"])
        self.assertEqual(reads[-1]["files_done"], 45)
        self.assertEqual(reads[-1]["bytes_done"], expected_bytes)
        self.assertEqual(reads[-1]["bytes_total"], expected_bytes)

    def test_query_progress_counts_each_package(self):
        packages = [
            Package("npm", "left-pad", "1.0.0", True, False, "package.json"),
            Package("npm", "lodash", "4.17.20", True, False, "package.json"),
        ]
        events = []

        def fake_batch(chunk):
            return [{"vulns": []} for _chunk in chunk]

        with patch("supply_scan.match._post_batch", side_effect=fake_batch):
            query_osv(packages, cache=NullCache(), on_progress=events.append)
        osv = [event for event in events if event["phase"] == "osv"]
        self.assertEqual(osv[0], {"phase": "osv", "packages_done": 0, "packages_total": 2})
        self.assertEqual(osv[-1]["packages_done"], 2)
        self.assertEqual(osv[-1]["packages_total"], 2)
        self.assertEqual([event["packages_done"] for event in osv], sorted(event["packages_done"] for event in osv))

    def test_progress_stream_reports_files_then_the_report(self):
        import urllib.request
        from http.server import ThreadingHTTPServer

        from supply_scan.serve import Handler

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "requirements.txt").write_text("requests>=2\n", encoding="utf-8")
            Path(tmp, "notes.txt").write_text("hello", encoding="utf-8")
            body = json.dumps({"target": tmp, "strict": False}).encode()
            request = urllib.request.Request(
                f"http://{host}:{port}/scan",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/x-ndjson",
                },
            )
            with patch("supply_scan.serve.save_scan", return_value={"id": "stream-test"}):
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read().decode()
                    content_type = response.headers.get("Content-Type", "")
        self.assertIn("ndjson", content_type)
        lines = [json.loads(line) for line in raw.splitlines() if line.strip()]
        reads = [
            line for line in lines
            if line["event"] == "progress" and line["phase"] == "read"
        ]
        self.assertTrue(reads)
        self.assertEqual(reads[0]["files_done"], 0)
        self.assertEqual(reads[-1]["files_done"], reads[-1]["files_total"])
        self.assertEqual(reads[-1]["bytes_done"], reads[-1]["bytes_total"])
        self.assertGreater(reads[-1]["bytes_total"], 0)
        self.assertEqual(lines[-1]["event"], "result")
        self.assertTrue(lines[-1]["ok"])
        self.assertEqual(lines[-1]["report"]["scan_id"], "stream-test")
        self.assertIn("packages", lines[-1]["report"])


def _one(name, version, osv_id, **extra):
    findings = extra.pop("vulns", None)
    if findings is None and osv_id is not None:
        findings = [{
            "id": osv_id,
            "cve": None,
            "severity": extra.pop("severity", "high"),
            "summary": "sample",
            "fixed_in": "9.0.0",
            "kind": extra.pop("kind", "vulnerability"),
        }]
    row = {
        "ecosystem": extra.pop("ecosystem", "npm"),
        "name": name,
        "version": version,
        "direct": extra.pop("direct", True),
        "dev": extra.pop("dev", False),
        "manifest": extra.pop("manifest", "package-lock.json"),
        "unchecked_reason": extra.pop("unchecked_reason", None),
        "recommend": extra.pop("recommend", None),
        "alias": extra.pop("alias", None),
        "vulns": findings or [],
    }
    row.update(extra)
    return row


def _ids(rows):
    return [finding["id"] for row in rows for finding in row["vulns"]]


def _marked(row):
    return [(item["id"], item["status"]) for item in row["advisories"]]


class CompareTests(unittest.TestCase):
    def test_same_version_is_an_advisory_change(self):
        current = {"packages": [_one("lodash", "4.17.20", None, vulns=[
            _finding("GHSA-stay"),
            _finding("GHSA-new"),
        ])]}
        previous = {"packages": [_one("lodash", "4.17.20", None, vulns=[
            _finding("GHSA-stay"),
            _finding("GHSA-old"),
        ])]}
        result = compare_reports(current, previous)
        self.assertEqual([row["change"] for row in result["rows"]], ["advisory_changed"])
        self.assertEqual(_marked(result["rows"][0]), [
            ("GHSA-new", "appeared"),
            ("GHSA-old", "cleared"),
            ("GHSA-stay", "still"),
        ])

    def test_a_version_change_keeps_the_advisory_on_the_same_package(self):
        current = {"packages": [_one("lodash", "4.17.21", "GHSA-stay", recommend="9.1.0")]}
        previous = {"packages": [_one("lodash", "4.17.20", "GHSA-stay", recommend="9.0.0")]}
        result = compare_reports(current, previous)
        row = result["rows"][0]
        self.assertEqual(row["change"], "version_changed")
        self.assertEqual(row["current"][0]["version"], "4.17.21")
        self.assertEqual(row["previous"][0]["version"], "4.17.20")
        self.assertEqual(_marked(row), [("GHSA-stay", "still")])

    def test_alias_and_manifest_do_not_split_the_package(self):
        previous = {"packages": [_one(
            "rustcrypto-ff", "0.13.0", "GHSA-stay",
            ecosystem="crates.io", alias="ff", dev=True, manifest="Cargo.lock", recommend="0.13.1",
        )]}
        current = {"packages": [_one(
            "rustcrypto-ff", "0.13.0", "GHSA-stay",
            ecosystem="crates.io", alias=None, dev=False, manifest="app/Cargo.lock", recommend="0.13.1",
        )]}
        result = compare_reports(current, previous)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["change"], "unchanged")
        self.assertEqual(result["rows"][0]["note"], "Now prod")

    def test_an_advisory_that_remains_on_another_version_is_not_cleared(self):
        previous = {"packages": [
            _one("lodash", "4.17.20", "GHSA-old", manifest="app/package-lock.json"),
            _one("lodash", "4.17.21", "GHSA-old", manifest="packages/ui/package-lock.json"),
        ]}
        current = {"packages": [
            _one("lodash", "4.17.21", "GHSA-old", manifest="packages/ui/package-lock.json"),
        ]}
        result = compare_reports(current, previous)
        row = result["rows"][0]
        self.assertEqual(row["change"], "version_changed")
        self.assertEqual(_marked(row), [("GHSA-old", "still")])

    def test_unchecked_row_pairs_with_the_resolved_row(self):
        previous = {"packages": [_one(
            "lodash", None, None, manifest="package.json",
            unchecked_reason="version is a range, no lockfile",
        )]}
        current = {"packages": [_one("lodash", "4.17.21", "GHSA-new", recommend="9.0.0")]}
        result = compare_reports(current, previous)
        row = result["rows"][0]
        self.assertEqual(row["change"], "version_changed")
        self.assertEqual(row["current"][0]["version"], "4.17.21")
        self.assertEqual(_marked(row), [("GHSA-new", "appeared")])

    def test_several_versions_stay_one_package(self):
        previous = {"packages": [
            _one("lodash", "1.0.0", "GHSA-a"),
            _one("lodash", "2.0.0", "GHSA-b"),
        ]}
        current = {"packages": [
            _one("lodash", "3.0.0", "GHSA-a"),
            _one("lodash", "4.0.0", "GHSA-c"),
        ]}
        result = compare_reports(current, previous)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["change"], "version_changed")
        self.assertEqual(_marked(result["rows"][0]), [
            ("GHSA-a", "still"),
            ("GHSA-b", "cleared"),
            ("GHSA-c", "appeared"),
        ])

    def test_added_and_removed_are_separate_rows(self):
        current = {"packages": [_one("left-pad", "1.0.0", None)]}
        previous = {"packages": [_one("lodash", "4.17.20", "GHSA-old")]}
        result = compare_reports(current, previous)
        kinds = {row["name"]: row["change"] for row in result["rows"]}
        self.assertEqual(kinds, {"left-pad": "added", "lodash": "removed"})
        self.assertEqual(result["rows"][0]["name"], "lodash")
        self.assertEqual(result["rows"][0]["current"], [])

    def test_a_clean_package_that_did_not_move_is_omitted(self):
        package = _one("left-pad", "1.0.0", None)
        result = compare_reports({"packages": [package]}, {"packages": [package]})
        self.assertEqual(result["rows"], [])

    def test_findings_are_ordered_and_inputs_stay_put(self):
        current = {"packages": [_one("express", "5.0.0", None, vulns=[
            _finding("GHSA-low", severity="low"),
            _finding("MAL-1", severity="high", kind="malware"),
        ]), _one("aaa", None, "GHSA-blank")]}
        previous = {"packages": []}
        original = json.loads(json.dumps(current))
        result = compare_reports(current, previous)
        self.assertEqual(current, original)
        self.assertEqual([row["name"] for row in result["rows"]], ["express", "aaa"])
        self.assertEqual([item["id"] for item in result["rows"][0]["advisories"]], ["MAL-1", "GHSA-low"])
        self.assertIsNone(result["rows"][1]["current"][0]["version"])

    def test_a_non_dict_report_is_rejected(self):
        with self.assertRaises(TypeError):
            compare_reports(None, {})

    def test_saved_scans_compare(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = {"target": "sample", "commit": "bbbb", "packages": [
                _one("lodash", "4.17.21", None, recommend="9.1.0", vulns=[
                    _finding("GHSA-stay"),
                    _finding("GHSA-new"),
                ]),
            ]}
            previous = {"target": "other", "commit": "aaaa", "packages": [
                _one("lodash", "4.17.20", None, recommend="9.0.0", vulns=[
                    _finding("GHSA-stay"),
                    _finding("GHSA-old"),
                ]),
            ]}
            with patch("supply_scan.scans.scans_dir", return_value=root):
                older = save_scan(previous)
                newer = save_scan(current)
                code, body = compare_response({"current": newer["id"], "previous": older["id"]})
                loaded = load_scan(newer["id"])
            self.assertEqual(code, 200)
            self.assertEqual(loaded["packages"][0]["vulns"][0]["id"], "GHSA-stay")
            self.assertEqual(body["rows"][0]["change"], "version_changed")
            self.assertEqual(_marked(body["rows"][0]), [
                ("GHSA-new", "appeared"),
                ("GHSA-old", "cleared"),
                ("GHSA-stay", "still"),
            ])


class GitTokenTests(unittest.TestCase):
    def test_git_auth_config_uses_http_extra_header(self):
        import os

        from supply_scan.acquire import build_clone_command
        from supply_scan.git_pat_auth import git_auth_config_args

        args = git_auth_config_args("ghp_test_token")
        self.assertEqual(len(args), 2)
        self.assertEqual(args[0], "-c")
        self.assertTrue(args[1].startswith("http.extraHeader=Authorization: Basic "))
        self.assertNotIn("ghp_test_token", args[1])
        cmd = build_clone_command(
            "https://github.com/org/repo.git",
            Path("C:/temp/repo"),
            "main",
            "ghp_test_token",
        )
        self.assertEqual(cmd[0], "git")
        self.assertIn("clone", cmd)
        if os.name == "nt":
            clone_url = cmd[-2]
            self.assertIn("x-access-token:", clone_url)
            self.assertIn("@github.com/org/repo.git", clone_url)
            self.assertFalse(any("http.extraHeader=Authorization: Basic" in part for part in cmd))
        else:
            joined = " ".join(cmd)
            self.assertNotIn("ghp_test_token", joined)
            self.assertTrue(any("http.extraHeader=Authorization: Basic" in part for part in cmd))
            self.assertIn("https://github.com/org/repo.git", cmd)

    def test_pat_clone_url_on_windows(self):
        import os

        if os.name != "nt":
            self.skipTest("Windows PAT URL embedding")

        from supply_scan.acquire import build_clone_command

        cmd = build_clone_command(
            "https://github.com/org/repo.git",
            Path("C:/temp/repo"),
            "main",
            "ghp_not_a_real_token",
        )
        clone_url = cmd[-2]
        self.assertIn("x-access-token:", clone_url)


class AcquireErrorTextTests(unittest.TestCase):
    def test_https_credential_prompt_becomes_a_short_sentence(self):
        detail = (
            "Cloning into 'C:\\\\Temp\\\\repo'...\n"
            "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
        )
        from supply_scan.acquire import short_acquire_error

        self.assertEqual(
            short_acquire_error(detail),
            "Private repository or HTTPS credentials required.",
        )


class BranchListErrorTests(unittest.TestCase):
    def test_long_git_stderr_becomes_a_short_sentence(self):
        detail = (
            "remote: Repository not found.\n"
            "fatal: repository 'https://github.com/example/missing/' not found"
        )
        self.assertEqual(_branch_list_error(detail), "Repository not found.")


class BatchServeTests(unittest.TestCase):
    def test_batch_scan_response_returns_aggregate_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            one = base / "one"
            two = base / "two"
            for tree, name in ((one, "left-pad"), (two, "lodash")):
                tree.mkdir()
                Path(tree, "package.json").write_text(
                    json.dumps({"dependencies": {name: "1.0.0"}}),
                    encoding="utf-8",
                )

            def fake_batch(chunk):
                return [{"vulns": []} for _ in chunk]

            with patch("supply_scan.match._post_batch", side_effect=fake_batch):
                code, body = batch_scan_response({
                    "targets": [{"target": str(one)}, {"target": str(two)}],
                    "strict": False,
                })
            self.assertEqual(code, 200)
            self.assertEqual(body["exit_code"], 0)
            self.assertEqual(len(body["reports"]), 2)
            self.assertEqual(body["reports"][0]["exit_code"], 0)


class BatchScanTests(unittest.TestCase):
    def _npm_tree(self, root: Path, name: str, version: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        root.joinpath("package.json").write_text(
            json.dumps({"dependencies": {name: version}}),
            encoding="utf-8",
        )

    def test_shared_osv_version_is_fetched_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            one = base / "one"
            two = base / "two"
            three = base / "three"
            self._npm_tree(one, "lodash", "4.17.21")
            self._npm_tree(two, "lodash", "4.17.21")
            self._npm_tree(three, "express", "4.18.2")
            seen: list[tuple[str, str, str]] = []

            def fake_batch(chunk):
                for package in chunk:
                    seen.append((package.ecosystem, package.name, package.version or ""))
                return [{"vulns": []} for _ in chunk]

            with patch("supply_scan.match._post_batch", side_effect=fake_batch):
                status, reports, _snapshots = run_batch(
                    [TargetSpec(str(one)), TargetSpec(str(two)), TargetSpec(str(three))],
                    use_cache=False,
                )
            self.assertEqual(status, 0)
            self.assertEqual(len(reports), 3)
            self.assertEqual(seen.count(("npm", "lodash", "4.17.21")), 1)
            self.assertIn(("npm", "express", "4.18.2"), seen)

    def test_failed_target_still_finishes_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            good_a = base / "good-a"
            missing = base / "missing"
            good_b = base / "good-b"
            self._npm_tree(good_a, "left-pad", "1.0.0")
            self._npm_tree(good_b, "left-pad", "1.0.1")

            def fake_batch(chunk):
                return [{"vulns": []} for _ in chunk]

            with patch("supply_scan.match._post_batch", side_effect=fake_batch):
                status, reports, _snapshots = run_batch(
                    [TargetSpec(str(good_a)), TargetSpec(str(missing)), TargetSpec(str(good_b))],
                    use_cache=False,
                )
            self.assertEqual(status, 2)
            self.assertEqual(reports[0]["exit_code"], 0)
            self.assertEqual(reports[1]["exit_code"], 2)
            self.assertEqual(reports[2]["exit_code"], 0)
            self.assertIn("error", reports[1])
            self.assertGreater(len(reports[0]["packages"]), 0)
            self.assertGreater(len(reports[2]["packages"]), 0)

    def test_concurrent_save_scan_keeps_both_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            barrier = threading.Barrier(2)

            def save_one(label: str) -> dict:
                barrier.wait(timeout=5)
                with patch("supply_scan.scans.scans_dir", return_value=root):
                    return save_scan({"target": label, "packages": []})

            results: list[dict] = []

            def worker(label: str) -> None:
                results.append(save_one(label))

            threads = [threading.Thread(target=worker, args=(f"repo-{index}",)) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            with patch("supply_scan.scans.scans_dir", return_value=root):
                index = list_scans(root)
            self.assertEqual(len(results), 2)
            self.assertEqual(len(index), 2)
            self.assertEqual(len({row["id"] for row in index}), 2)


class LocateFolderTests(unittest.TestCase):
    def test_finds_the_folder_whose_lockfiles_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "a" / "app"
            other = root / "b" / "app"
            for folder, text in ((good, "12345"), (other, "123")):
                folder.mkdir(parents=True)
                (folder / "package-lock.json").write_text(text)
            found = find_folder("APP", [("package-lock.json", 5)], roots=[root])
        self.assertEqual(found, [good])

    def test_skips_dependency_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules" / "app").mkdir(parents=True)
            self.assertEqual(find_folder("app", [], roots=[root]), [])

    def test_response_validates_name_and_passes_sizes(self):
        seen = {}

        def finder(name, manifests):
            seen["args"] = (name, manifests)
            return [Path("C:/x/app")]

        status, body = locate_response(
            {"name": "app", "files": [{"path": "go.mod", "size": 7}, {"path": "../x/go.mod", "size": 1}]},
            finder,
        )
        self.assertEqual(status, 200)
        self.assertEqual(seen["args"], ("app", [("go.mod", 7)]))
        self.assertEqual(len(body["paths"]), 1)
        self.assertEqual(locate_response({"name": "a/b", "files": []}, finder)[0], 400)


def _finding(osv_id, severity="high", kind="vulnerability"):
    return {
        "id": osv_id,
        "cve": None,
        "severity": severity,
        "summary": "sample",
        "fixed_in": "9.0.0",
        "kind": kind,
    }


if __name__ == "__main__":
    unittest.main()
