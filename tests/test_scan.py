import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from supply_scan.acquire import AcquireError, delete_tree, open_workspace, sanitize_git_url
from supply_scan.inventory import Package, dedupe, scan_tree
from supply_scan.cache import DiskCache
from supply_scan.match import Finding, annotate, cvss_v3_score, hydrate, range_contains, version_tuple
from supply_scan.report import exit_code


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

GO_MOD = """
module example.com/app

go 1.22

require (
    github.com/foo/bar v1.2.3
    github.com/foo/baz v0.1.0 // indirect
)

require github.com/solo/mod v1.0.0
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
name = "leftpad"
version = "0.1.0"
source = "git+https://github.com/example/leftpad#abcdef"
"""

CARGO_TOML = """
[dependencies]
serde = "1"
"""


def _advisory(fixed="4.17.21", osv_id="GHSA-1", cve="CVE-2021-1", severity=CRITICAL, events=None):
    if events is None:
        events = [{"introduced": "0"}, {"fixed": fixed}]
    vuln = {
        "id": osv_id,
        "summary": "example",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
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
        self.assertTrue(found["vitest"].dev)
        self.assertEqual(found["@scope/pkg"].version, "1.2.3")
        self.assertFalse(found["@scope/pkg"].direct)

    def test_go_mod_keeps_exact_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "go.mod").write_text(GO_MOD, encoding="utf-8")
            found = {pkg.name: pkg for pkg in scan_tree(Path(tmp))}
        self.assertEqual(found["github.com/foo/bar"].version, "v1.2.3")
        self.assertTrue(found["github.com/foo/bar"].direct)
        self.assertFalse(found["github.com/foo/baz"].direct)
        self.assertTrue(found["github.com/solo/mod"].direct)

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
        self.assertTrue(found["serde"].direct)
        self.assertEqual(found["serde"].ecosystem, "crates.io")
        self.assertIn("git dependency", found["leftpad"].unchecked_reason)

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
        self.assertIsNone(version_tuple("1.0.0-rc.1"))

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


class AcquireTests(unittest.TestCase):
    def test_url_allowlist(self):
        self.assertEqual(
            sanitize_git_url("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git",
        )
        with self.assertRaises(AcquireError):
            sanitize_git_url("https://github.com/org/repo.git && calc.exe")

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


if __name__ == "__main__":
    unittest.main()
