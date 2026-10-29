"""Read lockfiles into resolved package records.

A range in package.json, pyproject.toml, or a Gemfile is not an installed
version. Those rows are kept and marked unchecked so a run with no lockfile
cannot look clean.
A pnpm lockfile that is not the v6 or v9 shape this line parser knows is one
unchecked row, not a short package list. A yarn.lock that is neither classic
v1 nor the Berry shape is one unchecked row. A gradle.lockfile line this
parser does not know is one unchecked row, not a short package list. Nothing
here installs packages, and nothing here runs Gradle or Maven.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".venv",
    "venv",
    "target",
    "vendor",
    "site-packages",
}

_PNPM_KEY = re.compile(
    r"""^  (?! )['"]?/?(?P<name>(?:@[^/'"@]+/)?[^@'"\s]+)@(?P<version>[^('":\s']+)"""
)
_PNPM_LOCK_VERSION = re.compile(r"^lockfileVersion:\s*['\"]?(?P<major>\d+)\b")
_PNPM_KNOWN_MAJORS = {6, 9}
_REQ_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([^\\\s;#]+)\s*$"
)
_PUB_EXACT = re.compile(r"\d+\.\d+\.\d+")


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str | None
    direct: bool
    dev: bool
    manifest: str
    unchecked_reason: str | None = None
    vulns: list = field(default_factory=list)
    recommend: str | None = None
    alias: str | None = None


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _unchecked(
    ecosystem: str,
    name: str,
    version: str | None,
    dev: bool,
    manifest: str,
    reason: str,
    *,
    direct: bool = True,
    alias: str | None = None,
) -> Package:
    return Package(
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=direct,
        dev=dev,
        manifest=manifest,
        unchecked_reason=reason,
        alias=alias,
    )


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _rel(directory: Path, name: str) -> str:
    if directory == Path("."):
        return name
    return f"{directory.as_posix()}/{name}"


def parse_package_lock(text: str, manifest: str) -> list[Package]:
    data = json.loads(text)
    packages = data.get("packages")
    if isinstance(packages, dict):
        return _npm_lock_v2(packages, manifest)
    return _npm_lock_v1(data, manifest)


_NPM_PROD_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")


def _npm_project_entry(key: str) -> bool:
    return all(part != "node_modules" for part in key.split("/"))


def _npm_dep_names(meta: dict, fields: tuple[str, ...]) -> list[str]:
    names: list[str] = []
    for field in fields:
        entries = meta.get(field)
        if not isinstance(entries, dict):
            continue
        for name in entries:
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _npm_unwrap(packages: dict, key: str) -> str:
    seen: set[str] = set()
    current = key
    while current not in seen:
        seen.add(current)
        meta = packages.get(current)
        if not isinstance(meta, dict) or not meta.get("link"):
            return current
        target = meta.get("resolved")
        if not isinstance(target, str):
            return current
        target = target.removeprefix("./")
        if target not in packages:
            return current
        current = target
    return current


def _npm_resolve(packages: dict, from_key: str, dep_name: str) -> str | None:
    """Find the installed entry for dep_name required by the package at from_key.

    Node looks in node_modules under the requiring package, then under each
    parent directory. A scope folder is part of the package path, not a parent.
    """
    parts = from_key.split("/") if from_key else []
    while True:
        prefix = "/".join(parts)
        key = f"{prefix}/node_modules/{dep_name}" if prefix else f"node_modules/{dep_name}"
        if isinstance(packages.get(key), dict):
            return _npm_unwrap(packages, key)
        if not parts:
            return None
        parts.pop()
        if parts and parts[-1].startswith("@"):
            parts.pop()
        if parts and parts[-1] == "node_modules":
            parts.pop()


def _npm_walk(packages: dict, seeds: list[str], blocked: set[str]) -> set[str]:
    reached: set[str] = set()
    seen: set[str] = set()
    stack = list(seeds)
    while stack:
        key = stack.pop()
        if key in seen or key in blocked:
            continue
        seen.add(key)
        meta = packages.get(key)
        if not isinstance(meta, dict):
            continue
        if meta.get("link"):
            target = _npm_unwrap(packages, key)
            if target != key:
                stack.append(target)
            continue
        if not _npm_project_entry(key):
            reached.add(key)
        for dep_name in _npm_dep_names(meta, _NPM_PROD_FIELDS):
            resolved = _npm_resolve(packages, key, dep_name)
            if resolved:
                stack.append(resolved)
    return reached


def _npm_lock_v2(packages: dict, manifest: str) -> list[Package]:
    direct_prod: set[str] = set()
    direct_dev: set[str] = set()
    prod_seeds: list[str] = []
    dev_seeds: list[str] = []
    for key, meta in packages.items():
        if not isinstance(key, str) or not isinstance(meta, dict):
            continue
        if not _npm_project_entry(key):
            continue
        prod_names = _npm_dep_names(meta, _NPM_PROD_FIELDS)
        dev_names = _npm_dep_names(meta, ("devDependencies",))
        direct_prod.update(prod_names)
        direct_dev.update(dev_names)
        for name in prod_names:
            resolved = _npm_resolve(packages, key, name)
            if resolved:
                prod_seeds.append(resolved)
        for name in dev_names:
            resolved = _npm_resolve(packages, key, name)
            if resolved:
                dev_seeds.append(resolved)

    prod_paths = _npm_walk(packages, prod_seeds, set())
    dev_paths = _npm_walk(packages, dev_seeds, prod_paths)

    found: list[Package] = []
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict) or meta.get("link"):
            continue
        name = meta.get("name")
        if not name:
            name = str(key).split("node_modules/")[-1]
        version = meta.get("version")
        if not name or not version:
            continue
        if key in prod_paths:
            dev = False
        elif key in dev_paths:
            dev = True
        elif meta.get("dev") or meta.get("devOptional"):
            dev = True
        elif name in direct_dev and name not in direct_prod:
            dev = True
        else:
            dev = False
        direct = name in direct_prod or name in direct_dev
        found.append(Package("npm", name, str(version), direct, dev, manifest))
    return found


def _npm_lock_v1(data: dict, manifest: str) -> list[Package]:
    found: list[Package] = []

    def walk(deps: dict, top: bool) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                found.append(Package("npm", name, str(version), top, bool(meta.get("dev")), manifest))
            walk(meta.get("dependencies") or {}, False)

    walk(data.get("dependencies") or {}, True)
    return found


def parse_package_json(text: str, manifest: str) -> list[Package]:
    data = json.loads(text)
    found: list[Package] = []
    sections = (
        ("dependencies", False),
        ("optionalDependencies", False),
        ("devDependencies", True),
    )
    for section, dev in sections:
        entries = data.get(section) or {}
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            spec_text = spec if isinstance(spec, str) else None
            if spec_text and re.fullmatch(r"\d+\.\d+\.\d+", spec_text):
                found.append(Package("npm", name, spec_text, True, dev, manifest))
                continue
            found.append(_unchecked(
                "npm", name, spec_text, dev, manifest,
                "version is a range, no lockfile",
            ))
    return found


_YARN_EDGES = {"dependencies", "optionalDependencies", "peerDependencies"}
_YARN_REASONS = {
    "workspace": "workspace source, not an npm release",
    "patch": "patch source, not an npm release",
    "portal": "portal source, not an npm release",
    "file": "file source, not an npm release",
    "link": "file source, not an npm release",
    "git": "git source, not an npm release",
    "github": "git source, not an npm release",
    "http": "git source, not an npm release",
    "exec": "unsupported yarn source",
}
_YARN_RANGE = set("0123456789.^~>=<*v")


def _yarn_unrecognised(manifest: str) -> list[Package]:
    return [_unchecked(
        "npm", manifest, None, False, manifest,
        "yarn lockfile shape was not recognised",
    )]


def _yarn_shape(text: str) -> str | None:
    if "\t" in text:
        return None
    classic = False
    berry = False
    for line in text.splitlines():
        if line.startswith("  version \""):
            classic = True
        elif (
            line.startswith("  version:")
            or line.startswith("  resolution:")
            or line.startswith("__metadata:")
        ):
            berry = True
    if classic and berry:
        return None
    if berry:
        return "berry"
    if classic or "yarn lockfile v1" in text:
        return "classic"
    return None


def _split_descriptor(key: str) -> tuple[str, str]:
    if key.startswith("@"):
        name, sep, rest = key[1:].partition("@")
        if not sep:
            return key, ""
        return "@" + name, rest
    name, sep, rest = key.partition("@")
    if not sep:
        return key, ""
    return name, rest


def _yarn_protocol(rest: str) -> str | None:
    if rest.startswith("git+") or rest.startswith("git:") or rest.startswith("github:"):
        return "git"
    if rest.startswith("http://") or rest.startswith("https://"):
        return "http"
    if ":" not in rest:
        return None
    proto = rest.split(":", 1)[0]
    if proto in _YARN_REASONS or proto == "npm":
        return proto
    return None


def _split_npm_body(body: str) -> tuple[str | None, str]:
    """A `npm:` body is a range, or an alias `name@range`."""
    body = body.strip()
    if not body or body[0] in _YARN_RANGE:
        return None, body
    if body.startswith("@"):
        if "@" not in body[1:]:
            return None, body
        name, rest = _split_descriptor(body)
        return name, rest
    if "@" not in body:
        return None, body
    name, _, rest = body.partition("@")
    return name, rest


def _yarn_keys(header: str) -> list[str]:
    body = header[:-1].strip()
    if not body:
        return []
    quoted = re.findall(r'"((?:\\.|[^"\\])*)"', body)
    if quoted:
        return quoted
    return [part.strip() for part in body.split(",") if part.strip()]


def _yarn_unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    return text


def _yarn_dep(stripped: str, berry: bool) -> tuple[str, str] | None:
    if berry:
        match = re.match(r'^"((?:\\.|[^"\\])*)"\s*:\s*(.*)$', stripped)
        if match:
            return match.group(1), _yarn_unquote(match.group(2))
        name, sep, spec = stripped.partition(":")
        if not sep or not name.strip():
            return None
        return name.strip(), _yarn_unquote(spec)
    match = re.match(
        r'^(?:"((?:\\.|[^"\\])*)"|([A-Za-z0-9_.@/-]+))\s+"([^"]*)"$',
        stripped,
    )
    if not match:
        return None
    return match.group(1) or match.group(2), match.group(3)


def _reason_from_resolved(url: str) -> str | None:
    text = url.strip().lower()
    if text.startswith(("git+", "git:", "git@", "ssh:", "github:")):
        return _YARN_REASONS["git"]
    if text.startswith(("file:", "link:")):
        return _YARN_REASONS["file"]
    for proto in ("workspace", "portal", "patch"):
        if text.startswith(proto + ":"):
            return _YARN_REASONS[proto]
    if "codeload.github.com" in text:
        return _YARN_REASONS["git"]
    if any(host in text for host in ("://github.com/", "://gitlab.com/", "://bitbucket.org/")):
        return _YARN_REASONS["git"]
    return None


def _identity_from_resolution(resolution: str) -> tuple[str, str | None]:
    name, rest = _split_descriptor(resolution)
    proto = _yarn_protocol(rest)
    if proto in (None, "npm"):
        if proto == "npm":
            target, _version = _split_npm_body(rest.split(":", 1)[1])
            if target:
                name = target
        return name, None
    return name, _YARN_REASONS.get(proto, "unsupported yarn source")


def _yarn_candidates(name: str, spec: str) -> list[str]:
    spec = spec.strip()
    candidates = [f"{name}@{spec}"]
    if _yarn_protocol(spec) is None:
        candidates.append(f"{name}@npm:{spec}")
    return candidates


def _yarn_roles(texts: list[str]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    prod: dict[str, list[str]] = {}
    dev: dict[str, list[str]] = {}
    sections = (
        ("dependencies", prod),
        ("optionalDependencies", prod),
        ("peerDependencies", prod),
        ("devDependencies", dev),
    )
    for text in texts:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        for field, bucket in sections:
            entries = data.get(field) or {}
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if not isinstance(name, str) or not name:
                    continue
                bucket.setdefault(name, [])
                if isinstance(spec, str) and spec:
                    bucket[name].append(spec)
    for name in prod:
        dev.pop(name, None)
    return prod, dev


def _yarn_lookup(index: dict[str, dict], name: str, spec: str) -> dict | None:
    for candidate in _yarn_candidates(name, spec):
        found = index.get(candidate)
        if found is not None:
            return found
    return None


def _yarn_walk(seeds: list[dict], index: dict[str, dict], blocked: set[int]) -> set[int]:
    reached: set[int] = set()
    seen: set[int] = set()
    stack = list(seeds)
    while stack:
        entry = stack.pop()
        ident = id(entry)
        if ident in seen or ident in blocked:
            continue
        seen.add(ident)
        reached.add(ident)
        for dep_name, dep_spec in entry["deps"]:
            nxt = _yarn_lookup(index, dep_name, dep_spec)
            if nxt is not None:
                stack.append(nxt)
    return reached


def _parse_yarn_entries(text: str, berry: bool) -> list[dict]:
    current: dict | None = None
    entries: list[dict] = []
    in_deps = False
    in_metadata = False

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        entries.append(current)
        current = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] != " ":
            finish()
            in_deps = False
            header = raw.strip()
            if header == "__metadata:" or header.startswith("__metadata:"):
                in_metadata = True
                continue
            in_metadata = False
            if not header.endswith(":"):
                raise ValueError("yarn.lock was not understood")
            current = {
                "keys": _yarn_keys(header),
                "deps": [],
                "version": None,
                "resolved": None,
                "resolution": None,
            }
            continue
        if in_metadata or current is None:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent <= 2:
            field = stripped.split(":", 1)[0].strip().strip('"')
            if field in _YARN_EDGES and stripped.endswith(":"):
                in_deps = True
                continue
            in_deps = False
            if stripped.startswith("version "):
                match = re.match(r'^version\s+"([^"]*)"', stripped)
                if match:
                    current["version"] = match.group(1)
                continue
            if stripped.startswith("version:"):
                current["version"] = _yarn_unquote(stripped.split(":", 1)[1]).split()[0]
                continue
            if stripped.startswith("resolved "):
                match = re.match(r'^resolved\s+"([^"]*)"', stripped)
                if match:
                    current["resolved"] = match.group(1)
                continue
            if stripped.startswith("resolution:"):
                current["resolution"] = _yarn_unquote(stripped.split(":", 1)[1])
            continue
        if not in_deps:
            continue
        dep = _yarn_dep(stripped, berry)
        if dep is None:
            raise ValueError("yarn.lock was not understood")
        current["deps"].append(dep)
    finish()
    return entries


def _yarn_describe(entry: dict) -> None:
    requested: list[str] = []
    targets: list[str] = []
    key_reason = None
    for key in entry["keys"]:
        requested_name, rest = _split_descriptor(key)
        if not requested_name:
            continue
        requested.append(requested_name)
        proto = _yarn_protocol(rest)
        if proto in (None, "npm"):
            body = rest.split(":", 1)[1] if proto == "npm" else rest
            target, _range = _split_npm_body(body)
            targets.append(target or requested_name)
        else:
            if key_reason is None:
                key_reason = _YARN_REASONS.get(proto, "unsupported yarn source")
            targets.append(requested_name)
    entry["requested"] = requested
    if entry.get("resolution"):
        name, reason = _identity_from_resolution(entry["resolution"])
        entry["name"] = name or (targets[0] if targets else "")
        entry["reason"] = reason
    else:
        entry["name"] = targets[0] if targets else ""
        if entry.get("resolved"):
            entry["reason"] = _reason_from_resolved(entry["resolved"])
        else:
            entry["reason"] = key_reason
    aliases = [name for name in dict.fromkeys(requested) if name and name != entry["name"]]
    entry["alias"] = ", ".join(aliases) if aliases else None


def parse_yarn_lock(text: str, package_jsons: list[str], manifest: str) -> list[Package]:
    shape = _yarn_shape(text)
    if shape is None:
        return _yarn_unrecognised(manifest)
    entries = _parse_yarn_entries(text, shape == "berry")
    described: list[dict] = []
    index: dict[str, dict] = {}
    for entry in entries:
        _yarn_describe(entry)
        if not entry["name"]:
            continue
        if not entry["version"] and not entry["reason"]:
            continue
        described.append(entry)
        for key in entry["keys"]:
            index.setdefault(key, entry)

    prod, dev = _yarn_roles(package_jsons)
    prod_names = set(prod)
    dev_names = set(dev)

    def seeds(specs: dict[str, list[str]]) -> list[dict]:
        found: list[dict] = []
        for name, ranges in specs.items():
            for spec in ranges:
                entry = _yarn_lookup(index, name, spec)
                if entry is not None and entry not in found:
                    found.append(entry)
        return found

    prod_ids = _yarn_walk(seeds(prod), index, set())
    dev_ids = _yarn_walk(seeds(dev), index, prod_ids)
    found: list[Package] = []
    for entry in described:
        requested = set(entry["requested"])
        direct = bool(requested & prod_names or requested & dev_names)
        ident = id(entry)
        if ident in prod_ids:
            is_dev = False
        elif ident in dev_ids:
            is_dev = True
        elif requested & dev_names and not (requested & prod_names):
            is_dev = True
        else:
            is_dev = False
        if entry["reason"]:
            found.append(_unchecked(
                "npm", entry["name"], entry["version"], is_dev, manifest, entry["reason"],
                direct=direct, alias=entry["alias"],
            ))
            continue
        found.append(Package(
            "npm", entry["name"], entry["version"], direct, is_dev, manifest, alias=entry["alias"],
        ))
    return found


def _composer_names(section) -> set[str]:
    if not isinstance(section, dict):
        return set()
    return {str(name).strip().lower() for name in section if str(name).strip()}


def _composer_direct(text: str | None) -> tuple[set[str], set[str]]:
    if not text:
        return set(), set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return set(), set()
    if not isinstance(data, dict):
        return set(), set()
    prod = _composer_names(data.get("require"))
    dev = _composer_names(data.get("require-dev")) - prod
    return prod, dev


def _composer_version(value) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:
            return None
        return str(int(value)) if value.is_integer() else str(value)
    return None


def _composer_reason(version: str, package: dict) -> str | None:
    if version.startswith("dev-"):
        return "dev version, not a Packagist release"
    if version.endswith("-dev"):
        return "branch, not a Packagist release"
    source = package.get("source") if isinstance(package.get("source"), dict) else {}
    dist = package.get("dist") if isinstance(package.get("dist"), dict) else {}
    source_type = str(source.get("type") or "").lower()
    dist_type = str(dist.get("type") or "").lower()
    # Packagist releases record a git checkout and a zip dist. A git source
    # with no zip or tar is not a release this scan can query.
    if source_type == "git" and dist_type not in {"zip", "tar"}:
        return "git source, not a Packagist release"
    return None


def parse_composer_lock(text: str, composer_json: str | None, manifest: str) -> list[Package]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("composer.lock was not an object")
    prod_direct, dev_direct = _composer_direct(composer_json)
    found: list[Package] = []
    for section, dev_section in (("packages", False), ("packages-dev", True)):
        entries = data.get(section) or []
        if not isinstance(entries, list):
            continue
        for package in entries:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = _composer_version(package.get("version"))
            if not isinstance(name, str) or not name.strip() or not version:
                continue
            name = name.strip()
            key = name.lower()
            if key in prod_direct:
                direct, is_dev = True, False
            elif key in dev_direct:
                direct, is_dev = True, True
            else:
                direct, is_dev = False, dev_section
            reason = _composer_reason(version, package)
            if reason:
                found.append(_unchecked(
                    "Packagist", name, version, is_dev, manifest, reason, direct=direct,
                ))
                continue
            found.append(Package("Packagist", name, version, direct, is_dev, manifest))
    return found


def _pub_scalar(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _pub_field(stripped: str) -> tuple[str, str | None]:
    key, _, rest = stripped.partition(":")
    name = key.strip().strip("'\"")
    rest = rest.strip()
    return name, _pub_scalar(rest) if rest else None


def _pub_dependency(value: str) -> tuple[bool, bool]:
    parts = value.split()
    return value.startswith("direct"), "dev" in parts


def parse_pubspec_lock(text: str, manifest: str) -> list[Package]:
    section = None
    current: dict | None = None
    blocks: list[dict] = []

    def finish() -> None:
        nonlocal current
        if current and current.get("name"):
            blocks.append(current)
        current = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if indent == 0 and stripped.endswith(":"):
            finish()
            section = stripped[:-1].strip("'\"")
            continue
        if section != "packages":
            continue
        if indent == 2 and stripped.endswith(":"):
            finish()
            name, _value = _pub_field(stripped)
            current = {"name": name, "dependency": "", "source": "", "version": None}
            continue
        if current and indent == 4:
            key, value = _pub_field(stripped)
            if key in ("dependency", "source", "version") and value is not None:
                current[key] = value
    finish()

    found: list[Package] = []
    for block in blocks:
        name = str(block["name"])
        dependency = str(block["dependency"])
        source = str(block["source"])
        version = block["version"] if isinstance(block["version"], str) else None
        direct, dev = _pub_dependency(dependency)
        if source == "hosted" and version:
            found.append(Package("Pub", name, version, direct, dev, manifest))
            continue
        if source == "git":
            reason = "git source, not a Pub release"
        elif source == "path":
            reason = "path source, not a Pub release"
        elif source == "sdk":
            reason = "sdk source, not a Pub release"
        else:
            reason = "unsupported pub source"
        found.append(_unchecked("Pub", name, version, dev, manifest, reason, direct=direct))
    return found


def parse_pubspec_yaml(text: str, manifest: str) -> list[Package]:
    mode: str | None = None
    current: dict | None = None
    found: list[Package] = []

    def finish() -> None:
        nonlocal current
        if not current or not current.get("name"):
            current = None
            return
        name = str(current["name"])
        dev = bool(current["dev"])
        nested = current["nested"]
        version = current["inline"] if isinstance(current["inline"], str) else nested.get("version")
        current = None
        if "sdk" in nested:
            reason = "sdk source, not a Pub release"
        elif "git" in nested:
            reason = "git source, not a Pub release"
        elif "path" in nested:
            reason = "path source, not a Pub release"
        elif isinstance(version, str) and _PUB_EXACT.fullmatch(version):
            found.append(Package("Pub", name, version, True, dev, manifest))
            return
        else:
            reason = "version is a range, no lockfile"
        found.append(_unchecked(
            "Pub", name, version if isinstance(version, str) else None, dev, manifest, reason,
        ))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key, value = _pub_field(raw.strip())
        if indent == 0 and key in ("dependencies", "dev_dependencies") and value is None:
            finish()
            mode = "dev" if key == "dev_dependencies" else "prod"
            continue
        if indent == 0:
            finish()
            mode = None
            continue
        if mode is None:
            continue
        if current and indent <= int(current["indent"]):
            finish()
        if current and indent > int(current["indent"]):
            current["nested"][key] = value if value is not None else ""
            continue
        if indent == 2:
            finish()
            current = {"name": key, "dev": mode == "dev", "inline": value, "nested": {}, "indent": indent}
            if value is not None:
                finish()
    finish()
    return found


def _pnpm_unrecognised(manifest: str) -> list[Package]:
    return [_unchecked(
        "npm", manifest, None, False, manifest,
        "pnpm lockfile shape was not recognised",
    )]


def parse_pnpm_lock(text: str, manifest: str) -> list[Package]:
    section = None
    mode: str | None = None
    mode_indent = 0
    prod: set[str] = set()
    dev: set[str] = set()
    current: dict | None = None
    blocks: list[dict] = []
    version_major: int | None = None
    unrecognised = False

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("\t"):
            unrecognised = True
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and stripped.startswith("lockfileVersion:"):
            version = _PNPM_LOCK_VERSION.match(stripped)
            if not version:
                unrecognised = True
                continue
            major = int(version.group("major"))
            if version_major is None:
                version_major = major
            elif version_major != major:
                unrecognised = True
            continue
        if indent == 0 and stripped.startswith("packages:") and stripped != "packages:":
            unrecognised = True
            if current:
                blocks.append(current)
                current = None
            section = "packages"
            mode = None
            continue
        if indent == 0 and stripped.endswith(":"):
            if current:
                blocks.append(current)
                current = None
            section = stripped[:-1]
            if section in ("dependencies", "devDependencies"):
                mode = "dev" if section.startswith("dev") else "prod"
                mode_indent = 0
            else:
                mode = None
            continue
        if section == "packages":
            if indent == 2:
                match = _PNPM_KEY.match(line)
                if not match:
                    unrecognised = True
                    if current:
                        blocks.append(current)
                        current = None
                    continue
                if current:
                    blocks.append(current)
                current = {
                    "name": match.group("name"),
                    "version": match.group("version"),
                    "dev": False,
                }
                continue
            if current and stripped == "dev: true":
                current["dev"] = True
            continue
        if stripped in ("dependencies:", "devDependencies:") and section == "importers":
            mode = "dev" if stripped.startswith("dev") else "prod"
            mode_indent = indent
            continue
        if mode is not None and indent == mode_indent + 2 and stripped.endswith(":"):
            name = stripped[:-1].strip("'\"")
            if name and " " not in name:
                (dev if mode == "dev" else prod).add(name)
            continue
        if mode is not None and indent == mode_indent + 2 and ":" in stripped:
            # lockfile v5 writes `name: version` here. v6 and v9 nest the version.
            unrecognised = True
            continue
        if mode is not None and indent <= mode_indent:
            mode = None

    if current:
        blocks.append(current)

    if unrecognised or version_major not in _PNPM_KNOWN_MAJORS:
        return _pnpm_unrecognised(manifest)

    found: list[Package] = []
    for block in blocks:
        name = block["name"]
        if name in prod:
            direct, is_dev = True, False
        elif name in dev:
            direct, is_dev = True, True
        else:
            direct, is_dev = False, bool(block["dev"])
        found.append(Package("npm", name, block["version"], direct, is_dev, manifest))
    return found


_GO_VERSION = re.compile(r"^v\d")


def _go_strip_comment(raw: str) -> str:
    out: list[str] = []
    quote = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            out.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(raw) and raw[index + 1] == "/":
            break
        out.append(char)
        index += 1
    return "".join(out)


def _go_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote = None
    for char in text:
        if quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char in "\"'":
            quote = char
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def _go_replace(text: str) -> tuple[str, str | None, str, str | None] | None:
    if "=>" not in text:
        return None
    left_text, right_text = text.split("=>", 1)
    left = _go_tokens(left_text)
    right = _go_tokens(right_text)
    if len(left) == 1:
        left_path, left_version = left[0], None
    elif len(left) == 2:
        left_path, left_version = left[0], left[1]
    else:
        return None
    if len(right) == 1:
        return left_path, left_version, right[0], None
    if len(right) == 2 and _GO_VERSION.match(right[1]):
        return left_path, left_version, right[0], right[1]
    return None


def parse_go_mod(text: str, manifest: str) -> list[Package]:
    requires: list[tuple[str, str, bool]] = []
    replaces: list[tuple[str, str | None, str, str | None]] = []
    in_require = False
    in_replace = False
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = _go_strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith("require (") or line == "require (":
            in_require = True
            continue
        if line.startswith("replace (") or line == "replace (":
            in_replace = True
            continue
        if line == ")":
            in_require = False
            in_replace = False
            continue
        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                requires.append((parts[0], parts[1], indirect))
            continue
        if in_replace:
            parsed = _go_replace(line)
            if parsed:
                replaces.append(parsed)
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                requires.append((parts[1], parts[2], indirect))
            continue
        if line.startswith("replace "):
            parsed = _go_replace(line[len("replace "):])
            if parsed:
                replaces.append(parsed)

    specific: dict[tuple[str, str], tuple[str, str | None]] = {}
    general: dict[str, tuple[str, str | None]] = {}
    for left_path, left_version, right_path, right_version in replaces:
        if left_version:
            specific[(left_path, left_version)] = (right_path, right_version)
        else:
            general[left_path] = (right_path, right_version)

    found: list[Package] = []
    for path, version, indirect in requires:
        replacement = specific.get((path, version))
        if replacement is None:
            replacement = general.get(path)
        direct = not indirect
        if replacement is None:
            found.append(Package("Go", path, version, direct, False, manifest))
            continue
        right_path, right_version = replacement
        if right_version is None:
            found.append(_unchecked(
                "Go", path, version, False, manifest,
                f"replaced by local path {right_path}",
                direct=direct,
            ))
            continue
        if right_path != path:
            found.append(_unchecked(
                "Go", path, version, False, manifest,
                f"replaced by {right_path}",
                direct=direct,
            ))
            continue
        found.append(Package("Go", path, right_version, direct, False, manifest))
    return found


def _cargo_tables(data: dict):
    yield data.get("dependencies"), False
    yield data.get("dev-dependencies"), True
    yield data.get("build-dependencies"), True
    target = data.get("target")
    if isinstance(target, dict):
        for body in target.values():
            if isinstance(body, dict):
                yield body.get("dependencies"), False


def _cargo_identity(key: str, spec) -> tuple[str, str | None]:
    if isinstance(spec, dict):
        real = spec.get("package")
        if isinstance(real, str) and real.strip():
            real = real.strip()
            return real, key if key != real else None
    return key, None


def _cargo_direct(manifests: list[str]) -> tuple[set[str], set[str], dict[str, str], dict[str, str | None]]:
    prod: set[str] = set()
    dev: set[str] = set()
    aliases: dict[str, set[str]] = {}
    shown: dict[str, str | None] = {}
    for text in manifests:
        data = tomllib.loads(text)
        for table, is_dev in _cargo_tables(data):
            if not isinstance(table, dict):
                continue
            for key, spec in table.items():
                real, nick = _cargo_identity(str(key), spec)
                (dev if is_dev else prod).add(real)
                if nick:
                    aliases.setdefault(real, set()).add(nick)
                if real not in shown:
                    shown[real] = spec if isinstance(spec, str) else None
    dev -= prod
    joined = {name: ", ".join(sorted(nicks)) for name, nicks in aliases.items()}
    return prod, dev, joined, shown


def parse_cargo_lock(text: str, cargo_tomls: list[str], manifest: str) -> list[Package]:
    data = tomllib.loads(text)
    if cargo_tomls:
        prod, dev, aliases, _shown = _cargo_direct(cargo_tomls)
    else:
        prod, dev, aliases = set(), set(), {}
    found: list[Package] = []
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        source = str(pkg.get("source") or "")
        if not source:
            continue
        direct = name in prod or name in dev
        is_dev = name in dev
        alias = aliases.get(str(name))
        if source.startswith("registry+"):
            found.append(Package(
                "crates.io", str(name), str(version), direct, is_dev, manifest, alias=alias,
            ))
            continue
        if source.startswith("git+"):
            found.append(_unchecked(
                "crates.io", str(name), str(version), is_dev, manifest,
                "git dependency, not a crates.io release",
                direct=direct,
                alias=alias,
            ))
    return found


def parse_cargo_toml(text: str, manifest: str) -> list[Package]:
    prod, dev, aliases, shown = _cargo_direct([text])
    found: list[Package] = []
    for name in sorted(prod | dev):
        found.append(_unchecked(
            "crates.io", name, shown.get(name), name in dev, manifest,
            "version is a range, no lockfile",
            alias=aliases.get(name),
        ))
    return found


def _dependency_names(items) -> set[str]:
    names: set[str] = set()
    if not isinstance(items, list):
        return names
    for item in items:
        if isinstance(item, dict) and item.get("name"):
            names.add(pypi_name(str(item["name"])))
        elif isinstance(item, str):
            names.add(pypi_name(item.split("[", 1)[0].split("=", 1)[0].split("<", 1)[0].split(">", 1)[0].split("!", 1)[0].split("~", 1)[0].split(";", 1)[0].strip()))
    return {name for name in names if name}


def parse_uv_lock(text: str, manifest: str) -> list[Package]:
    data = tomllib.loads(text)
    direct: set[str] = set()
    dev: set[str] = set()
    found: list[Package] = []
    for pkg in data.get("package") or []:
        source = pkg.get("source") or {}
        if not isinstance(source, dict):
            source = {}
        local = any(key in source for key in ("virtual", "editable", "path", "directory"))
        if local:
            direct.update(_dependency_names(pkg.get("dependencies")))
            meta = pkg.get("metadata") or {}
            requires_dev = meta.get("requires-dev") or {}
            if isinstance(requires_dev, dict):
                for group in requires_dev.values():
                    dev.update(_dependency_names(group))
            dev_deps = pkg.get("dev-dependencies") or {}
            if isinstance(dev_deps, dict):
                for group in dev_deps.values():
                    dev.update(_dependency_names(group))
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        norm = pypi_name(str(name))
        if "git" in source:
            found.append(_unchecked(
                "PyPI", norm, str(version), False, manifest,
                "git dependency, not a PyPI release", direct=False,
            ))
            continue
        if "registry" not in source and source:
            found.append(_unchecked("PyPI", norm, str(version), False, manifest, "unsupported package source"))
            continue
        found.append(Package("PyPI", norm, str(version), False, False, manifest))

    for pkg in found:
        if pkg.unchecked_reason:
            continue
        if pkg.name in direct:
            pkg.direct = True
            pkg.dev = False
        elif pkg.name in dev:
            pkg.direct = True
            pkg.dev = True
    return found


def parse_poetry_lock(text: str, pyproject_text: str | None, manifest: str) -> list[Package]:
    data = tomllib.loads(text)
    prod, dev = _pyproject_python_names(pyproject_text) if pyproject_text else (set(), set())
    found: list[Package] = []
    for pkg in data.get("package") or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        norm = pypi_name(str(name))
        groups = [str(g).lower() for g in (pkg.get("groups") or [])]
        category = str(pkg.get("category") or "").lower()
        is_dev = category == "dev" or any(g in {"dev", "test", "tests"} for g in groups)
        if norm in prod:
            direct, is_dev = True, False
        elif norm in dev:
            direct, is_dev = True, True
        else:
            direct = False
        found.append(Package("PyPI", norm, str(version), direct, is_dev, manifest))
    return found


def _pyproject_python_names(text: str | None) -> tuple[set[str], set[str]]:
    if not text:
        return set(), set()
    data = tomllib.loads(text)
    prod = _dependency_names((data.get("project") or {}).get("dependencies"))
    dev: set[str] = set()
    optional = (data.get("project") or {}).get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for group, items in optional.items():
            if str(group).lower() in {"dev", "test", "tests"}:
                dev.update(_dependency_names(items))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies") or {}
        if isinstance(deps, dict):
            prod.update(pypi_name(name) for name in deps if name.lower() != "python")
        old_dev = poetry.get("dev-dependencies") or {}
        if isinstance(old_dev, dict):
            dev.update(pypi_name(name) for name in old_dev)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for group, body in groups.items():
                if str(group).lower() in {"dev", "test", "tests"} and isinstance(body, dict):
                    names = body.get("dependencies") or {}
                    if isinstance(names, dict):
                        dev.update(pypi_name(name) for name in names)
    dev -= prod
    return prod, dev


def parse_pyproject(text: str, manifest: str) -> list[Package]:
    prod, dev = _pyproject_python_names(text)
    found = []
    for name in sorted(prod):
        found.append(_unchecked("PyPI", name, None, False, manifest, "version is a range, no lockfile"))
    for name in sorted(dev):
        found.append(_unchecked("PyPI", name, None, True, manifest, "version is a range, no lockfile"))
    return found


def parse_requirements(text: str, manifest: str, dev: bool = False) -> list[Package]:
    found: list[Package] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        match = _REQ_PIN.match(line)
        if match and "*" not in match.group(2):
            found.append(Package(
                "PyPI", pypi_name(match.group(1)), match.group(2), True, dev, manifest,
            ))
            continue
        name = re.split(r"[<>=~!\[;\s@]", line, maxsplit=1)[0].strip()
        if name:
            found.append(_unchecked(
                "PyPI", pypi_name(name), line, dev, manifest,
                "version is a range, no lockfile",
            ))
    return found


_RUBY_NAME = r"[A-Za-z][A-Za-z0-9_.-]*"
_RUBY_SEGMENT = r"(?:\d+|[A-Za-z][0-9A-Za-z]*)"
_SPEC_LINE = re.compile(rf"^(?P<name>{_RUBY_NAME}) \((?P<version>[^)]+)\)$")
_DEP_LINE = re.compile(rf"^(?P<name>{_RUBY_NAME})(?: \([^)]*\))?$")
_DIRECT_LINE = re.compile(rf"^(?P<name>{_RUBY_NAME})(?: \([^)]*\))?(!)?$")
_GEM_VERSION = re.compile(rf"^(?P<base>{_RUBY_SEGMENT}(?:\.{_RUBY_SEGMENT})*)(?:-.+)?$")
_GEM_CALL = re.compile(rf"""^gem\s*\(?\s*(['"])(?P<name>{_RUBY_NAME})\1(?P<rest>.*)$""")
_GROUP_DO = re.compile(r"^group\b(?P<body>.*)\bdo$")
_INLINE_GROUPS = re.compile(
    r"\bgroups?\s*:\s*(?P<body>\[[^\]]*\]|:[A-Za-z_][A-Za-z0-9_]*|['\"][^'\"]+['\"])"
)
_EXACT_REQ = re.compile(rf"^=?\s*({_RUBY_SEGMENT}(?:\.{_RUBY_SEGMENT})*)\s*$")
_RUBY_STRING = re.compile(r"""(['"])(?P<value>(?:\\.|(?!\1).)*)\1""")
_SOURCE_OPT = re.compile(r"\b(git|github|path|source)\s*:")
_RUBYGEMS_REMOTES = {
    "https://rubygems.org",
    "http://rubygems.org",
    "https://index.rubygems.org",
    "http://index.rubygems.org",
}
_LOCK_SECTIONS = {"GIT": "git", "PATH": "path", "PLUGIN SOURCE": "plugin", "GEM": "gem"}
_LOCK_HEADERS = set(_LOCK_SECTIONS) | {
    "DEPENDENCIES",
    "PLATFORMS",
    "RUBY VERSION",
    "BUNDLED WITH",
    "CHECKSUMS",
}
_RUBY_REASON = {
    "git": "git source, not a RubyGems release",
    "path": "path source, not a RubyGems release",
    "plugin": "plugin source, not a RubyGems release",
    "other": "gem source, not RubyGems",
}
_DEV_GROUPS = {"development", "test"}


def _ruby_code(line: str) -> str:
    out: list[str] = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            out.append(char)
            if char == "\\" and index + 1 < len(line):
                out.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "#":
            break
        out.append(char)
        index += 1
    return "".join(out)


def _ruby_words(text: str, word: str) -> int:
    return len(re.findall(rf"\b{word}\b", _RUBY_STRING.sub(" ", text)))


def _ruby_group_names(body: str) -> set[str]:
    names: set[str] = set()
    for match in re.finditer(r"%[iIwW]\[([^\]]*)\]", body):
        names.update(part for part in match.group(1).split() if part)
    plain = re.sub(r"%[iIwW]\[[^\]]*\]", " ", body)
    for match in re.finditer(r":([A-Za-z_][A-Za-z0-9_]*)|['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", plain):
        names.add(next(group for group in match.groups() if group))
    return names


def _gem_requirement(rest: str) -> tuple[str | None, str | None]:
    kind = _SOURCE_OPT.search(rest)
    if kind:
        which = kind.group(1)
        if which in ("git", "github"):
            return "git source, not a RubyGems release", None
        if which == "path":
            return "path source, not a RubyGems release", None
        return "gem source, not RubyGems", None
    exact: list[str] = []
    for match in _RUBY_STRING.finditer(rest):
        hit = _EXACT_REQ.fullmatch(match.group("value").strip())
        if not hit:
            return None, None
        exact.append(hit.group(1))
    if exact and len(set(exact)) == 1:
        return None, exact[0]
    return None, None


def _gemfile_gems(text: str) -> list[dict]:
    depth = 0
    stack: list[tuple[int, set[str]]] = []
    found: list[dict] = []
    for raw in text.splitlines():
        line = _ruby_code(raw).strip()
        if not line:
            continue
        gem = _GEM_CALL.match(line)
        if gem:
            inline = _INLINE_GROUPS.search(gem.group("rest"))
            if inline:
                groups = _ruby_group_names(inline.group("body"))
            else:
                groups = set()
                for _opened, names in stack:
                    groups.update(names)
            reason, version = _gem_requirement(gem.group("rest"))
            found.append({
                "name": gem.group("name"),
                "dev": bool(groups) and groups <= _DEV_GROUPS,
                "reason": reason,
                "version": version,
            })
        group = _GROUP_DO.match(line)
        if group:
            stack.append((depth, _ruby_group_names(group.group("body"))))
        depth += _ruby_words(line, "do") - _ruby_words(line, "end")
        if depth < 0:
            depth = 0
        stack = [item for item in stack if item[0] < depth]
    return found


def _gemfile_roles(text: str | None) -> tuple[set[str], set[str]] | None:
    if text is None:
        return None
    prod: set[str] = set()
    dev: set[str] = set()
    for gem in _gemfile_gems(text):
        if gem["dev"]:
            dev.add(gem["name"])
        else:
            prod.add(gem["name"])
    return prod, dev - prod


def _ruby_base_version(version: str) -> str:
    """Bundler writes a platform after a hyphen. RubyGems advisories use the version."""
    match = _GEM_VERSION.fullmatch(version.strip())
    if not match:
        return version.strip()
    return match.group("base")


def _rubygems_remote(remote: str | None) -> bool:
    if not remote:
        return False
    return remote.strip().rstrip("/").lower() in _RUBYGEMS_REMOTES


def _walk_names(roots: set[str], deps: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = [name for name in roots if name in deps]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(deps.get(name, ()))
    return seen


def parse_gemfile_lock(text: str, gemfile: str | None, manifest: str) -> list[Package]:
    if "\t" in text:
        raise ValueError("Gemfile.lock was not understood")
    section = None
    remote = None
    in_specs = False
    spec_indent = None
    current: dict | None = None
    specs: list[dict] = []
    directs: list[str] = []
    saw_header = False

    def finish() -> None:
        nonlocal current
        if current is not None:
            specs.append(current)
            current = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[0] != " ":
            finish()
            section = raw.strip()
            remote = None
            in_specs = False
            spec_indent = None
            if section in _LOCK_HEADERS:
                saw_header = True
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()
        if section in _LOCK_SECTIONS:
            if stripped.startswith("remote:"):
                finish()
                remote = stripped.split(":", 1)[1].strip()
                in_specs = False
                spec_indent = None
                continue
            if stripped == "specs:":
                finish()
                in_specs = True
                spec_indent = None
                continue
            if not in_specs:
                continue
            if spec_indent is None:
                spec_indent = indent
            if indent < spec_indent:
                raise ValueError("Gemfile.lock was not understood")
            if indent == spec_indent:
                match = _SPEC_LINE.fullmatch(stripped)
                if not match:
                    raise ValueError("Gemfile.lock was not understood")
                finish()
                source = _LOCK_SECTIONS[section]
                if source == "gem":
                    source = "rubygems" if _rubygems_remote(remote) else "other"
                current = {
                    "name": match.group("name"),
                    "version": _ruby_base_version(match.group("version")),
                    "source": source,
                    "deps": set(),
                }
                continue
            if current is None:
                raise ValueError("Gemfile.lock was not understood")
            match = _DEP_LINE.fullmatch(stripped)
            if not match:
                raise ValueError("Gemfile.lock was not understood")
            current["deps"].add(match.group("name"))
            continue
        if section == "DEPENDENCIES":
            match = _DIRECT_LINE.fullmatch(stripped)
            if not match:
                raise ValueError("Gemfile.lock was not understood")
            directs.append(match.group("name"))
    finish()
    if not saw_header:
        raise ValueError("Gemfile.lock was not understood")

    merged: dict[tuple[str, str, str], dict] = {}
    order: list[tuple[str, str, str]] = []
    for spec in specs:
        key = (spec["name"], spec["version"], spec["source"])
        previous = merged.get(key)
        if previous is None:
            merged[key] = spec
            order.append(key)
            continue
        previous["deps"].update(spec["deps"])

    deps: dict[str, set[str]] = {}
    for spec in merged.values():
        deps.setdefault(spec["name"], set()).update(spec["deps"])
    direct_set = set(directs)
    roles = _gemfile_roles(gemfile)
    if roles is None:
        prod_roots = set(direct_set)
        dev_roots: set[str] = set()
    else:
        _prod_names, dev_names = roles
        dev_roots = {name for name in direct_set if name in dev_names}
        prod_roots = direct_set - dev_roots
    prod_reach = _walk_names(prod_roots, deps)
    dev_reach = _walk_names(dev_roots, deps)

    found: list[Package] = []
    for key in order:
        spec = merged[key]
        name = spec["name"]
        direct = name in direct_set
        if name in prod_reach:
            dev = False
        elif name in dev_reach or name in dev_roots:
            dev = True
        else:
            dev = False
        reason = _RUBY_REASON.get(spec["source"])
        if reason:
            found.append(_unchecked(
                "RubyGems", name, spec["version"], dev, manifest, reason, direct=direct,
            ))
            continue
        found.append(Package("RubyGems", name, spec["version"], direct, dev, manifest))
    return found


_CATALOG_TABLES = ("versions", "libraries", "bundles", "plugins")
_DYNAMIC_VERSIONS = {"release", "latest", "latest.release", "latest.integration"}


def _maven_token(value: str) -> bool:
    return bool(value) and ":" not in value and not any(ch.isspace() for ch in value)


def _literal_maven_version(version: str) -> bool:
    if not version or version.lower() in _DYNAMIC_VERSIONS:
        return False
    return not any(ch in version for ch in " \t,[]()+*")


def _library_module(spec) -> str | None:
    if isinstance(spec, str):
        parts = spec.split(":")
        if len(parts) < 2:
            return None
        group, artifact = parts[0], parts[1]
    elif isinstance(spec, dict):
        module = spec.get("module")
        if isinstance(module, str):
            parts = module.split(":")
            if len(parts) != 2:
                return None
            group, artifact = parts
        else:
            group = spec.get("group")
            artifact = spec.get("name")
            if not isinstance(group, str) or not isinstance(artifact, str):
                return None
    else:
        return None
    if not _maven_token(group) or not _maven_token(artifact):
        return None
    return f"{group}:{artifact}"


def _version_node(spec):
    if isinstance(spec, str):
        parts = spec.split(":")
        if len(parts) < 3:
            return None
        return ":".join(parts[2:])
    if isinstance(spec, dict) and "version" in spec:
        return spec.get("version")
    return None


def _resolve_version(spec, versions: dict) -> tuple[str, str | None]:
    """A catalog version is literal, a range, or not written in the file."""
    node = _version_node(spec)
    if isinstance(node, dict):
        ref = node.get("ref")
        if not isinstance(ref, str) or not ref:
            return "range", None
        if ref not in versions:
            return "missing", None
        target = versions[ref]
        if not isinstance(target, str):
            return "range", None
        node = target
    if not isinstance(node, str) or not node:
        return "missing", None
    if _literal_maven_version(node):
        return "literal", node
    return "range", node


def _catalog_modules(text: str | None) -> tuple[set[str], dict[str, str]]:
    if not text:
        return set(), {}
    try:
        data = tomllib.loads(text)
    except Exception:
        return set(), {}
    libraries = data.get("libraries") if isinstance(data, dict) else None
    if not isinstance(libraries, dict):
        return set(), {}
    aliases: dict[str, set[str]] = {}
    for alias, spec in libraries.items():
        module = _library_module(spec)
        if module:
            aliases.setdefault(module, set()).add(str(alias))
    joined = {module: ", ".join(sorted(names)) for module, names in aliases.items()}
    return set(joined), joined


def _catalog_unrecognised(manifest: str) -> list[Package]:
    return [_unchecked(
        "Maven", manifest, None, False, manifest, "version catalog was not recognised",
    )]


def _catalog_library(alias: str, spec, versions: dict, manifest: str) -> Package:
    module = _library_module(spec)
    kind, version = _resolve_version(spec, versions)
    if module is None:
        return _unchecked(
            "Maven", alias, None, False, manifest,
            "version is not written in the repo",
            alias=alias,
        )
    if kind == "literal":
        return Package("Maven", module, version, True, False, manifest, alias=alias)
    reason = "version is a range, no lockfile" if kind == "range" else "version is not written in the repo"
    return _unchecked("Maven", module, version, False, manifest, reason, alias=alias)


def _catalog_plugin(alias: str, spec, versions: dict, manifest: str) -> Package:
    plugin_id = alias
    if isinstance(spec, dict):
        declared = spec.get("id")
        if isinstance(declared, str) and declared and not any(ch.isspace() for ch in declared):
            plugin_id = declared
        kind, version = _resolve_version(spec, versions)
    else:
        kind, version = "missing", None
    if kind == "range":
        reason = "version is a range, no lockfile"
    elif kind == "missing":
        reason = "version is not written in the repo"
    else:
        reason = "Gradle plugin, not a Maven module"
    shown = alias if alias != plugin_id else None
    return _unchecked("Maven", plugin_id, version, False, manifest, reason, alias=shown)


def parse_version_catalog(text: str, manifest: str) -> list[Package]:
    data = tomllib.loads(text)
    if not isinstance(data, dict):
        return _catalog_unrecognised(manifest)
    if not any(key in data for key in ("metadata", *_CATALOG_TABLES)):
        return _catalog_unrecognised(manifest)
    for key in _CATALOG_TABLES:
        if key in data and not isinstance(data[key], dict):
            return _catalog_unrecognised(manifest)
    versions = data.get("versions") if isinstance(data.get("versions"), dict) else {}
    libraries = data.get("libraries") if isinstance(data.get("libraries"), dict) else {}
    plugins = data.get("plugins") if isinstance(data.get("plugins"), dict) else {}
    found: list[Package] = []
    for alias, spec in libraries.items():
        found.append(_catalog_library(str(alias), spec, versions, manifest))
    for alias, spec in plugins.items():
        found.append(_catalog_plugin(str(alias), spec, versions, manifest))
    return dedupe(found)


def _lock_unrecognised(manifest: str) -> list[Package]:
    return [_unchecked(
        "Maven", manifest, None, False, manifest, "gradle lockfile shape was not recognised",
    )]


def _config_name(value: str) -> bool:
    return bool(value) and not any(ch in value for ch in " \t,=")


def _gradle_lock_entry(line: str):
    if line.startswith("empty="):
        rest = line[len("empty="):]
        if rest == "":
            return ("empty",)
        configs = [part.strip() for part in rest.split(",")]
        if configs and all(_config_name(part) for part in configs):
            return ("empty",)
        return None
    if line.count("=") != 1:
        return None
    coord, configs_text = line.split("=", 1)
    parts = coord.split(":")
    if len(parts) < 3 or not configs_text:
        return None
    group, artifact = parts[0], parts[1]
    version = ":".join(parts[2:])
    if not _maven_token(group) or not _maven_token(artifact):
        return None
    if not version or any(ch.isspace() for ch in version):
        return None
    configs = [part.strip() for part in configs_text.split(",")]
    if not configs or any(not _config_name(part) for part in configs):
        return None
    return ("module", f"{group}:{artifact}", version, configs)


def parse_gradle_lock(text: str, catalog_text: str | None, manifest: str) -> list[Package]:
    modules, aliases = _catalog_modules(catalog_text)
    found: list[Package] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = _gradle_lock_entry(line)
        if parsed is None:
            return _lock_unrecognised(manifest)
        if parsed[0] == "empty":
            continue
        _kind, name, version, configs = parsed
        dev = all("test" in config.lower() for config in configs)
        if _literal_maven_version(version):
            found.append(Package(
                "Maven", name, version, name in modules, dev, manifest, alias=aliases.get(name),
            ))
            continue
        found.append(_unchecked(
            "Maven", name, version, dev, manifest,
            "version is a range, no lockfile",
            direct=name in modules,
            alias=aliases.get(name),
        ))
    return dedupe(found)


_PROPERTY = re.compile(r"\$\{([^{}]+)\}")


def _local_name(tag: str) -> str:
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[-1]
    return tag


def _pom_root(text: str) -> ET.Element:
    stripped = re.sub(r"^\s*<\?xml[^?]*\?>", "", text, count=1)
    return ET.fromstring(stripped)


def _pom_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in list(element):
        if _local_name(child.tag) == name:
            return child
    return None


def _pom_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if _local_name(child.tag) == name]


def _pom_text(element: ET.Element | None) -> str | None:
    if element is None or element.text is None:
        return None
    text = element.text.strip()
    return text or None


def _pom_child_text(element: ET.Element, name: str) -> str | None:
    return _pom_text(_pom_child(element, name))


def _resolve_property_table(raw: dict[str, str]) -> dict[str, str]:
    resolved = dict(raw)
    for _ in range(len(resolved) + 2):
        changed = False
        for key, value in list(resolved.items()):
            def repl(match, current=key, table=resolved):
                name = match.group(1).strip()
                if not name or name == current:
                    return match.group(0)
                target = table.get(name)
                if target is None or "${" in target:
                    return match.group(0)
                return target

            nxt = _PROPERTY.sub(repl, value)
            if nxt != value:
                resolved[key] = nxt
                changed = True
        if not changed:
            break
    return resolved


def _expand_property(value: str, props: dict[str, str]) -> str:
    current = value
    for _ in range(12):
        def repl(match, table=props):
            name = match.group(1).strip()
            target = table.get(name)
            if target is None or "${" in target:
                return match.group(0)
            return target

        nxt = _PROPERTY.sub(repl, current)
        if nxt == current:
            return current
        current = nxt
    return current


def _unresolved_property_names(expr: str, props: dict[str, str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()

    def walk(text: str) -> None:
        for name in _PROPERTY.findall(text):
            name = name.strip()
            if not name or name in seen:
                continue
            seen.add(name)
            target = props.get(name)
            if target is None:
                names.append(name)
                continue
            if "${" in target or not _literal_maven_version(target):
                names.append(name)
                walk(target)

    walk(expr)
    return names


def _pom_properties(roots: list[ET.Element]) -> dict[str, str]:
    raw: dict[str, str] = {}
    coords = {"groupId": None, "artifactId": None, "version": None}
    for root in roots:
        props = _pom_child(root, "properties")
        if props is not None:
            for child in list(props):
                key = _local_name(child.tag)
                value = (child.text or "").strip()
                if key and value:
                    raw[key] = value
        for key in coords:
            value = _pom_child_text(root, key)
            if value:
                coords[key] = value
    resolved = _resolve_property_table(raw)
    for key, value in coords.items():
        if not value:
            continue
        expanded = _expand_property(value, resolved)
        resolved[f"project.{key}"] = expanded
        resolved[f"pom.{key}"] = expanded
        if key not in raw:
            resolved[key] = expanded
    return _resolve_property_table(resolved)


def _pom_dependency_fields(dep: ET.Element, props: dict[str, str]):
    group_raw = _pom_child_text(dep, "groupId") or ""
    artifact_raw = _pom_child_text(dep, "artifactId") or ""
    version_raw = _pom_child_text(dep, "version")
    scope = (_pom_child_text(dep, "scope") or "compile").lower()
    kind = (_pom_child_text(dep, "type") or "jar").lower()
    group = _expand_property(group_raw, props) if group_raw else ""
    artifact = _expand_property(artifact_raw, props) if artifact_raw else ""
    version = _expand_property(version_raw, props) if version_raw else None
    names: list[str] = []
    for raw in (group_raw, artifact_raw, version_raw or ""):
        for name in _unresolved_property_names(raw, props):
            if name not in names:
                names.append(name)
    return group, artifact, version, scope, kind, names


def _pom_management(roots: list[ET.Element], props: dict[str, str]):
    managed: dict[str, str] = {}
    imports: list[str] = []
    for root in roots:
        block = _pom_child(root, "dependencyManagement")
        holder = _pom_child(block, "dependencies") if block is not None else None
        if holder is None:
            continue
        for dep in _pom_children(holder, "dependency"):
            group, artifact, version, scope, kind, _names = _pom_dependency_fields(dep, props)
            if not _maven_token(group) or not _maven_token(artifact):
                continue
            label = f"{group}:{artifact}"
            if scope == "import" and kind == "pom":
                if label not in imports:
                    imports.append(label)
                continue
            if version:
                managed[label] = version
    return managed, imports


def _pom_alias(names: list[str]) -> str | None:
    cleaned = []
    for name in names:
        if name and name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        return None
    return ", ".join(cleaned)


def _pom_package(
    group: str,
    artifact: str,
    version: str | None,
    scope: str,
    names: list[str],
    manifest: str,
    *,
    version_raw: str | None,
) -> Package:
    dev = scope == "test"
    plain = _maven_token(group) and _maven_token(artifact) and "${" not in group and "${" not in artifact
    name = f"{group}:{artifact}" if group or artifact else manifest
    alias = _pom_alias(names)
    shown = version if version else version_raw
    if plain and version and "${" not in version and _literal_maven_version(version):
        return Package("Maven", name, version, True, dev, manifest, alias=alias)
    if version and "${" not in version and not _literal_maven_version(version):
        return _unchecked(
            "Maven", name, version, dev, manifest,
            "version is a range, no lockfile",
            alias=alias,
        )
    return _unchecked(
        "Maven", name, shown, dev, manifest,
        "version is not written in the repo",
        alias=alias,
    )


def parse_pom(texts: list[str], manifest: str, missing_parent: str | None = None) -> list[Package]:
    roots = [_pom_root(text) for text in texts]
    if not roots:
        return []
    props = _pom_properties(roots)
    managed, imports = _pom_management(roots, props)
    found: list[Package] = []
    own = roots[-1]
    block = _pom_child(own, "dependencyManagement")
    holder = _pom_child(block, "dependencies") if block is not None else None
    if holder is not None:
        for dep in _pom_children(holder, "dependency"):
            group, artifact, version, scope, kind, names = _pom_dependency_fields(dep, props)
            if scope != "import" or kind != "pom":
                continue
            if not group and not artifact:
                continue
            version_raw = _pom_child_text(dep, "version")
            found.append(_pom_package(
                group, artifact, version, "compile", names, manifest, version_raw=version_raw,
            ))
    dependencies = _pom_child(own, "dependencies")
    if dependencies is None:
        return found
    for dep in _pom_children(dependencies, "dependency"):
        group, artifact, version, scope, _kind, names = _pom_dependency_fields(dep, props)
        if not group and not artifact:
            continue
        version_raw = _pom_child_text(dep, "version")
        if not version_raw and _maven_token(group) and _maven_token(artifact):
            managed_version = managed.get(f"{group}:{artifact}")
            if managed_version:
                version = managed_version
                names.extend(_unresolved_property_names(managed_version, props))
            else:
                if missing_parent and missing_parent not in names:
                    names.append(missing_parent)
                for label in imports:
                    if label not in names:
                        names.append(label)
        found.append(_pom_package(
            group, artifact, version, scope, names, manifest, version_raw=version_raw,
        ))
    return found


def _pom_parent_file(pom_file: Path, text: str) -> tuple[Path | None, str | None]:
    try:
        root = _pom_root(text)
    except ET.ParseError:
        return None, None
    parent = _pom_child(root, "parent")
    if parent is None:
        return None, None
    group = _pom_child_text(parent, "groupId") or ""
    artifact = _pom_child_text(parent, "artifactId") or ""
    label = f"{group}:{artifact}" if group and artifact else None
    relative = _pom_child(parent, "relativePath")
    if relative is None:
        target = "../pom.xml"
    else:
        target = (relative.text or "").strip()
        if not target:
            return None, label
    if target.startswith(("/", "\\")) or ":" in target:
        return None, label
    base = "." if pom_file.parent == Path(".") else pom_file.parent.as_posix()
    joined = f"{base}/{target}"
    parts: list[str] = []
    for part in joined.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None, label
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        return None, label
    return Path(*parts), label


def _pom_chain(pom_file: Path, poms: dict[Path, str]) -> tuple[list[str], str | None]:
    chain: list[str] = []
    missing: str | None = None
    current: Path | None = pom_file
    seen: set[Path] = set()
    while current is not None and current not in seen:
        seen.add(current)
        text = poms.get(current)
        if text is None:
            break
        chain.append(text)
        parent_file, label = _pom_parent_file(current, text)
        if parent_file is not None and parent_file in poms:
            current = parent_file
            continue
        missing = label
        break
    chain.reverse()
    return chain, missing


def _pom_key(directory: Path) -> Path:
    if directory == Path("."):
        return Path("pom.xml")
    return directory / "pom.xml"


def _gradle_failed(rows: list[Package], manifest: str) -> bool:
    return (
        len(rows) == 1
        and rows[0].name == manifest
        and rows[0].unchecked_reason in {
            f"could not parse {manifest}",
            "gradle lockfile shape was not recognised",
            "version catalog was not recognised",
        }
    )


def parse_gemfile(text: str, manifest: str) -> list[Package]:
    found: list[Package] = []
    for gem in _gemfile_gems(text):
        dev = bool(gem["dev"])
        name = gem["name"]
        if gem["reason"]:
            found.append(_unchecked(
                "RubyGems", name, gem["version"], dev, manifest, gem["reason"],
            ))
            continue
        if gem["version"]:
            found.append(Package("RubyGems", name, gem["version"], True, dev, manifest))
            continue
        found.append(_unchecked(
            "RubyGems", name, None, dev, manifest, "version is a range, no lockfile",
        ))
    return found


def dedupe(packages: list[Package]) -> list[Package]:
    merged: dict[tuple, Package] = {}
    order: list[tuple] = []
    for pkg in packages:
        if pkg.unchecked_reason:
            key = ("unchecked", pkg.manifest, pkg.ecosystem, pkg.name, pkg.version, pkg.unchecked_reason)
        else:
            key = (pkg.ecosystem, pkg.name, pkg.version)
        previous = merged.get(key)
        if previous is None:
            merged[key] = pkg
            order.append(key)
            continue
        if pkg.direct and not previous.direct:
            previous.direct = True
            previous.manifest = pkg.manifest
        if previous.dev and not pkg.dev:
            previous.dev = False
        if pkg.alias:
            if not previous.alias:
                previous.alias = pkg.alias
            elif pkg.alias != previous.alias:
                names = sorted({part for part in previous.alias.split(", ") + pkg.alias.split(", ") if part})
                previous.alias = ", ".join(names)
    return [merged[key] for key in order]


def _nearest(directory: Path, locks: set[Path]) -> Path | None:
    current = directory
    while True:
        if current in locks:
            return current
        if current == Path("."):
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def _safe(parser, manifest: str, ecosystem: str):
    try:
        return parser()
    except Exception:
        return [_unchecked(ecosystem, manifest, None, False, manifest, f"could not parse {manifest}")]


def _walk_dirs(dirnames: list[str]) -> None:
    dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]


def _file_size(path: Path) -> int:
    try:
        return path.lstat().st_size
    except OSError:
        return 0


def _measure_tree(root: Path, on_progress) -> tuple[int, int]:
    """Count files and bytes under root. Skipped directories match the scan walk."""
    files = 0
    total = 0
    emitted = 0
    for dirpath, dirnames, filenames in os.walk(root):
        _walk_dirs(dirnames)
        for name in filenames:
            files += 1
            total += _file_size(Path(dirpath) / name)
            if files - emitted >= 40:
                on_progress({
                    "phase": "count",
                    "files_done": files,
                    "files_total": 0,
                    "bytes_done": total,
                    "bytes_total": 0,
                })
                emitted = files
    if files != emitted:
        on_progress({
            "phase": "count",
            "files_done": files,
            "files_total": 0,
            "bytes_done": total,
            "bytes_total": 0,
        })
    return files, total


def _emit_read(on_progress, files_done: int, files_total: int, bytes_done: int, bytes_total: int) -> None:
    if files_done > files_total:
        files_total = files_done
    if bytes_done > bytes_total:
        bytes_total = bytes_done
    on_progress({
        "phase": "read",
        "files_done": files_done,
        "files_total": files_total,
        "bytes_done": bytes_done,
        "bytes_total": bytes_total,
    })


def scan_tree(root: Path, on_progress=None) -> list[Package]:
    root = root.resolve()
    files_total = 0
    bytes_total = 0
    if on_progress is not None:
        files_total, bytes_total = _measure_tree(root, on_progress)
        _emit_read(on_progress, 0, files_total, 0, bytes_total)
    files_done = 0
    bytes_done = 0
    entries: list[tuple[Path, set[str], Path]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        _walk_dirs(dirnames)
        if on_progress is not None:
            for name in filenames:
                files_done += 1
                bytes_done += _file_size(Path(dirpath) / name)
                if files_done == files_total or files_done % 40 == 0:
                    _emit_read(on_progress, files_done, files_total, bytes_done, bytes_total)
        directory = Path(dirpath).relative_to(root)
        entries.append((directory, set(filenames), Path(dirpath)))
    if on_progress is not None:
        _emit_read(on_progress, files_done, files_done, bytes_done, bytes_done)

    npm_locks = {
        directory for directory, names, _path in entries
        if "package-lock.json" in names or "pnpm-lock.yaml" in names or "yarn.lock" in names
    }
    cargo_locks = {directory for directory, names, _path in entries if "Cargo.lock" in names}
    pub_locks = {directory for directory, names, _path in entries if "pubspec.lock" in names}
    found: list[Package] = []

    names_by_dir = {directory: names for directory, names, _path in entries}
    yarn_jsons: dict[Path, list[str]] = {}
    for directory, names, path in entries:
        if "package.json" not in names:
            continue
        owner = _nearest(directory, npm_locks)
        if owner is None:
            continue
        owner_names = names_by_dir.get(owner, set())
        if "yarn.lock" not in owner_names:
            continue
        if "package-lock.json" in owner_names or "pnpm-lock.yaml" in owner_names:
            continue
        yarn_jsons.setdefault(owner, []).append(_read(path / "package.json"))

    cargo_tomls: dict[Path, list[str]] = {lock: [] for lock in cargo_locks}
    for directory, names, path in entries:
        if "Cargo.toml" not in names:
            continue
        owner = _nearest(directory, cargo_locks)
        if owner is None:
            manifest = _rel(directory, "Cargo.toml")
            found.extend(_safe(lambda p=path, m=manifest: parse_cargo_toml(_read(p / "Cargo.toml"), m), manifest, "crates.io"))
            continue
        cargo_tomls.setdefault(owner, []).append(_read(path / "Cargo.toml"))

    for directory, names, path in entries:
        if "package-lock.json" in names:
            manifest = _rel(directory, "package-lock.json")
            found.extend(_safe(lambda p=path, m=manifest: parse_package_lock(_read(p / "package-lock.json"), m), manifest, "npm"))
        elif "pnpm-lock.yaml" in names:
            manifest = _rel(directory, "pnpm-lock.yaml")
            found.extend(_safe(lambda p=path, m=manifest: parse_pnpm_lock(_read(p / "pnpm-lock.yaml"), m), manifest, "npm"))
        elif "yarn.lock" in names:
            manifest = _rel(directory, "yarn.lock")
            jsons = yarn_jsons.get(directory, [])
            found.extend(_safe(
                lambda p=path, m=manifest, q=jsons: parse_yarn_lock(_read(p / "yarn.lock"), q, m),
                manifest,
                "npm",
            ))
        elif "package.json" in names and _nearest(directory, npm_locks) is None:
            manifest = _rel(directory, "package.json")
            found.extend(_safe(lambda p=path, m=manifest: parse_package_json(_read(p / "package.json"), m), manifest, "npm"))

        if "go.mod" in names:
            manifest = _rel(directory, "go.mod")
            found.extend(_safe(lambda p=path, m=manifest: parse_go_mod(_read(p / "go.mod"), m), manifest, "Go"))

        if "pubspec.lock" in names:
            manifest = _rel(directory, "pubspec.lock")
            found.extend(_safe(
                lambda p=path, m=manifest: parse_pubspec_lock(_read(p / "pubspec.lock"), m),
                manifest,
                "Pub",
            ))
        elif "pubspec.yaml" in names and _nearest(directory, pub_locks) is None:
            manifest = _rel(directory, "pubspec.yaml")
            found.extend(_safe(
                lambda p=path, m=manifest: parse_pubspec_yaml(_read(p / "pubspec.yaml"), m),
                manifest,
                "Pub",
            ))

        if "composer.lock" in names:
            manifest = _rel(directory, "composer.lock")
            composer_json = _read(path / "composer.json") if "composer.json" in names else None
            found.extend(_safe(
                lambda p=path, m=manifest, q=composer_json: parse_composer_lock(
                    _read(p / "composer.lock"), q, m,
                ),
                manifest,
                "Packagist",
            ))

        if "Gemfile.lock" in names:
            manifest = _rel(directory, "Gemfile.lock")
            gemfile = _read(path / "Gemfile") if "Gemfile" in names else None
            found.extend(_safe(
                lambda p=path, m=manifest, g=gemfile: parse_gemfile_lock(
                    _read(p / "Gemfile.lock"), g, m,
                ),
                manifest,
                "RubyGems",
            ))
        elif "Gemfile" in names:
            manifest = _rel(directory, "Gemfile")
            found.extend(_safe(
                lambda p=path, m=manifest: parse_gemfile(_read(p / "Gemfile"), m),
                manifest,
                "RubyGems",
            ))

        if "Cargo.lock" in names:
            manifest = _rel(directory, "Cargo.lock")
            tomls = cargo_tomls.get(directory, [])
            found.extend(_safe(
                lambda p=path, m=manifest, t=tomls: parse_cargo_lock(_read(p / "Cargo.lock"), t, m),
                manifest,
                "crates.io",
            ))

        if "uv.lock" in names:
            manifest = _rel(directory, "uv.lock")
            found.extend(_safe(lambda p=path, m=manifest: parse_uv_lock(_read(p / "uv.lock"), m), manifest, "PyPI"))
            continue
        if "poetry.lock" in names:
            manifest = _rel(directory, "poetry.lock")
            pyproject = _read(path / "pyproject.toml") if "pyproject.toml" in names else None
            found.extend(_safe(
                lambda p=path, m=manifest, q=pyproject: parse_poetry_lock(_read(p / "poetry.lock"), q, m),
                manifest,
                "PyPI",
            ))
            continue

        requirement_names = sorted(
            name for name in names
            if name.lower() == "requirements.txt" or (name.lower().startswith("requirements") and name.lower().endswith(".txt"))
        )
        if requirement_names:
            for name in requirement_names:
                manifest = _rel(directory, name)
                dev = "dev" in name.lower()
                found.extend(_safe(
                    lambda p=path, n=name, m=manifest, d=dev: parse_requirements(_read(p / n), m, d),
                    manifest,
                    "PyPI",
                ))
            continue
        if "pyproject.toml" in names:
            manifest = _rel(directory, "pyproject.toml")
            found.extend(_safe(lambda p=path, m=manifest: parse_pyproject(_read(p / "pyproject.toml"), m), manifest, "PyPI"))

    # Versions come from gradle.lockfile or a literal in libs.versions.toml.
    # build.gradle and build.gradle.kts are not read.
    gradle_catalogs: dict[Path, tuple[Path, str]] = {}
    for directory, names, path in entries:
        if "libs.versions.toml" not in names:
            continue
        project = directory.parent if directory.name == "gradle" else directory
        if project in gradle_catalogs and directory.name != "gradle":
            continue
        gradle_catalogs[project] = (directory, _read(path / "libs.versions.toml"))

    locked_modules: dict[Path, set[str]] = {project: set() for project in gradle_catalogs}
    for directory, names, path in entries:
        if "gradle.lockfile" not in names:
            continue
        manifest = _rel(directory, "gradle.lockfile")
        owner = _nearest(directory, set(gradle_catalogs))
        catalog_text = gradle_catalogs[owner][1] if owner is not None else None
        rows = _safe(
            lambda p=path, m=manifest, c=catalog_text: parse_gradle_lock(
                _read(p / "gradle.lockfile"), c, m,
            ),
            manifest,
            "Maven",
        )
        found.extend(rows)
        if owner is not None and not _gradle_failed(rows, manifest):
            locked_modules[owner].update(pkg.name for pkg in rows if ":" in pkg.name)

    literal_catalogs: set[Path] = set()
    for project, (file_dir, text) in gradle_catalogs.items():
        manifest = _rel(file_dir, "libs.versions.toml")
        rows = _safe(
            lambda t=text, m=manifest: parse_version_catalog(t, m),
            manifest,
            "Maven",
        )
        if _gradle_failed(rows, manifest):
            found.extend(rows)
            continue
        if any(pkg.unchecked_reason is None for pkg in rows):
            literal_catalogs.add(project)
        locked = locked_modules.get(project, set())
        for pkg in rows:
            if ":" in pkg.name and pkg.name in locked and pkg.unchecked_reason != "Gradle plugin, not a Maven module":
                continue
            found.append(pkg)

    for directory, names, _path in entries:
        if "gradle.lockfile" in names:
            continue
        script = "build.gradle" if "build.gradle" in names else None
        if script is None and "build.gradle.kts" in names:
            script = "build.gradle.kts"
        if script is None:
            continue
        if _nearest(directory, literal_catalogs) is not None:
            continue
        manifest = _rel(directory, script)
        found.append(_unchecked(
            "Maven", manifest, None, False, manifest, "Gradle script, no lockfile",
        ))

    poms: dict[Path, str] = {}
    for directory, names, path in entries:
        if "pom.xml" not in names:
            continue
        poms[_pom_key(directory)] = _read(path / "pom.xml")
    for pom_file, _text in poms.items():
        manifest = pom_file.as_posix()
        chain, missing = _pom_chain(pom_file, poms)
        found.extend(_safe(
            lambda c=chain, m=manifest, miss=missing: parse_pom(c, m, miss),
            manifest,
            "Maven",
        ))

    return found
