"""Read lockfiles into resolved package records.

A range in package.json or pyproject.toml is not an installed version. Those
rows are kept and marked unchecked so a run with no lockfile cannot look clean.
Nothing here installs packages.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
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
_REQ_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*==\s*([^\\\s;#]+)\s*$"
)


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
) -> Package:
    return Package(
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=direct,
        dev=dev,
        manifest=manifest,
        unchecked_reason=reason,
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


def parse_pnpm_lock(text: str, manifest: str) -> list[Package]:
    section = None
    mode: str | None = None
    mode_indent = 0
    prod: set[str] = set()
    dev: set[str] = set()
    current: dict | None = None
    blocks: list[dict] = []

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
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
            match = _PNPM_KEY.match(line)
            if match and indent == 2:
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
        if mode is not None and indent <= mode_indent:
            mode = None

    if current:
        blocks.append(current)

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


def parse_go_mod(text: str, manifest: str) -> list[Package]:
    found: list[Package] = []
    in_block = False
    for raw in text.splitlines():
        indirect = "// indirect" in raw
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if line == ")":
            in_block = False
            continue
        if in_block:
            parts = line.split()
            if len(parts) >= 2:
                found.append(Package("Go", parts[0], parts[1], not indirect, False, manifest))
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                found.append(Package("Go", parts[1], parts[2], not indirect, False, manifest))
    return found


def _cargo_direct(manifests: list[str]) -> tuple[set[str], set[str]]:
    prod: set[str] = set()
    dev: set[str] = set()
    for text in manifests:
        data = tomllib.loads(text)
        prod.update((data.get("dependencies") or {}).keys())
        dev.update((data.get("dev-dependencies") or {}).keys())
        dev.update((data.get("build-dependencies") or {}).keys())
        for key, value in data.items():
            if key.startswith("target.") and isinstance(value, dict):
                prod.update((value.get("dependencies") or {}).keys())
    dev -= prod
    return prod, dev


def parse_cargo_lock(text: str, cargo_tomls: list[str], manifest: str) -> list[Package]:
    data = tomllib.loads(text)
    prod, dev = _cargo_direct(cargo_tomls) if cargo_tomls else (set(), set())
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
        if source.startswith("registry+"):
            found.append(Package("crates.io", name, str(version), direct, is_dev, manifest))
            continue
        if source.startswith("git+"):
            found.append(_unchecked(
                "crates.io", name, str(version), is_dev, manifest,
                "git dependency, not a crates.io release",
                direct=direct,
            ))
    return found


def parse_cargo_toml(text: str, manifest: str) -> list[Package]:
    prod, dev = _cargo_direct([text])
    found: list[Package] = []
    data = tomllib.loads(text)
    specs = {}
    specs.update(data.get("dependencies") or {})
    specs.update(data.get("dev-dependencies") or {})
    for name in prod | dev:
        spec = specs.get(name)
        shown = spec if isinstance(spec, str) else None
        found.append(_unchecked(
            "crates.io", name, shown, name in dev, manifest,
            "version is a range, no lockfile",
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


def scan_tree(root: Path) -> list[Package]:
    root = root.resolve()
    entries: list[tuple[Path, set[str], Path]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        directory = Path(dirpath).relative_to(root)
        entries.append((directory, set(filenames), Path(dirpath)))

    npm_locks = {
        directory for directory, names, _path in entries
        if "package-lock.json" in names or "pnpm-lock.yaml" in names
    }
    cargo_locks = {directory for directory, names, _path in entries if "Cargo.lock" in names}
    found: list[Package] = []

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
        elif "package.json" in names and _nearest(directory, npm_locks) is None:
            manifest = _rel(directory, "package.json")
            found.extend(_safe(lambda p=path, m=manifest: parse_package_json(_read(p / "package.json"), m), manifest, "npm"))

        if "go.mod" in names:
            manifest = _rel(directory, "go.mod")
            found.extend(_safe(lambda p=path, m=manifest: parse_go_mod(_read(p / "go.mod"), m), manifest, "Go"))

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

    return found
