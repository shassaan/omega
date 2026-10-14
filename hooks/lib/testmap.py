from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import paths

PYTHON_EXTS = (".py",)
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
VITEST_CONFIGS = ("vitest.config.ts", "vitest.config.js", "vitest.config.mts", "vitest.config.mjs",
                  "vitest.config.cts", "vitest.config.cjs")
JEST_CONFIGS = ("jest.config.js", "jest.config.ts", "jest.config.cjs", "jest.config.mjs",
                "jest.config.json")


@dataclass
class MappedTest:
    candidates: list = field(default_factory=list)
    existing: Optional[str] = None
    lang: str = ""
    from_contract: bool = False


def _clean(rel: str) -> str:
    text = Path(str(rel)).as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def is_test(rel: str, cfg) -> bool:
    return paths.match_globs(_clean(rel), cfg.get("tdd.test_globs", []))


def is_exempt_rel(rel: str, cfg) -> bool:
    return paths.match_globs(_clean(rel), cfg.get("tdd.exempt_globs", []))


def is_source(rel: str, cfg) -> bool:
    relative = _clean(rel)
    if not relative or relative.startswith("/") or relative.startswith("../"):
        return False
    ext = os.path.splitext(relative)[1]
    if ext not in (cfg.get("tdd.source_exts", []) or []):
        return False
    return not is_test(relative, cfg) and not is_exempt_rel(relative, cfg)


def lang_of(rel: str) -> str:
    ext = os.path.splitext(rel)[1]
    if ext in PYTHON_EXTS:
        return "python"
    if ext in JS_EXTS:
        return "ts"
    return ""


def _dedupe(items: list) -> list:
    out: list = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


def _first_existing(workspace: str, candidates: list) -> Optional[str]:
    for candidate in candidates:
        if os.path.isfile(os.path.join(workspace, candidate)):
            return candidate
    return None


def _render(template: str, groups: dict) -> Optional[str]:
    try:
        return _clean(template.format(**groups))
    except (KeyError, IndexError, ValueError):
        return None


def map_test(rel: str, ctx, cfg, contracts: Optional[list] = None) -> MappedTest:
    relative = _clean(rel)
    workspace = ctx.workspace
    overrides = cfg.get("tdd.overrides", {}) or {}
    if relative in overrides:
        value = overrides[relative]
        candidates = _dedupe([_clean(v) for v in ([value] if isinstance(value, str) else list(value or []))])
        return MappedTest(candidates, _first_existing(workspace, candidates), lang_of(relative), False)
    if contracts is None:
        from . import contracts as contracts_mod
        try:
            contracts = contracts_mod.load_all(workspace, cfg)
        except OSError:
            contracts = []
    from . import contracts as contracts_mod
    covering = contracts_mod.covering(contracts or [], relative)
    if covering:
        candidates = _dedupe([_clean(t) for c in covering for t in c.tests])
        if candidates:
            return MappedTest(candidates, _first_existing(workspace, candidates), lang_of(relative), True)
    for mapping in cfg.get("tdd.mappings", []) or []:
        try:
            match = re.match(mapping.get("source", ""), relative)
        except re.error:
            continue
        if not match:
            continue
        groups = {k: (v or "") for k, v in match.groupdict().items()}
        srcdir = relative.rsplit("/", 1)[0] + "/" if "/" in relative else ""
        groups.setdefault("srcdir", srcdir)
        groups["srcdir"] = srcdir
        rendered = [_render(t, groups) for t in mapping.get("tests", [])]
        candidates = _dedupe([r for r in rendered if r and r != relative])
        return MappedTest(candidates, _first_existing(workspace, candidates), mapping.get("lang", ""), False)
    return MappedTest([], None, lang_of(relative), False)


def workspace_python(workspace: str) -> str:
    candidates = [os.path.join(workspace, ".venv", "bin", "python"),
                  os.path.join(workspace, "venv", "bin", "python")]
    virtual_env = os.environ.get("VIRTUAL_ENV")
    if virtual_env:
        candidates.append(os.path.join(virtual_env, "bin", "python"))
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "python3"


def _package_json(workspace: str) -> dict:
    try:
        with open(os.path.join(workspace, "package.json"), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def js_runner(workspace: str) -> Optional[str]:
    if any(os.path.isfile(os.path.join(workspace, name)) for name in VITEST_CONFIGS):
        return "vitest"
    if any(os.path.isfile(os.path.join(workspace, name)) for name in JEST_CONFIGS):
        return "jest"
    package = _package_json(workspace)
    deps: dict = {}
    for key in ("devDependencies", "dependencies"):
        value = package.get(key)
        if isinstance(value, dict):
            deps.update(value)
    if "vitest" in deps:
        return "vitest"
    if "jest" in deps:
        return "jest"
    if isinstance(package.get("jest"), dict):
        return "jest"
    return None


def runner_for(test_rel: str, ctx, cfg) -> Optional[list]:
    relative = _clean(test_rel)
    lang = lang_of(relative)
    if lang == "python":
        name = "python"
    elif lang == "ts":
        name = js_runner(ctx.workspace)
        if name is None:
            return None
    else:
        return None
    spec = (cfg.get("tdd.runners", {}) or {}).get(name) or {}
    argv = spec.get("argv")
    if not isinstance(argv, list) or not argv:
        return None
    values = {"python": workspace_python(ctx.workspace), "test": relative}
    return [str(token).replace("{python}", values["python"]).replace("{test}", values["test"])
            for token in argv]


def scope_key(test_rel: str) -> str:
    return "test:" + _clean(test_rel)
