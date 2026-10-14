from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import json
import os
import re
from typing import Optional

from hooks.lib import adapters, paths, state

EXIT_OK, EXIT_REFUSED, EXIT_ERROR = 0, 1, 2
HOOK_SCRIPTS = tuple(sorted({spec.script for spec in adapters.HOOK_TABLE}))
FEATURES_HEADER = re.compile(r"^\s*\[features\]\s*$")
TABLE_HEADER = re.compile(r"^\s*\[")
HOOKS_ENABLED = re.compile(r"^\s*hooks\s*=\s*true\s*$")


class InstallError(Exception):
    pass


def is_harness_group(group) -> bool:
    text = json.dumps(group)
    return "bin/launch.sh" in text and any(script in text for script in HOOK_SCRIPTS)


def read_json_object(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InstallError("%s is not valid JSON (%s); fix or remove it, then re-run" % (path, exc.__class__.__name__))
    if not isinstance(data, dict):
        raise InstallError("%s does not hold a JSON object; fix or remove it, then re-run" % path)
    return data


def merge_hooks(existing, rendered: dict) -> dict:
    current = existing if isinstance(existing, dict) else {}
    merged: dict = {}
    for event, groups in current.items():
        kept = [g for g in (groups if isinstance(groups, list) else []) if not is_harness_group(g)]
        if kept:
            merged[event] = kept
    for event, groups in rendered.items():
        merged[event] = merged.get(event, []) + list(groups)
    return merged


def merge_deny(existing, rendered: list) -> list:
    current = [item for item in (existing if isinstance(existing, list) else []) if isinstance(item, str)]
    return current + [item for item in rendered if item not in current]


def install_claude(workspace: Path, root: Path) -> Path:
    target = workspace / ".claude" / "settings.json"
    settings = read_json_object(target)
    rendered = adapters.render_claude_settings(root, absolute=True)
    settings["hooks"] = merge_hooks(settings.get("hooks"), rendered["hooks"])
    permissions = settings.get("permissions") if isinstance(settings.get("permissions"), dict) else {}
    permissions["deny"] = merge_deny(permissions.get("deny"), rendered["permissions"]["deny"])
    settings["permissions"] = permissions
    target.parent.mkdir(parents=True, exist_ok=True)
    state.write_json_atomic(target, settings)
    return target


def merge_codex_toml(text: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if FEATURES_HEADER.match(line)), None)
    if start is None:
        prefix = text if not text or text.endswith("\n") else text + "\n"
        separator = "\n" if prefix.strip() else ""
        return prefix + separator + adapters.render_codex_config_toml()
    end = next((i for i in range(start + 1, len(lines)) if TABLE_HEADER.match(lines[i])), len(lines))
    section = [line for line in lines[start + 1:end] if not re.match(r"^\s*hooks\s*=", line)]
    rebuilt = lines[:start + 1] + ["hooks = true"] + section + lines[end:]
    return "\n".join(rebuilt) + "\n"


def install_codex(workspace: Path, root: Path) -> list:
    directory = workspace / ".codex"
    hooks_path = directory / "hooks.json"
    current = read_json_object(hooks_path)
    rendered = adapters.render_codex_hooks(root, absolute=True)
    current["hooks"] = merge_hooks(current.get("hooks"), rendered["hooks"])
    toml_path = directory / "config.toml"
    toml_text = toml_path.read_text(encoding="utf-8") if toml_path.exists() else ""
    directory.mkdir(parents=True, exist_ok=True)
    state.write_json_atomic(hooks_path, current)
    if not any(HOOKS_ENABLED.match(line) for line in features_lines(toml_text)):
        toml_text = merge_codex_toml(toml_text)
    tmp = toml_path.with_name("%s.tmp-%d" % (toml_path.name, os.getpid()))
    tmp.write_text(toml_text, encoding="utf-8")
    os.replace(str(tmp), str(toml_path))
    return [hooks_path, toml_path]


def features_lines(text: str) -> list:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if FEATURES_HEADER.match(line)), None)
    if start is None:
        return []
    end = next((i for i in range(start + 1, len(lines)) if TABLE_HEADER.match(lines[i])), len(lines))
    return lines[start + 1:end]


def ensure_gitignore(workspace: Path) -> Optional[Path]:
    target = workspace / ".gitignore"
    if not target.is_file():
        return None
    text = target.read_text(encoding="utf-8")
    entries = {line.strip() for line in text.splitlines()}
    if entries & {".omega/", ".omega", "/.omega/", "/.omega"}:
        return None
    prefix = text if not text or text.endswith("\n") else text + "\n"
    target.write_text(prefix + ".omega/\n", encoding="utf-8")
    return target


def install(workspace: str, provider: str = "both", root: Optional[Path] = None) -> list:
    base = Path(os.path.realpath(workspace))
    harness = Path(root).resolve() if root is not None else paths.harness_root()
    written: list = []
    if provider in ("claude", "both"):
        written.append(install_claude(base, harness))
    if provider in ("codex", "both"):
        written.extend(install_codex(base, harness))
    ignore = ensure_gitignore(base)
    if ignore is not None:
        written.append(ignore)
    return written


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="install_workspace.py",
                                     description="Install the harness hooks into a workspace with absolute paths.")
    parser.add_argument("workspace")
    parser.add_argument("--provider", choices=("claude", "codex", "both"), default="both")
    args = parser.parse_args(argv)
    workspace = os.path.realpath(args.workspace)
    if not os.path.isdir(workspace):
        sys.stderr.write("[install] %s is not a directory\n" % workspace)
        return EXIT_REFUSED
    try:
        written = install(workspace, args.provider)
    except InstallError as exc:
        sys.stderr.write("[install] refused: %s\n" % exc)
        return EXIT_ERROR
    except Exception as exc:
        sys.stderr.write("[install] internal error: %s: %s\n" % (exc.__class__.__name__, str(exc)[:200]))
        return EXIT_ERROR
    for path in written:
        sys.stdout.write("[install] wrote %s\n" % path)
    sys.stdout.write("[install] %s hooks now run from %s\n" % (args.provider, paths.harness_root() / "bin" / "launch.sh"))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
