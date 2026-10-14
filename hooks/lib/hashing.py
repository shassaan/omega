from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

DELETED = "<deleted>"
DIRECTORY = "<dir>"
_CHUNK = 1 << 20


def sha256_file(path: str) -> str:
    target = str(path)
    if os.path.isdir(target):
        return DIRECTORY
    digest = hashlib.sha256()
    try:
        with open(target, "rb") as handle:
            while True:
                block = handle.read(_CHUNK)
                if not block:
                    break
                digest.update(block)
    except (FileNotFoundError, NotADirectoryError):
        return DELETED
    except IsADirectoryError:
        return DIRECTORY
    except OSError:
        return DELETED
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _rel_key(workspace: str, path: str) -> str:
    from . import paths as paths_mod
    text = str(path)
    if os.path.isabs(text):
        return paths_mod.rel(text, workspace)
    while text.startswith("./"):
        text = text[2:]
    return Path(text).as_posix()


def _abs_of(workspace: str, rel_or_abs: str) -> str:
    text = str(rel_or_abs)
    return text if os.path.isabs(text) else os.path.join(workspace, text)


def snapshot(workspace: str, rel_paths: list) -> dict:
    files: dict = {}
    for item in rel_paths or []:
        key = _rel_key(workspace, item)
        if key in files:
            continue
        files[key] = sha256_file(_abs_of(workspace, key))
    return files


def files_digest(files: dict) -> str:
    return sha256_text(canonical_json(files or {}))


def fresh(clearance: dict, workspace: str, ledger_paths: list) -> tuple:
    if not isinstance(clearance, dict):
        return False, "clearance is not a JSON object"
    files = clearance.get("files")
    if not isinstance(files, dict):
        return False, "clearance has no files map"
    digest = clearance.get("files_digest")
    if digest is not None and digest != files_digest(files):
        return False, "files_digest does not match the files map"
    for rel_path, recorded in sorted(files.items()):
        current = sha256_file(_abs_of(workspace, rel_path))
        if current != recorded:
            return False, "%s changed since the clearance was written" % rel_path
    for item in ledger_paths or []:
        key = _rel_key(workspace, item)
        if key not in files:
            return False, "%s was touched but is not covered by the clearance" % key
    return True, "every cleared file matches its recorded sha256"
