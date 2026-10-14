from __future__ import annotations

import dataclasses
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import hashing

SEAMS = ("Unit", "Integration", "Functional", "Journey")
METADATA_KEYS = ("slug", "code", "tests", "owed", "assumptions")
KEYWORDS = ("Given", "When", "Then", "And")
NOT_APPLICABLE_PREFIX = "not_applicable:"
DEFAULT_DIR = "docs/contracts"

_TITLE = re.compile(r"^#\s+Contract:\s*(.*?)\s*$")
_H1 = re.compile(r"^#\s+")
_H2 = re.compile(r"^##\s+(.*?)\s*#*\s*$")
_H3_SCENARIO = re.compile(r"^###\s+Scenario:\s*(.*?)\s*$")
_H3 = re.compile(r"^###\s+")
_META = re.compile(r"^(slug|code|tests|owed|assumptions)\s*:\s*(.*?)\s*$", re.IGNORECASE)
_STEP = re.compile(r"^\s*[-*+]\s+(Given|When|Then|And)\b[\s:,]*(.*?)\s*$", re.IGNORECASE)
_NOT_APPLICABLE = re.compile(r"^\s*_\s*Not applicable\s*:\s*(.*?)\s*_\s*$", re.IGNORECASE)
_CONTINUATION = re.compile(r"^\s+\S")
_ORDER = {"Given": 0, "When": 1, "Then": 2}


@dataclass
class Step:
    keyword: str
    text: str


@dataclass
class Scenario:
    name: str
    steps: list = field(default_factory=list)


@dataclass
class Contract:
    path: str
    slug: str
    title: str
    code: list
    tests: list
    owed: str
    assumptions: str
    seams: dict
    errors: list
    warnings: list


def normalise(text: str) -> str:
    return " ".join(str(text or "").split()).casefold()


def _split_list(value: str) -> list:
    out: list = []
    for item in value.split(","):
        item = item.strip().strip("`").strip()
        while item.startswith("./"):
            item = item[2:]
        if item and item not in out:
            out.append(item)
    return out


def _check_scenario(scenario: Scenario, errors: list) -> None:
    present: set = set()
    previous: Optional[str] = None
    highest = -1
    out_of_order = False
    dangling_and = False
    for step in scenario.steps:
        keyword = step.keyword
        if keyword == "And":
            if previous is None:
                dangling_and = True
            continue
        present.add(keyword)
        rank = _ORDER[keyword]
        if rank < highest:
            out_of_order = True
        highest = max(highest, rank)
        previous = keyword
    for keyword in ("Given", "When", "Then"):
        if keyword not in present:
            errors.append("E008: scenario %s lacks %s" % (scenario.name, keyword))
    if out_of_order:
        errors.append("E010: step out of order in %s" % scenario.name)
    if dangling_and:
        errors.append("E012: And without a preceding step in %s" % scenario.name)


def parse(text: str, path: str) -> Contract:
    errors: list = []
    warnings: list = []
    lines = (text or "").splitlines()
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    title = ""
    if index < len(lines) and _TITLE.match(lines[index]):
        title = _TITLE.match(lines[index]).group(1)
        index += 1
    else:
        errors.append("E001: missing title line")
    meta: dict = {}
    seams: dict = {}
    scenario_names: dict = {}
    current_seam: Optional[str] = None
    current_scenario: Optional[Scenario] = None
    seen_section = False
    in_assumptions = False
    seam_flags: dict = {}
    while index < len(lines):
        line = lines[index]
        index += 1
        stripped = line.strip()
        h2 = _H2.match(line) if line.startswith("## ") or line.startswith("##\t") else None
        if h2:
            seen_section = True
            in_assumptions = False
            current_scenario = None
            heading = h2.group(1).strip()
            seam = next((s for s in SEAMS if s.casefold() == heading.casefold()), None)
            if seam is None:
                errors.append("E011: unknown section %s" % heading)
                current_seam = None
            elif seam in seams:
                errors.append("E011: unknown section %s (duplicate)" % heading)
                current_seam = None
            else:
                seams[seam] = []
                seam_flags[seam] = None
                current_seam = seam
            continue
        if not seen_section:
            m = _META.match(line)
            if m:
                key = m.group(1).lower()
                value = m.group(2)
                in_assumptions = key == "assumptions"
                if key in meta:
                    warnings.append("W003: metadata key %s repeated; the first value is used" % key)
                    continue
                meta[key] = value
                continue
            if in_assumptions and _CONTINUATION.match(line):
                meta["assumptions"] = (meta.get("assumptions", "") + "\n" + stripped).strip()
                continue
            if stripped:
                in_assumptions = False
            continue
        if _META.match(line):
            errors.append("E013: metadata line after the first section")
            continue
        if current_seam is None:
            continue
        scenario_match = _H3_SCENARIO.match(line)
        if scenario_match:
            name = scenario_match.group(1).strip()
            current_scenario = Scenario(name=name, steps=[])
            seams[current_seam].append(current_scenario)
            key = normalise(name)
            scenario_names[key] = scenario_names.get(key, 0) + 1
            if scenario_names[key] == 2:
                errors.append("E009: duplicate scenario name %s" % name)
            continue
        if _H3.match(line):
            current_scenario = None
            continue
        na = _NOT_APPLICABLE.match(line)
        if na and current_scenario is None:
            if seam_flags.get(current_seam) is None:
                seam_flags[current_seam] = na.group(1).strip()
            continue
        step = _STEP.match(line)
        if step and current_scenario is not None:
            keyword = step.group(1).capitalize()
            current_scenario.steps.append(Step(keyword=keyword, text=step.group(2).strip()))
            continue
    final_seams: dict = {}
    for seam in SEAMS:
        if seam not in seams:
            errors.append("E006: seam missing %s" % seam)
            continue
        scenarios = seams[seam]
        reason = seam_flags.get(seam)
        if scenarios:
            if reason is not None:
                warnings.append("W007: seam %s has scenarios and a not-applicable line; the line is ignored" % seam)
            for scenario in scenarios:
                _check_scenario(scenario, errors)
            final_seams[seam] = scenarios
        elif reason is not None:
            if seam == "Unit":
                errors.append("E014: Unit seam cannot be not-applicable")
            elif not reason:
                errors.append("E007: seam %s has no scenario" % seam)
            final_seams[seam] = NOT_APPLICABLE_PREFIX + reason
        else:
            errors.append("E007: seam %s has no scenario" % seam)
            final_seams[seam] = []
    for key in METADATA_KEYS:
        if key not in meta:
            errors.append("E003: missing metadata key %s" % key)
    slug = (meta.get("slug") or "").strip()
    stem = Path(path).stem if path else ""
    if "slug" in meta and slug != stem:
        errors.append("E002: slug does not match file name")
    code = _split_list(meta.get("code", ""))
    tests = _split_list(meta.get("tests", ""))
    if ("code" in meta and not code) or ("tests" in meta and not tests):
        errors.append("E015: empty code or tests list")
    return Contract(
        path=str(path),
        slug=slug,
        title=title,
        code=code,
        tests=tests,
        owed=(meta.get("owed") or "").strip(),
        assumptions=(meta.get("assumptions") or "").strip(),
        seams=final_seams,
        errors=_sorted_codes(errors),
        warnings=_sorted_codes(warnings),
    )


def _code_number(entry: str) -> int:
    m = re.match(r"^[EW](\d+)", entry)
    return int(m.group(1)) if m else 999


def _sorted_codes(entries: list) -> list:
    unique: list = []
    for entry in entries:
        if entry not in unique:
            unique.append(entry)
    return sorted(unique, key=_code_number)


def _bad_rel(value: str) -> bool:
    return value.startswith("/") or value.startswith("~") or ".." in Path(value).parts


def validate(contract: Contract, workspace: str, strict_existence: bool) -> Contract:
    errors = [e for e in contract.errors if not re.match(r"^E00[45]:", e)]
    warnings = [w for w in contract.warnings if not re.match(r"^W00[45]:", w)]
    for label, items in (("4", contract.code), ("5", contract.tests)):
        kind = "code" if label == "4" else "tests"
        for item in items:
            exists = not _bad_rel(item) and os.path.exists(os.path.join(workspace, item))
            if exists:
                continue
            if strict_existence or _bad_rel(item):
                errors.append("E00%s: %s path not found %s" % (label, kind, item))
            else:
                warnings.append("W00%s: %s path not found %s" % (label, kind, item))
    return dataclasses.replace(contract, errors=_sorted_codes(errors), warnings=_sorted_codes(warnings))


def structure(contract: Contract) -> dict:
    seams: dict = {}
    for seam, value in sorted(contract.seams.items()):
        if isinstance(value, str) and value.startswith(NOT_APPLICABLE_PREFIX):
            seams[seam] = {"not_applicable": normalise(value[len(NOT_APPLICABLE_PREFIX):])}
        else:
            seams[seam] = [{"name": normalise(s.name),
                            "steps": [[step.keyword, normalise(step.text)] for step in s.steps]}
                           for s in value]
    return {
        "slug": contract.slug,
        "code": sorted(contract.code),
        "tests": sorted(contract.tests),
        "assumptions": normalise(contract.assumptions),
        "seams": seams,
    }


def fingerprint(contract: Contract) -> str:
    return hashing.sha256_text(hashing.canonical_json(structure(contract)))


def seam_counts(contract: Contract) -> dict:
    counts: dict = {}
    for seam in SEAMS:
        value = contract.seams.get(seam)
        counts[seam] = len(value) if isinstance(value, list) else 0
    return counts


def not_applicable(contract: Contract) -> list:
    return [seam for seam in SEAMS
            if isinstance(contract.seams.get(seam), str)
            and contract.seams[seam].startswith(NOT_APPLICABLE_PREFIX)]


def is_valid(contract: Contract) -> bool:
    return not any(e.startswith("E") for e in contract.errors)


def contracts_dir(workspace: str, cfg=None) -> Path:
    rel_dir = cfg.get("contracts.dir", DEFAULT_DIR) if cfg is not None else DEFAULT_DIR
    return Path(workspace) / (rel_dir or DEFAULT_DIR)


def load_file(path: str, workspace: str, strict_existence: bool = False) -> Contract:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        missing = Contract(path=str(path), slug=Path(path).stem, title="", code=[], tests=[], owed="",
                           assumptions="", seams={}, errors=["E001: missing title line"],
                           warnings=["W000: unreadable: %s" % exc.__class__.__name__])
        return missing
    return validate(parse(text, str(path)), workspace, strict_existence)


def load_all(workspace: str, cfg) -> list:
    directory = contracts_dir(workspace, cfg)
    if not directory.is_dir():
        return []
    found: list = []
    for item in sorted(directory.glob("*.md")):
        if item.name.lower() == "readme.md" or not item.is_file():
            continue
        found.append(load_file(str(item), workspace, strict_existence=False))
    return found


def _clean_rel(value: str) -> str:
    text = Path(str(value)).as_posix()
    while text.startswith("./"):
        text = text[2:]
    return text


def covering(contracts: list, rel_path: str) -> list:
    target = _clean_rel(rel_path)
    return [c for c in contracts or [] if target in [_clean_rel(p) for p in c.code]]
