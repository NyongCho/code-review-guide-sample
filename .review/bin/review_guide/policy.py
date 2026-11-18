"""Deterministic risk floors and patch scope. Model output is never authority."""

import fnmatch
import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

from .contracts import Json, SENSITIVE, ValidationError, relative_path, validate_config


@dataclass(frozen=True)
class VerifiedApproval:
    """Created by a trusted resolver, never deserialized from worker output."""

    binding: Json
    actor: str
    source: str


class PatchSyntaxError(ValidationError):
    """Git could not parse the diff; no edit is authorized."""


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def classify_risk(paths: list[str], ai_risk: str | None, config: Json) -> Json:
    cfg = validate_config(config)
    paths = [relative_path(path) for path in paths]
    sensitive = [path for path in paths if matches(path, SENSITIVE + cfg["sensitive_paths"])]
    risk = "high" if sensitive else ai_risk if ai_risk in {"low", "medium", "high"} else "medium"
    return {"risk": risk, "sensitive_paths": sensitive, "human_required": risk != "low"}


def check_hunk_boundaries(patch: str) -> None:
    """Git can ignore an extra change line once the declared hunk is complete."""
    lines = patch.split("\n")
    remaining = None
    for index, line in enumerate(lines):
        if line.startswith("@@ "):
            header = re.match(r"^@@ -[0-9]+(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@", line)
            if not header:
                raise PatchSyntaxError("invalid hunk header")
            try:
                remaining = sum(int(count or "1") for count in header.groups())
            except ValueError as exc:
                raise PatchSyntaxError("invalid hunk size") from exc
        elif remaining is not None:
            if line.startswith("\\ No newline at end of file"):
                continue
            if remaining == 0:
                # Traditional unified diffs can start a new file without a diff --git line.
                if (line.startswith("--- ") and index + 2 < len(lines)
                        and lines[index + 1].startswith("+++ ") and lines[index + 2].startswith("@@ ")):
                    remaining = None
                elif line.rstrip("\r") != "-- " and line.startswith(("+", "-", " ")):
                    raise PatchSyntaxError("change outside declared hunk")
            elif not line or line.startswith((" ", "+", "-")):
                # Git also accepts an empty line as blank context.
                remaining -= 1 if line.startswith(("+", "-")) else 2
            else:
                remaining = None


def patch_paths(patch: str) -> list[str]:
    if not patch or len(patch.encode()) > 2_000_000 or "\x00" in patch:
        raise ValidationError("empty or oversized patch")
    with tempfile.TemporaryDirectory(prefix="review-patch-") as tmp:
        result = subprocess.run(["git", "apply", "--numstat", "-z", "-"], input=patch,
                                cwd=tmp, capture_output=True, text=True, timeout=10,
                                env={**os.environ, "LC_ALL": "C"})
    if result.returncode:
        if result.stderr.startswith("error: corrupt patch at "):
            raise PatchSyntaxError("invalid unified diff")
        raise ValidationError("invalid git patch")
    check_hunk_boundaries(patch)
    paths = []
    for record in result.stdout.split("\x00"):
        if not record:
            continue
        fields = record.split("\t", 2)
        if len(fields) != 3 or fields[0] == "-" or fields[1] == "-":
            raise ValidationError("binary or unsupported patch")
        paths.append(relative_path(fields[2]))
    if not paths:
        raise ValidationError("patch has no supported changes")
    return paths


def check_patch(patch: str, run: Json, config: Json,
                approval: VerifiedApproval | None, *, created_paths: set[str] | None = None) -> Json:
    cfg = validate_config(config)
    reject = lambda reason: {"status": "needs_human", "reason": reason, "paths": []}
    if not cfg["auto_fix"]:
        return reject("automatic fixes are disabled")
    if any(line.startswith(("rename from ", "rename to ", "copy from ", "copy to ",
                            "old mode ", "new mode ")) for line in patch.splitlines()):
        return reject("rename, copy or mode changes require review")
    if any(line.startswith("new file mode ") and line != "new file mode 100644"
           for line in patch.splitlines()):
        return reject("unsupported new file mode")
    try:
        paths = patch_paths(patch)
    except PatchSyntaxError:
        return reject("invalid unified diff") | {"format_feedback": "Regenerate a complete git diff with accurate hunk counts and repository-relative paths. The source/ snapshot prefix is not part of the target paths."}
    except (ValidationError, subprocess.TimeoutExpired):
        return reject("unsafe or invalid patch")
    binding = {key: run.get(key) for key in ("repository", "base_sha", "head_sha", "input_digest", "policy_sha")}
    binding["patch_digest"] = hashlib.sha256(patch.encode()).hexdigest()
    approved = isinstance(approval, VerifiedApproval) and approval.binding == binding
    # Policy and ground truth are always changed through their own protected workflows.
    if any(matches(path, [".review/**", ".github/**", ".agents/**", ".codex/**", "AGENTS*", "**/AGENTS*", "REVIEW.md"])
           for path in paths):
        return reject("policy, workflow and instruction edits require a separate change")
    if approved:
        return {"status": "verified", "reason": "scoped human approval", "paths": paths}
    sections = patch.split("diff --git ")[1:]
    for path in paths:
        is_new = path in created_paths if created_paths is not None else any("\nnew file mode 100644\n" in section and f"\n+++ b/{path}\n" in section for section in sections)
        reason = automatic_path_error(path, is_new, run, cfg)
        if reason:
            return reject(reason)
    return {"status": "verified", "reason": "verified finding within automatic scope", "paths": paths}


def automatic_path_error(path: str, is_new: bool, run: Json, cfg: Json) -> str | None:
    if not cfg["auto_fix"] or not matches(path, cfg["fix_allowed"]):
        return "path is outside automatic fix scope"
    if matches(path, SENSITIVE + cfg["sensitive_paths"]):
        return "sensitive path"
    parts = path.split("/")
    test_directory = any(part in {"test", "tests", "__tests__", "spec", "specs"} for part in parts[:-1])
    test_filename = matches(parts[-1], ["test*.py", "*_test.*", "*.test.*", "*.spec.*", "*Test.java", "*Tests.java"])
    if not is_new and (test_directory or test_filename):
        return "existing verification changed"
    if is_new and "tests" in parts[:-1]:
        return None
    if path not in run.get("fix_paths", []):
        return "path is unrelated to verified findings"
    return None
