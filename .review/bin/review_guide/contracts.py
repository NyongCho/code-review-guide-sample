"""Validation at file, model and workflow boundaries."""

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

Json = dict[str, Any]
STATES = {"verified", "findings", "needs_human", "incomplete", "failed"}
ROLES = {"bugs", "security", "verify", "fix"}
EMPTY_FINDINGS_ERROR = "findings status requires findings"
SENSITIVE = ["auth/**", "**/auth/**", "billing/**", "**/billing/**", "migrations/**",
             "**/migrations/**", ".github/**", ".review/**", ".agents/**", ".codex/**",
             "**/AGENTS*", "AGENTS*", "REVIEW.md", "*lock*", "pyproject.toml"]


class ValidationError(ValueError):
    """Input does not satisfy the public contract."""


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def text(value: Any, name: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{name}: non-empty string required")
    return value


def integer(value: Any, name: str, minimum: int = 1) -> int:
    require(type(value) is int and value >= minimum, f"{name}: integer >= {minimum} required")
    return value


def relative_path(value: Any) -> str:
    text(value, "path")
    require(not value.startswith("/") and "\\" not in value and "\x00" not in value
            and all(part not in ("", ".", "..") for part in value.split("/"))
            and not re.match(r"^[A-Za-z]:", value), "unsafe relative path")
    return str(PurePosixPath(value))


def hex_digest(value: Any, name: str, lengths=(64,)) -> str:
    require(isinstance(value, str) and len(value) in lengths
            and re.fullmatch(r"[0-9a-f]+", value) is not None, f"{name}: invalid digest")
    return value


def object_value(value: Any) -> Json:
    require(isinstance(value, dict), "JSON object required")
    return copy.deepcopy(value)


def no_secrets(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() not in {"api_key", "openai_api_key", "github_token", "password",
                                        "access_token", "refresh_token", "private_key"},
                    "credential values must not be serialized")
            no_secrets(child)
    elif isinstance(value, list):
        for child in value:
            no_secrets(child)


def validate_config(value: Json) -> Json:
    cfg = object_value(value)
    no_secrets(cfg)
    require(cfg.get("schema_version") == 1, "unsupported config schema_version")
    require(cfg.get("mode") in {"self_hosted", "api"}, "mode must be self_hosted or api")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cfg.get("repository", "")) is not None,
            "repository must be owner/name")
    for key in ("model", "effort", "codex_version"):
        text(cfg.get(key), key)
    defaults = {"max_rounds": 3, "critical_trials": 3, "review_mode": "observe",
                "auto_merge": False, "auto_fix": False, "model_timeout_s": 600,
                "run_timeout_s": 3600, "retention_days": 14, "trusted_ref": "refs/heads/main",
                "sensitive_paths": SENSITIVE, "fix_allowed": ["src/**", "tests/**"],
                "blocked_severities": ["P0", "P1"], "allowed_actors": [],
                "isolation": {"status": "needs_verification"}}
    for key, default in defaults.items():
        cfg.setdefault(key, copy.deepcopy(default))
    for key in ("max_rounds", "critical_trials", "model_timeout_s", "run_timeout_s", "retention_days"):
        integer(cfg[key], key)
    require(cfg["max_rounds"] <= 10, "max_rounds exceeds supported finite workflow limit (10)")
    require(cfg["auto_merge"] is False, "automatic merge is unsupported")
    require(type(cfg["auto_fix"]) is bool, "auto_fix must be boolean")
    require(cfg["review_mode"] in {"observe", "block"}, "invalid review_mode")
    require(cfg["trusted_ref"].startswith("refs/heads/"), "trusted_ref must name a branch")
    if cfg["review_mode"] == "block":
        require(isinstance(cfg.get("blocking_approval"), dict), "blocking requires approval reference")
    for field in ("fix_allowed", "sensitive_paths", "allowed_actors", "blocked_severities"):
        require(isinstance(cfg[field], list) and all(isinstance(x, str) and x for x in cfg[field]),
                f"{field}: string list required")
    commands = cfg.get("test_commands")
    require(isinstance(commands, list) and bool(commands), "test_commands required")
    for command in commands:
        require(isinstance(command, list) and bool(command)
                and all(isinstance(arg, str) and arg and "\x00" not in arg for arg in command),
                "test commands must be argv arrays, not shell strings")
    if cfg["mode"] == "api":
        budget = cfg.get("api_budget", {})
        require(isinstance(budget, dict) and type(budget.get("approved_usd")) in (int, float)
                and 0 < budget["approved_usd"] < float("inf"), "approved API budget required")
        integer(budget.get("max_calls"), "api_budget.max_calls")
    return cfg


def validate_edits(edits: list) -> None:
    require(isinstance(edits, list), "edits must be a list")
    seen = set()
    size = 0
    for edit in edits:
        require(isinstance(edit, dict) and set(edit) == {"path", "operation", "content"}, "invalid file edit")
        path = relative_path(edit["path"])
        require(path not in seen and ".git" not in path.lower().split("/")
                and all(ch.isprintable() for ch in path), "duplicate or unsafe edit path")
        seen.add(path)
        require(edit["operation"] in ("create", "replace", "delete"), "invalid edit operation")
        content = edit["content"]
        require(isinstance(content, str) and "\x00" not in content, "edit requires text content")
        require(edit["operation"] != "delete" or not content, "delete requires empty content")
        try:
            size += len(content.encode()) + len(path.encode())
        except UnicodeEncodeError as exc:
            raise ValidationError("edit requires UTF-8 text") from exc
        require(size <= 2_000_000, "oversized edit proposal")


def validate_output(value: Json, role: str) -> Json:
    result = object_value(value)
    require(role in ROLES, "invalid model role")
    proposal = "edits" if "edits" in result else "patch"
    require(set(result) == {"status", "findings", "summary", "risk", proposal, "dispositions"},
            "invalid model output fields")
    require(result["status"] in STATES, "invalid output status")
    text(result["summary"], "summary")
    require(result["risk"] in {"low", "medium", "high", "unknown"}, "invalid risk")
    if proposal == "edits":
        validate_edits(result["edits"])
        require(role == "fix" or not result["edits"], "only fixer may return edits")
        if not result["edits"]:
            # Retain the review-record format used by historical evaluation cases.
            del result["edits"]
            result["patch"] = ""
    else:
        require(isinstance(result["patch"], str) and not result["patch"], "file edits required")
    require(isinstance(result["findings"], list), "findings must be a list")
    ids = set()
    for item in result["findings"]:
        require(isinstance(item, dict), "invalid finding")
        require(set(item) == {"id", "kind", "severity", "path", "line", "condition", "impact", "evidence"},
                "invalid finding fields")
        for key in ("id", "condition", "impact", "evidence"):
            text(item[key], key)
        require(item["id"] not in ids, "duplicate finding id")
        ids.add(item["id"])
        require(item["kind"] in {"bug", "security", "spec"}, "invalid finding kind")
        require(item["severity"] in {"P0", "P1", "P2", "P3"}, "invalid severity")
        relative_path(item["path"])
        integer(item["line"], "line")
    require(result["status"] != "verified" or not result["findings"], "verified cannot contain findings")
    require(result["status"] != "findings" or bool(result["findings"]), EMPTY_FINDINGS_ERROR)
    require(isinstance(result["dispositions"], list), "dispositions must be a list")
    for disposition in result["dispositions"]:
        require(isinstance(disposition, dict) and set(disposition) == {"id", "decision", "reason"},
                "invalid disposition")
        text(disposition["id"], "id")
        text(disposition["reason"], "reason")
        require(disposition["decision"] in {"confirmed", "dismissed", "resolved", "pending"},
                "invalid disposition decision")
    return result


def validate_run(value: Json) -> Json:
    run = object_value(value)
    no_secrets(run)
    require(run.get("schema_version") == 1, "unsupported run schema_version")
    for key in ("repository", "mode", "auth_kind", "model", "codex_version", "runner", "role"):
        text(run.get(key), key)
    require((run["mode"], run["auth_kind"]) in {("self_hosted", "chatgpt"), ("api", "api_key")},
            "runtime/auth mismatch")
    require(run["role"] in ROLES, "invalid role")
    for key in ("base_sha", "head_sha", "policy_sha"):
        hex_digest(run.get(key), key, (40, 64))
    for key in ("input_digest", "config_digest", "prompt_digest"):
        hex_digest(run.get(key), key)
    integer(run.get("pr"), "pr")
    integer(run.get("round"), "round")
    require(isinstance(run.get("rules"), dict) and bool(run["rules"]), "rules provenance required")
    for path, sha in run["rules"].items():
        relative_path(path)
        hex_digest(sha, "rule hash")
    try:
        when = datetime.fromisoformat(run.get("deadline_at", "").replace("Z", "+00:00"))
        require(when.tzinfo is not None, "deadline must include timezone")
    except (ValueError, AttributeError) as exc:
        raise ValidationError("invalid deadline_at") from exc
    require(run.get("status") in STATES, "invalid run status")
    require(isinstance(run.get("findings"), list) and isinstance(run.get("evidence"), list),
            "run evidence and findings lists required")
    return run


def validate_case(value: Json) -> Json:
    case = object_value(value)
    require(case.get("schema_version") == 1, "unsupported case schema_version")
    require(re.fullmatch(r"[a-zA-Z0-9_-]+", case.get("id", "")) is not None, "invalid case id")
    hex_digest(case.get("input_digest"), "input_digest")
    require(case.get("status") in {"candidate", "confirmed"}, "invalid case status")
    require(isinstance(case.get("source"), dict), "case source required")
    require(type(case.get("critical")) is bool and case.get("split") in {"tuning", "holdout"},
            "critical and split required")
    if case["status"] == "confirmed":
        decision = case.get("decision", {})
        for key in ("actor", "at", "reason", "authority", "input_digest"):
            text(decision.get(key), key)
        require(decision["input_digest"] == case["input_digest"], "decision does not match input")
        require(isinstance(case.get("answers"), list), "confirmed answers required")
    return case


def validate_eval_manifest(value: Json) -> Json:
    manifest = object_value(value)
    require(manifest.get("schema_version") == 1, "unsupported evaluation schema_version")
    for key in ("corpus_digest", "rubric_digest"):
        hex_digest(manifest.get(key), key)
    configurations = manifest.get("configurations")
    require(isinstance(configurations, dict) and len(configurations) == 2, "two frozen configurations required")
    for identity, configuration in configurations.items():
        require(isinstance(configuration, dict) and digest(configuration) == identity,
                "frozen configuration digest mismatch")
    order = manifest.get("configuration_order")
    require(isinstance(order, list) and len(order) == 2 and set(order) == set(configurations),
            "configuration order mismatch")
    require(isinstance(manifest.get("expected"), list) and bool(manifest["expected"]), "expected trials required")
    seen = set()
    for trial in manifest["expected"]:
        text(trial.get("case_id"), "case_id")
        hex_digest(trial.get("configuration_digest"), "configuration_digest")
        require(trial["configuration_digest"] in configurations, "unknown trial configuration")
        integer(trial.get("trial_index"), "trial_index")
        key = (trial["case_id"], trial["configuration_digest"], trial["trial_index"])
        require(key not in seen, "duplicate expected trial")
        seen.add(key)
    return manifest
