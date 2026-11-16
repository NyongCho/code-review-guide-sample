"""Pure state transitions for a bounded review/repair run."""

import copy
from datetime import datetime

from .contracts import Json, ValidationError, digest, hex_digest, require, validate_config, validate_output, validate_run
from .policy import check_patch, classify_risk

MODEL_FIELDS = {"status", "findings", "summary", "risk", "patch", "dispositions"}


def initial_state(run: Json, config: Json) -> Json:
    validate_config(config)
    return validate_run(run) | {"phase": "bugs", "next_role": "bugs", "terminal": False,
                                "status": "incomplete", "calls": 0, "round": 1,
                                "candidates": {}, "open_findings": [], "event_digests": {},
                                "history": [], "ci_status": "pending", "tested_head": None,
                                "reviewed_head": None, "after_fix": False, "fixed_ids": []}


def _finish(state: Json, status: str, reason: str) -> Json:
    state.update(status=status, reason=reason, terminal=True, phase="done", next_role=None)
    return state


def _next(state: Json, role: str) -> Json:
    state.update(phase=role, next_role=role if role in {"bugs", "security", "verify", "fix"} else None,
                 status="incomplete", terminal=False)
    return state


def _budget(state: Json, cfg: Json) -> Json:
    if not state["terminal"] and state["next_role"] and cfg["mode"] == "api":
        if state["calls"] >= cfg["api_budget"]["max_calls"]:
            return _finish(state, "incomplete", "model call budget exhausted")
    return state


def advance(state: Json, event: Json, config: Json) -> Json:
    cfg, result = validate_config(config), copy.deepcopy(state)
    event_id = event.get("id")
    require(isinstance(event_id, str) and bool(event_id), "event id required")
    event_digest = digest(event)
    previous = result["event_digests"].get(event_id)
    if previous is not None:
        require(previous == event_digest, "same event id has different content")
        return result
    if result["terminal"]:
        return result
    result["event_digests"][event_id] = event_digest
    if event.get("head_sha") != result["head_sha"]:
        return _finish(result, "incomplete", "stale_head")
    now = datetime.fromisoformat(event["at"].replace("Z", "+00:00"))
    deadline = datetime.fromisoformat(result["deadline_at"].replace("Z", "+00:00"))
    require(now.tzinfo is not None, "event time requires timezone")
    if now >= deadline:
        return _finish(result, "incomplete", "deadline expired")
    kind = event.get("kind")
    if kind == "tick":
        return _budget(result, cfg)
    if kind == "tests_result":
        require(type(event.get("passed")) is bool, "test pass boolean required")
        result.update(ci_status="passed" if event["passed"] else "failed", tested_head=result["head_sha"])
        result["evidence"].append({"kind": "tests", "head_sha": result["head_sha"], "passed": event["passed"]})
        if not event["passed"]:
            return _finish(result, "needs_human", "deterministic checks failed")
        if result["phase"] == "tests":
            if result["reviewed_head"] == result["head_sha"] and not result["open_findings"]:
                return _finish(result, "verified", "current head reviewed and tested")
            result["candidates"] = {}
            return _budget(_next(result, "bugs"), cfg)
        return result
    if kind == "patch_result":
        require(result["phase"] == "publish", "patch result out of sequence")
        published = event["result"]
        if published.get("status") != "verified":
            return _finish(result, published.get("status", "failed"), published.get("reason", "patch not published"))
        hex_digest(published.get("head_sha"), "published head", (40, 64))
        hex_digest(published.get("input_digest"), "published input")
        require(published["head_sha"] != result["head_sha"], "patch must create a new head")
        result.update(head_sha=published["head_sha"], input_digest=published["input_digest"],
                      tested_head=None, reviewed_head=None, ci_status="pending", after_fix=True)
        result["candidates"] = {}
        result.pop("patch", None)
        return _next(result, "tests")
    require(kind == "model_result", "unknown event kind")
    role = event.get("role")
    require(role == result["next_role"], "model role out of sequence")
    result["calls"] += 1
    raw = event.get("result", {})
    try:
        model = validate_output({key: value for key, value in raw.items() if key in MODEL_FIELDS}, role)
    except (ValidationError, AttributeError):
        return _finish(result, "failed", "invalid model output")
    result["history"].append({"round": result["round"], "role": role, "head_sha": result["head_sha"], "result": model})
    if model["status"] in {"incomplete", "failed", "needs_human"}:
        return _finish(result, model["status"], raw.get("reason", model["summary"]))
    if role in {"bugs", "security"}:
        prior = {item["id"]: item for items in [result["open_findings"], *result["candidates"].values()] for item in items}
        if any(item["id"] in prior and prior[item["id"]] != item for item in model["findings"]):
            return _finish(result, "incomplete", "conflicting finding identity across reviewers")
        result["candidates"][role] = model["findings"]
        risk = classify_risk(result.get("changed_paths", []), model["risk"], cfg)["risk"]
        result["risk"] = max((risk, result.get("risk", "low")), key={"low": 0, "medium": 1, "high": 2}.get)
        return _budget(_next(result, "security" if role == "bugs" else "verify"), cfg)
    if role == "fix":
        if not model["patch"]:
            return _finish(result, "needs_human", "fixer did not propose a patch")
        decision = check_patch(model["patch"], result, cfg, None)
        if decision["status"] != "verified":
            return _finish(result, "needs_human", decision["reason"])
        result["patch"] = model["patch"]
        result["fixed_ids"] = [item["id"] for item in result["open_findings"]]
        return _next(result, "publish")
    expected = {item["id"] for item in result["open_findings"]}
    expected.update(item["id"] for items in result["candidates"].values() for item in items)
    dispositions = {item["id"]: item for item in model["dispositions"]}
    if len(dispositions) != len(model["dispositions"]):
        return _finish(result, "incomplete", "duplicate verifier disposition")
    if not expected.issubset(dispositions):
        return _finish(result, "incomplete", "verifier omitted prior finding disposition")
    confirmed = {item["id"] for item in model["findings"]}
    if any(dispositions[key]["decision"] == "confirmed" and key not in confirmed for key in expected):
        return _finish(result, "incomplete", "confirmed finding missing from final review")
    if any(dispositions[key]["decision"] == "pending" for key in expected):
        return _finish(result, "needs_human", "verifier could not resolve a finding")
    result.update(open_findings=model["findings"], findings=model["findings"], reviewed_head=result["head_sha"])
    if not model["findings"]:
        if result["tested_head"] == result["head_sha"] and result["ci_status"] == "passed":
            return _finish(result, "verified", "current head reviewed and tested")
        return _next(result, "tests")
    if not cfg["auto_fix"]:
        return _finish(result, "findings", "verified findings require resolution")
    if result["after_fix"]:
        if confirmed.intersection(result["fixed_ids"]):
            return _finish(result, "needs_human", "same finding remains after attempted fix")
        if result["round"] >= cfg["max_rounds"]:
            return _finish(result, "needs_human", "review round limit reached")
        result["round"] += 1
    result["fix_paths"] = list(dict.fromkeys(item["path"] for item in model["findings"]))
    return _budget(_next(result, "fix"), cfg)


def required_checks(state: Json, config: Json) -> Json:
    cfg = validate_config(config)
    ci = "success" if state.get("tested_head") == state["head_sha"] and state.get("ci_status") == "passed" else "failure"
    if cfg["review_mode"] == "observe":
        ai = "neutral"
    elif state.get("blocking_authorized") is not True:
        ai = "failure"
    elif not state.get("terminal") or state["status"] in {"incomplete", "failed", "needs_human"}:
        ai = "failure"
    else:
        ai = "failure" if any(item["severity"] in cfg["blocked_severities"] for item in state["findings"]) else "success"
    return {"ci": ci, "ai": ai, "review_status": state["status"], "head_sha": state["head_sha"]}
