"""Install a self-contained bundle, preserving local changes with a three-way merge."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from . import __version__
from .contracts import Json, ValidationError, relative_path, require, validate_config
from .workflows import render_workflows

START, END = "<!-- review-guide:start -->", "<!-- review-guide:end -->"


def _managed(local: str, body: str) -> str:
    require(local.count(START) == local.count(END) <= 1,
            "malformed or duplicate managed block")
    block = START + "\n" + body.rstrip() + "\n" + END
    if START in local:
        require(local.index(START) < local.index(END), "reversed managed block")
        before, rest = local.split(START)
        _, after = rest.split(END)
        return before + block + after
    return local.rstrip() + "\n\n" + block + "\n"


def safe_target(root: Path, relative: str) -> Path:
    path = root / relative_path(relative)
    require(not root.is_symlink(), "target root cannot be a symlink")
    for parent in (path, *path.parents):
        if parent == root.parent:
            break
        require(not parent.is_symlink(), f"symlink target: {relative}")
    require(path.resolve().is_relative_to(root.resolve()), "target escapes project")
    return path


def _read(path: Path) -> str | None:
    return path.read_text() if path.exists() else None


def _merge(local: str, base: str, incoming: str) -> str | None:
    with tempfile.TemporaryDirectory(prefix="review-merge-") as tmp:
        paths = [Path(tmp) / name for name in ("local", "base", "incoming")]
        for path, content in zip(paths, (local, base, incoming)):
            path.write_text(content)
        result = subprocess.run(["git", "merge-file", "-p", *map(str, paths)],
                                capture_output=True, text=True, check=False)
        require(result.returncode >= 0, "merge process terminated")
        return result.stdout if result.returncode == 0 else None


def _bundle_files(bundle: Path) -> dict[str, str]:
    files = {}
    for source, prefix in ((bundle / "runtime", ".review/bin"),
                           (bundle / "schemas", ".review/schemas"),
                           (bundle / "templates/project", "")):
        require(source.is_dir(), f"bundle component missing: {source.name}")
        for path in sorted(source.rglob("*")):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "bundle symlinks are unsupported")
            if path.is_file():
                rel = "/".join(part for part in (prefix, path.relative_to(source).as_posix()) if part)
                files[rel] = path.read_text()
    skill = bundle / "skills/review-maintain/SKILL.md"
    if skill.is_file():
        files[".agents/skills/review-maintain/SKILL.md"] = skill.read_text()
    return files


def plan_install(target: Path, bundle: Path, config: Json) -> Json:
    cfg = validate_config(config)
    target, bundle = Path(target).absolute(), Path(bundle).resolve()
    require(target.is_dir(), "target directory does not exist")
    manifest_path = safe_target(target, ".review/manifest.json")
    previous = json.loads(_read(manifest_path) or '{"files":{}}')
    files = _bundle_files(bundle)
    files.update(render_workflows(cfg))
    files[".review/config.json"] = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    block = ("리뷰 체계의 첫 배포·인증 도입·마이그레이션·사고·모델 변경 시 "
             "`.agents/skills/review-maintain/SKILL.md`를 읽고 점검한다.\n"
             "PR 리뷰 기준은 `REVIEW.md`, 실행 정책과 검증 상태는 `.review/`에 있다.\n")
    pr_template = ".github/pull_request_template.md"
    managed = {"AGENTS.md": block}
    if pr_template in files:
        managed[pr_template] = files[pr_template]
    for relative, body in managed.items():
        base = previous.get("files", {}).get(relative, {}).get("base")
        local = _read(safe_target(target, relative)) or ""
        # The incoming side starts from the recorded baseline, including its block.
        # Local instructions inside and outside the block take the normal merge path.
        files[relative] = _managed(base if base is not None else local, body)
    writes, expected, conflicts, baselines = {}, {}, [], {}
    for relative, incoming in files.items():
        path = safe_target(target, relative)
        local = _read(path)
        base = previous.get("files", {}).get(relative, {}).get("base")
        expected[relative] = local
        baselines[relative] = {"base": incoming, "sha256": hashlib.sha256(incoming.encode()).hexdigest()}
        if relative in managed and base is None and START not in (local or ""):
            merged = incoming
        elif local is None or local == base or local == incoming:
            merged = incoming
        elif incoming == base:
            merged = local
        elif base is not None:
            merged = _merge(local, base, incoming)
        else:
            merged = None
        if merged is None:
            conflicts.append(relative)
        elif merged != local:
            writes[relative] = merged
    new_manifest = {"schema_version": 1, "template_version": __version__,
                    "source_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
                    "files": baselines}
    expected[".review/manifest.json"] = _read(manifest_path)
    writes[".review/manifest.json"] = json.dumps(new_manifest, ensure_ascii=False, indent=2) + "\n"
    return {"schema_version": 1, "target": str(target), "writes": writes, "expected": expected,
            "conflicts": conflicts, "incoming": {key: files[key] for key in conflicts}}


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".review-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_install(target: Path, proposal: Json) -> Json:
    target = Path(target).absolute()
    require(str(target) == proposal["target"], "proposal target mismatch")
    for relative, expected in proposal["expected"].items():
        require(_read(safe_target(target, relative)) == expected, f"stale install proposal: {relative}")
    if proposal["conflicts"]:
        for relative, content in proposal["incoming"].items():
            _atomic_write(safe_target(target, ".review/proposals/" + relative), content)
        return {"status": "needs_human", "conflicts": proposal["conflicts"], "written": []}
    applied = []
    try:
        for relative, content in proposal["writes"].items():
            _atomic_write(safe_target(target, relative), content)
            applied.append(relative)
    except OSError:
        for relative in reversed(applied):
            old = proposal["expected"][relative]
            path = safe_target(target, relative)
            if old is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, old)
        raise
    return {"status": "needs_verification", "written": applied, "conflicts": []}
