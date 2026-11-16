"""Export Git objects as data without checkout hooks, instruction discovery or history."""

import fnmatch
import hashlib
import json
import subprocess
from pathlib import Path

from .contracts import Json, hex_digest, relative_path, require

DEFAULT_EXCLUDED = [".review/evals/**", ".review/runs/**", ".env", ".env.*", "**/.env", "**/.env.*", "auth.json"]


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          check=True, timeout=30).stdout


def _entries(repo: Path, sha: str):
    for record in _git(repo, "ls-tree", "-rz", sha).split(b"\x00"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        path = relative_path(name.decode("utf-8"))
        yield mode, kind, oid, path


def _inert(path: str) -> bool:
    parts = Path(path).parts
    return (Path(path).name in {"AGENTS.md", "AGENTS.override.md", "REVIEW.md", "CLAUDE.md"}
            or any(part in {".agents", ".codex", ".claude", ".review"} for part in parts))


def prepare_workspace(repo: Path, base: str, head: str, dest: Path, excluded: list[str]) -> Json:
    hex_digest(base, "base", (40, 64))
    hex_digest(head, "head", (40, 64))
    repo, dest = Path(repo).resolve(), Path(dest).absolute()
    require(not dest.exists() and not dest.is_symlink(), "workspace destination must be new")
    for parent in dest.parents:
        require(not parent.is_symlink(), "workspace parent is a symlink")
    exclusions = DEFAULT_EXCLUDED + excluded
    selected, inert, total = {}, {}, 0
    for mode, kind, oid, path in _entries(repo, head):
        if any(fnmatch.fnmatchcase(path, rule) for rule in exclusions):
            continue
        require(mode in {"100644", "100755"} and kind == "blob", "symlinks and submodules require human review")
        data = _git(repo, "cat-file", "blob", oid)
        total += len(data)
        require(len(data) <= 5_000_000 and total <= 50_000_000, "snapshot exceeds supported size")
        key = "inert/" + hashlib.sha256(path.encode()).hexdigest() + ".txt" if _inert(path) else "source/" + path
        selected[key] = data
        if _inert(path):
            inert[path] = key
    trusted = {}
    for mode, kind, oid, path in _entries(repo, base):
        if path in {"REVIEW.md", ".review/config.json"} or path.startswith((".review/prompts/", ".review/schemas/")):
            require(mode in {"100644", "100755"} and kind == "blob", "unsafe trusted policy file")
            trusted[path] = _git(repo, "cat-file", "blob", oid)
    diff = _git(repo, "diff", "--no-ext-diff", "--no-textconv", base, head, "--", ".",
                *[":(exclude)" + pattern for pattern in exclusions])
    for relative, data in selected.items():
        path = dest / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for relative, data in trusted.items():
        path = dest / "policy" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    dest.mkdir(exist_ok=True)
    (dest / "change.diff").write_bytes(diff)
    manifest = {"base_sha": base, "head_sha": head, "inert_files": inert,
                "changed_paths": [p.decode() for p in _git(repo, "diff", "--name-only", "-z", base, head).split(b"\x00") if p],
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in selected.items()},
                "rules": {name: hashlib.sha256(data).hexdigest() for name, data in trusted.items()},
                "diff_digest": hashlib.sha256(diff).hexdigest()}
    (dest / "input-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest
