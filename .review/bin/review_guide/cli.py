"""Small CLI shared by installed projects and CI."""

import argparse
import json
import sys
from pathlib import Path

from .contracts import ValidationError, validate_config
from .install import apply_install, plan_install
from .codex import build_request, normalize_action, normalize_result, run_codex
from .lifecycle import advance


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reviewctl", description="Project-owned AI review tools")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a project configuration")
    validate.add_argument("--config", type=Path, required=True)
    install = sub.add_parser("install", help="install or propose an update, preserving user edits")
    install.add_argument("--target", type=Path, required=True)
    install.add_argument("--config", type=Path, required=True)
    install.add_argument("--bundle", type=Path, default=Path(__file__).resolve().parents[2])
    mode = install.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    for command in ("request", "run-codex"):
        worker = sub.add_parser(command, help="prepare a gated model request" if command == "request" else "execute the subscription runtime")
        worker.add_argument("--config", type=Path, required=True)
        worker.add_argument("--run", type=Path, required=True)
        worker.add_argument("--workspace", type=Path, required=True)
        worker.add_argument("--output", type=Path, required=True)
        if command == "run-codex":
            worker.add_argument("--executable", type=Path, required=True)
    normalize = sub.add_parser("normalize", help="normalize a Codex JSONL or Action result")
    normalize.add_argument("--raw", type=Path, required=True)
    normalize.add_argument("--output", type=Path, required=True)
    normalize.add_argument("--action-outcome", choices=["success", "failure", "cancelled", "skipped"])
    normalize.add_argument("--exit-code", type=int, default=0)
    transition = sub.add_parser("advance", help="advance a trusted run with one event")
    for name in ("config", "state", "event", "output"):
        transition.add_argument("--" + name, type=Path, required=True)
    ci = sub.add_parser("ci", help="protected workflow controller; not a worker API")
    ci.add_argument("operation", choices=["entry", "tests", "inspect", "prepare-worker", "worker", "ssh-worker", "normalize-worker", "collect", "finish", "approval", "fetch-artifact", "eval-entry", "eval-self-hosted", "eval-request", "eval-normalize", "eval-record"])
    ci.add_argument("--name")
    ci.add_argument("--destination", type=Path)
    serve = sub.add_parser("serve", help="restricted SSH forced-command worker")
    serve.add_argument("--server-config", type=Path, required=True)
    from .knowledge_cli import register, execute
    register(sub)
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            import os
            import signal
            from .ssh_worker import serve_request, MAX_ARCHIVE
            from .contracts import require
            require(not os.environ.get('SSH_ORIGINAL_COMMAND'), 'SSH commands are not accepted')
            def interrupted(signum, frame):
                raise InterruptedError('worker connection interrupted')
            for sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, interrupted)
            result = serve_request(sys.stdin.buffer.read(MAX_ARCHIVE+1), json.loads(args.server_config.read_text()))
        elif args.command in {"case", "eval"}:
            result = execute(args)
        elif args.command == "validate":
            result = validate_config(json.loads(args.config.read_text()))
        elif args.command == "install":
            proposal = plan_install(args.target, args.bundle, json.loads(args.config.read_text()))
            result = apply_install(args.target, proposal) if args.apply else proposal
        elif args.command in {"request", "run-codex"}:
            cfg, run = json.loads(args.config.read_text()), json.loads(args.run.read_text())
            request = build_request(run["role"], run, args.workspace, cfg)
            if args.command == "request":
                args.output.mkdir(parents=True, exist_ok=True)
                (args.output / "prompt.md").write_text(request["prompt"])
                public = {key: value for key, value in request.items() if key not in {"gate", "prompt", "argv"}}
                (args.output / "request.json").write_text(json.dumps(public, ensure_ascii=False, indent=2) + "\n")
                result = {"status": "prepared", "prompt_file": str(args.output / "prompt.md"), **public}
            else:
                result = run_codex(request, args.executable, request["timeout_s"])
                args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        elif args.command == "normalize":
            raw = args.raw.read_text() if args.raw.is_file() else ""
            result = (normalize_action(raw, args.action_outcome) if args.action_outcome
                      else normalize_result(raw, args.exit_code, False))
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        elif args.command == "advance":
            result = advance(json.loads(args.state.read_text()), json.loads(args.event.read_text()),
                             json.loads(args.config.read_text()))
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        elif args.command == "ci":
            from .pipeline import ci_main
            result = ci_main(args.operation, args.name, args.destination)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"reviewctl: {exc}", file=sys.stderr)
        return 2
