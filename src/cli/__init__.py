"""Command line entry point for the deobfuscation helpers."""

from __future__ import annotations

import argparse
from .. import sandbox_runner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Luraph helper CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_capture = sub.add_parser("capture", help="Run sandbox capture pipeline")
    run_capture.add_argument("--init", required=True)
    run_capture.add_argument("--json", required=True)
    run_capture.add_argument("--key", required=True)
    run_capture.add_argument("--out", default="out")
    run_capture.add_argument("--timeout", type=int, default=12)
    run_capture.add_argument("--run-lifter", action="store_true")
    run_capture.add_argument("--detect-protections", action="store_true")
    run_capture.add_argument("--capture-runtime", choices=["frida", "luajit", "emulator"], default=None)
    run_capture.add_argument("--capture-timeout", type=int, default=10)
    run_capture.add_argument("--capture-output", default=None)
    run_capture.add_argument("--capture-target", default=None)

    args = parser.parse_args(argv)

    if args.command == "capture":
        runner_args = [
            "--init",
            args.init,
            "--json",
            args.json,
            "--key",
            args.key,
            "--out",
            args.out,
            "--timeout",
            str(args.timeout),
        ]
        if args.run_lifter:
            runner_args.append("--run-lifter")
        if args.detect_protections:
            runner_args.append("--detect-protections")
        if args.capture_runtime:
            runner_args.extend(["--capture-runtime", args.capture_runtime])
        if args.capture_output:
            runner_args.extend(["--capture-output", args.capture_output])
        if args.capture_timeout is not None:
            runner_args.extend(["--capture-timeout", str(args.capture_timeout)])
        if args.capture_target:
            runner_args.extend(["--capture-target", args.capture_target])
        return sandbox_runner.main(runner_args)

    parser.error("Unhandled command")
    return 2


if __name__ == "__main__":  # pragma: no cover - CLI wrapper
    raise SystemExit(main())
