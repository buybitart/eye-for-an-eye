#!/usr/bin/env python3
"""LAB ONLY / NOT FOR PUBLIC DEPLOYMENT. Deprecated, finite loopback experiment."""


def main() -> int:
    from eye_for_an_eye.cli import main as run
    return run(command="garbage")


if __name__ == "__main__":
    raise SystemExit(main())
