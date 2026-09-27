#!/usr/bin/env python3
"""Compatibility entrypoint for bounded services observation."""


def main() -> int:
    from eye_for_an_eye.cli import main as run
    return run(command="services")


if __name__ == "__main__":
    raise SystemExit(main())
