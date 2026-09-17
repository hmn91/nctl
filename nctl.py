"""PyInstaller/standalone entry point for nctl."""

from nctl.app import main


if __name__ == "__main__":
    raise SystemExit(main())
