import os
from pathlib import Path
import subprocess
import sys
import venv


def main() -> None:
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or later is required.")
    root = Path(__file__).resolve().parent
    env = root / ".venv"
    venv.EnvBuilder(with_pip=True).create(env)
    python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "-e", ".[test]"], cwd=root, check=True)
    print("Ready. Run the commands in README.md.")


if __name__ == "__main__":
    main()
