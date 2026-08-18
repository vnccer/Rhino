"""Stop the demo stack and delete its local PostgreSQL data volume."""

import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    subprocess.run(
        ["docker", "compose", "down", "--volumes", "--remove-orphans"],
        cwd=REPOSITORY_ROOT,
        check=True,
    )
    print("Demo containers and local database volume removed.")


if __name__ == "__main__":
    main()
