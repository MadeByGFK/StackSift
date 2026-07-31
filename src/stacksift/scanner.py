from pathlib import Path


def find_log_files(path: Path) -> list[Path]:
    if path.is_file() and path.suffix == ".log":
        return [path]

    if path.is_dir():
        return sorted(path.rglob("*.log"))

    return []