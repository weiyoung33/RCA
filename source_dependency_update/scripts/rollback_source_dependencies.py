"""Restore one install backup. Preview first; refuse to overwrite later edits."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    parser.add_argument("backup_directory", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    backup = args.backup_directory.resolve()
    entries = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
    for item in entries:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            parser.exit(2, "Invalid backup manifest path\n")
        path = root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item["installed_sha256"]:
            parser.exit(2, "Later edits or a missing file need review before rollback: " + str(relative) + "\n")
        if item["existed"] and not (backup / relative).is_file():
            parser.exit(2, "Required backup file is missing: " + str(relative) + "\n")
    for item in entries:
        print(("Restore " if item["existed"] else "Remove added file ") + item["path"])
    if not args.apply:
        print("Preview only. Add --apply to restore. Database records and incident data are not changed.")
        return
    for item in entries:
        path = root / item["path"]
        if item["existed"]:
            shutil.copy2(backup / item["path"], path)
        else:
            path.unlink()
    print("Source files restored. Restart the backend.")


if __name__ == "__main__":
    main()
