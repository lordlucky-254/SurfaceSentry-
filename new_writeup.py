#!/usr/bin/env python3
"""Create a new CTF/lab write-up from the template."""
import argparse
import datetime
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "ctf-writeups" / "_template.md"
INDEX = ROOT / "ctf-writeups" / "README.md"


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("title")
    p.add_argument("--platform", default="Other")
    p.add_argument("--difficulty", default="Unknown")
    a = p.parse_args()

    today = datetime.date.today().isoformat()
    slug = slugify(a.title)
    out_dir = ROOT / "ctf-writeups" / a.platform.lower()
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{slug}.md"
    if out.exists():
        raise SystemExit(f"Already exists: {out}")

    content = TEMPLATE.read_text(encoding="utf-8")
    for key, value in {
        "{title}": a.title,
        "{platform}": a.platform,
        "{difficulty}": a.difficulty,
        "{date}": today,
    }.items():
        content = content.replace(key, value)
    out.write_text(content, encoding="utf-8")

    rel = out.relative_to(ROOT / "ctf-writeups")
    row = f"| {today} | [{a.title}]({rel.as_posix()}) | {a.platform} | {a.difficulty} | |"
    lines = INDEX.read_text(encoding="utf-8").splitlines()
    # Insert after the last table row so the Markdown table stays intact
    last_row = max(i for i, line in enumerate(lines) if line.startswith("|"))
    lines.insert(last_row + 1, row)
    INDEX.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Created {out}")


if __name__ == "__main__":
    main()
