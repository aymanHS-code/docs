#!/usr/bin/env python3
"""
Convert custom MDX <Table> components under specific headings ("## Headers" and
"## Path Parameters") into standard Markdown tables across all .mdx files.

Usage (dry-run by default):
  python scripts/convert_tables.py --root /absolute/path/to/docs

Apply changes in-place:
  python scripts/convert_tables.py --root /absolute/path/to/docs --apply

You can limit the scope via a glob:
  python scripts/convert_tables.py --root /abs/path --glob "api-reference/**/*.mdx" --apply
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


TABLE_BLOCK_RE = re.compile(r"<Table>[\s\S]*?</Table>", re.MULTILINE)
TABLE_HEAD_RE = re.compile(r"<Table\.Head>([\s\S]*?)</Table\.Head>", re.MULTILINE)
TABLE_BODY_RE = re.compile(r"<Table\.Body>([\s\S]*?)</Table\.Body>", re.MULTILINE)
HEADER_CELL_RE = re.compile(r"<Table\.Header>\s*([\s\S]*?)\s*</Table\.Header>")
ROW_RE = re.compile(r"<Table\.Row>([\s\S]*?)</Table\.Row>", re.MULTILINE)
CELL_RE = re.compile(r"<Table\.Cell>\s*([\s\S]*?)\s*</Table\.Cell>")


HEADING_RE_TEMPLATE = r"(^|\n)##\s+{heading}\s*\n"


@dataclass
class ParsedTable:
    headers: List[str]
    rows: List[List[str]]


def sanitize_cell_text(text: str) -> str:
    """Return cell text trimmed; leave MD/MDX syntax as-is.

    Also collapse internal newlines to spaces to avoid breaking Markdown table rows.
    """
    cleaned = text.strip()
    cleaned = re.sub(r"\s*\n\s*", " ", cleaned)
    return cleaned


def parse_table_block(table_block: str) -> Optional[ParsedTable]:
    head_match = TABLE_HEAD_RE.search(table_block)
    body_match = TABLE_BODY_RE.search(table_block)
    if not head_match or not body_match:
        return None

    head_html = head_match.group(1)
    body_html = body_match.group(1)

    headers = [sanitize_cell_text(h) for h in HEADER_CELL_RE.findall(head_html)]

    rows: List[List[str]] = []
    for row_html in ROW_RE.findall(body_html):
        cells = [sanitize_cell_text(c) for c in CELL_RE.findall(row_html)]
        if cells:
            rows.append(cells)

    if not headers:
        return None

    return ParsedTable(headers=headers, rows=rows)


def build_markdown_table(parsed: ParsedTable) -> str:
    header_row = "| " + " | ".join(parsed.headers) + " |"
    separator_row = "| " + " | ".join(["---"] * len(parsed.headers)) + " |"
    body_rows = []
    for row in parsed.rows:
        # Pad or truncate to header length to avoid malformed tables
        adjusted = (row + [""] * len(parsed.headers))[: len(parsed.headers)]
        body_rows.append("| " + " | ".join(adjusted) + " |")
    markdown = "\n".join([header_row, separator_row] + body_rows)
    return markdown


def find_section_bounds(content: str, section_heading: str) -> List[Tuple[int, int]]:
    """Find (start, end) indices for sections by heading until the next level-2 heading or EOF."""
    pattern = re.compile(HEADING_RE_TEMPLATE.format(heading=re.escape(section_heading)), re.MULTILINE)
    bounds: List[Tuple[int, int]] = []

    for match in pattern.finditer(content):
        start = match.end()
        # Next heading
        next_heading = re.search(r"\n##\s+", content[start:], re.MULTILINE)
        end = start + (next_heading.start() if next_heading else len(content) - start)
        bounds.append((start, end))
    return bounds


def convert_first_table_in_section(section_text: str) -> Tuple[str, bool]:
    """Replace the first <Table>...</Table> in a section with a Markdown table, if found."""
    table_match = TABLE_BLOCK_RE.search(section_text)
    if not table_match:
        return section_text, False

    table_block = table_match.group(0)
    parsed = parse_table_block(table_block)
    if not parsed:
        return section_text, False

    markdown_table = build_markdown_table(parsed)

    # Ensure blank lines around the table for proper rendering
    replacement = f"\n{markdown_table}\n"
    new_section = section_text[: table_match.start()] + replacement + section_text[table_match.end() :]
    return new_section, True


def convert_content(content: str, headings: Sequence[str]) -> Tuple[str, bool]:
    changed = False
    new_content = content

    # Work from the end to preserve indices when replacing substrings by keeping earlier indices stable
    for heading in headings:
        bounds = find_section_bounds(new_content, heading)
        # Process in reverse order to not invalidate subsequent indices
        for start, end in reversed(bounds):
            section = new_content[start:end]
            converted, did_change = convert_first_table_in_section(section)
            if did_change:
                new_content = new_content[:start] + converted + new_content[end:]
                changed = True
    return new_content, changed


def iter_files(root: Path, glob: Optional[str]) -> Iterable[Path]:
    if glob:
        yield from root.glob(glob)
    else:
        yield from root.rglob("*.mdx")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert MDX <Table> blocks under specific headings to Markdown tables.")
    parser.add_argument("--root", type=str, required=True, help="Absolute path to repository/docs root to scan.")
    parser.add_argument("--glob", type=str, default=None, help="Optional glob relative to root to restrict files, e.g. 'api-reference/**/*.mdx'.")
    parser.add_argument("--apply", action="store_true", help="Write changes in-place. If omitted, runs as dry-run.")
    parser.add_argument("--backup", action="store_true", help="Write .bak backups when applying changes.")
    args = parser.parse_args(argv)

    root_path = Path(args.root).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        print(f"Root path does not exist or is not a directory: {root_path}", file=sys.stderr)
        return 2

    headings = ["Headers", "Path Parameters"]

    changed_files: List[Path] = []
    examined = 0
    for file_path in iter_files(root_path, args.glob):
        if not file_path.is_file() or file_path.suffix.lower() != ".mdx":
            continue
        examined += 1
        original = file_path.read_text(encoding="utf-8")
        converted, did_change = convert_content(original, headings)
        if did_change and converted != original:
            changed_files.append(file_path)
            if args.apply:
                if args.backup:
                    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
                    backup_path.write_text(original, encoding="utf-8")
                file_path.write_text(converted, encoding="utf-8")

    if args.apply:
        print(f"Examined {examined} files. Updated {len(changed_files)} files:")
    else:
        print(f"[Dry-run] Examined {examined} files. Would update {len(changed_files)} files:")

    for p in changed_files:
        print(f" - {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

