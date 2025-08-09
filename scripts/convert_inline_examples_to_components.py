#!/usr/bin/env python3
"""
Convert inline example code blocks in MDX (```json with leading "// Example ...")
into sidebar components by removing the inline blocks. After running this, use
`scripts/add_examples_to_mdx.py` to insert <RequestExample>/<ResponseExample>
based on OpenAPI examples if missing.

What it removes:
  ```json
  // Example body|request|response
  { ... }
  ```

Usage:
  python scripts/convert_inline_examples_to_components.py --root /abs/path [--apply] [--backup]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Optional, Sequence


API_DIR = "api-reference"


INLINE_EXAMPLE_RE = re.compile(
    r"```json\s*\n\s*//\s*Example\s*(body|request|response)[\s\S]*?\n```",
    re.IGNORECASE,
)


def process_text(text: str) -> str:
    return re.sub(INLINE_EXAMPLE_RE, "", text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Remove inline example code blocks from MDX.")
    parser.add_argument("--root", type=str, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    mdx_root = root / API_DIR
    updated = []
    for mdx in mdx_root.rglob("*.mdx"):
        text = mdx.read_text(encoding="utf-8")
        new_text = process_text(text)
        if new_text != text:
            updated.append(mdx)
            if args.apply:
                if args.backup:
                    (mdx.with_suffix(mdx.suffix + ".bak.inline-removed")).write_text(text, encoding="utf-8")
                mdx.write_text(new_text, encoding="utf-8")

    if args.apply:
        print(f"Updated {len(updated)} files:")
    else:
        print(f"[Dry-run] Would update {len(updated)} files:")
    for p in updated:
        print(f" - {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

