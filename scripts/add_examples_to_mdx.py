#!/usr/bin/env python3
"""
Insert RequestExample / ResponseExample blocks into MDX API pages using examples
from their referenced OpenAPI operations.

- Detect `openapi: openapi-spec method path` in MDX frontmatter
- Load the OpenAPI file, find the operation, and extract:
  - Request JSON example (requestBody→application/json→example or synthesized)
  - Response JSON example (200/2xx→application/json→example or synthesized)
- If the MDX does not already have <RequestExample> or <ResponseExample>, append
  them at the end of the page.

Usage:
  python scripts/add_examples_to_mdx.py --root /absolute/path/to/docs [--apply] [--backup]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple


SPEC_DIR = "openapi-specs"
API_DIR = "api-reference"


FRONTMATTER_RE = re.compile(r"^---\n([\s\S]*?)\n---\n")
OPENAPI_REF_RE = re.compile(r"^openapi:\s*\"?([^\"]+)\s+([A-Z]+)\s+([^\"]+)\"?\s*$", re.MULTILINE)


def synthesize_example_from_schema(schema: Dict) -> Dict:
    props = schema.get("properties", {})
    example: Dict = {}
    for key, prop in props.items():
        if not isinstance(prop, dict):
            continue
        if "example" in prop:
            example[key] = prop["example"]
            continue
        t = prop.get("type")
        if t == "string":
            example[key] = key
        elif t == "number":
            example[key] = 0
        elif t == "integer":
            example[key] = 0
        elif t == "boolean":
            example[key] = False
        elif t == "array":
            example[key] = []
        elif t == "object":
            example[key] = {}
    return example


def resolve_ref(spec: Dict, ref: str) -> Optional[Dict]:
    if not ref.startswith("#/components/"):
        return None
    parts = ref.lstrip("#/").split("/")
    node: Dict = spec
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            return None
        node = node[p]  # type: ignore
    return node if isinstance(node, dict) else None


def get_operation(spec: Dict, method: str, path: str) -> Optional[Dict]:
    paths = spec.get("paths", {})
    op = paths.get(path, {})
    if not isinstance(op, dict):
        return None
    return op.get(method.lower())


def extract_request_example(spec: Dict, op: Dict) -> Optional[Dict]:
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return None
    content = rb.get("content")
    if not isinstance(content, dict):
        return None
    json_ct = content.get("application/json")
    if not isinstance(json_ct, dict):
        return None
    if "example" in json_ct:
        return json_ct["example"]
    schema = json_ct.get("schema")
    if isinstance(schema, dict) and "$ref" in schema:
        target = resolve_ref(spec, schema["$ref"]) or {}
        return synthesize_example_from_schema(target)
    if isinstance(schema, dict):
        return synthesize_example_from_schema(schema)
    return None


def extract_response_example(spec: Dict, op: Dict) -> Optional[Dict]:
    res = op.get("responses")
    if not isinstance(res, dict):
        return None
    # Prefer 200, else first 2xx key
    keys = ["200"] + [k for k in res.keys() if re.match(r"2\\d\\d", k) and k != "200"]
    for k in keys:
        r = res.get(k)
        if not isinstance(r, dict):
            continue
        content = r.get("content")
        if not isinstance(content, dict):
            continue
        json_ct = content.get("application/json")
        if not isinstance(json_ct, dict):
            continue
        if "example" in json_ct:
            return json_ct["example"]
        schema = json_ct.get("schema")
        if isinstance(schema, dict) and "$ref" in schema:
            target = resolve_ref(spec, schema["$ref"]) or {}
            return synthesize_example_from_schema(target)
        if isinstance(schema, dict):
            return synthesize_example_from_schema(schema)
    return None


def has_component(text: str, tag: str) -> bool:
    return f"<{tag}>" in text


def append_examples(text: str, request_example: Optional[Dict], response_example: Optional[Dict]) -> str:
    blocks: list[str] = []
    if request_example is not None and not has_component(text, "RequestExample"):
        blocks.append("<RequestExample>\n\n" +
                      "```json Request Body\n" +
                      json.dumps(request_example, indent=2) +
                      "\n```\n\n</RequestExample>\n")
    if response_example is not None and not has_component(text, "ResponseExample"):
        blocks.append("<ResponseExample>\n\n" +
                      "```json Response\n" +
                      json.dumps(response_example, indent=2) +
                      "\n```\n\n</ResponseExample>\n")
    if not blocks:
        return text
    sep = "\n\n" if text.endswith("\n") else "\n\n"
    return text + sep + "\n\n".join(blocks)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Insert RequestExample/ResponseExample blocks into MDX based on OpenAPI examples.")
    parser.add_argument("--root", type=str, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    mdx_root = root / API_DIR

    updated = []
    for mdx_path in mdx_root.rglob("*.mdx"):
        text = mdx_path.read_text(encoding="utf-8")
        m = FRONTMATTER_RE.search(text)
        if not m:
            continue
        fm_text = m.group(1)
        ref = OPENAPI_REF_RE.search(fm_text)
        if not ref:
            continue
        spec_file, method, path = ref.groups()
        # Resolve spec path
        spec_path = (root / spec_file) if spec_file.startswith("openapi-specs/") else (root / (spec_file.lstrip("/")))
        if not spec_path.exists():
            spec_path = root / SPEC_DIR / Path(spec_file).name
        if not spec_path.exists():
            continue
        try:
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        op = get_operation(spec, method, path)
        if not isinstance(op, dict):
            continue
        req_ex = extract_request_example(spec, op)
        res_ex = extract_response_example(spec, op)

        new_text = append_examples(text, req_ex, res_ex)
        if new_text != text:
            updated.append(mdx_path)
            if args.apply:
                if args.backup:
                    (mdx_path.with_suffix(mdx_path.suffix + ".bak")).write_text(text, encoding="utf-8")
                mdx_path.write_text(new_text, encoding="utf-8")

    if args.apply:
        print(f"Updated {len(updated)} files:")
    else:
        print(f"[Dry-run] Would update {len(updated)} files:")
    for p in updated:
        print(f" - {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

