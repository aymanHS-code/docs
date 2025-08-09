#!/usr/bin/env python3
"""
Generate a simple per-field request UI (inputs) for endpoints with application/json
request bodies, and inject it into MDX pages that reference those operations.

The UI renders a form, assembles JSON from the schema's top-level properties,
and sends the request directly to the OpenAPI server + path using fetch.

Notes:
- Only handles top-level scalar properties (string/number/integer/boolean).
  For objects/arrays or nested schemas, a JSON textarea is provided for manual input.
- Idempotent: skips pages that already include a GeneratedFieldsUI marker.

Usage:
  python scripts/generate_fields_ui.py --root /absolute/path --apply [--backup]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple


SPEC_DIR = "openapi-specs"
API_DIR = "api-reference"


FRONTMATTER_RE = re.compile(r"^---\n([\s\S]*?)\n---\n")
OPENAPI_REF_RE = re.compile(r"^openapi:\s*\"?([^\"]+)\s+([A-Z]+)\s+([^\"]+)\"?\s*$", re.MULTILINE)


def parse_frontmatter(text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    m = FRONTMATTER_RE.search(text)
    if not m:
        return None, None, None
    fm = m.group(1)
    m2 = re.search(r"^openapi:\s*\"?([^\"]+)\s+([A-Z]+)\s+([^\"]+)\"?\s*$", fm, re.MULTILINE)
    if not m2:
        return None, None, None
    return m2.group(1), m2.group(2).upper(), m2.group(3)


def resolve_ref(spec: Dict, ref: str) -> Optional[Dict]:
    if not ref.startswith("#/components/"):
        return None
    node: Dict = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]  # type: ignore
    return node if isinstance(node, dict) else None


def get_operation(spec: Dict, method: str, path: str) -> Optional[Dict]:
    paths = spec.get("paths", {})
    methods = paths.get(path)
    if not isinstance(methods, dict):
        return None
    op = methods.get(method.lower())
    return op if isinstance(op, dict) else None


def pick_server(spec: Dict) -> Optional[str]:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url") if isinstance(servers[0], dict) else None
        if isinstance(url, str) and url:
            return url.rstrip("/")
    return None


def extract_request_schema(spec: Dict, op: Dict) -> Optional[Dict]:
    rb = op.get("requestBody")
    if not isinstance(rb, dict):
        return None
    content = rb.get("content")
    if not isinstance(content, dict):
        return None
    json_ct = content.get("application/json")
    if not isinstance(json_ct, dict):
        return None
    schema = json_ct.get("schema")
    if isinstance(schema, dict) and "$ref" in schema:
        return resolve_ref(spec, schema["$ref"]) or {}
    return schema if isinstance(schema, dict) else None


def build_fields_html(schema: Dict, required: Iterable[str]) -> Tuple[str, str]:
    # Returns (inputs_html, body_builder_js)
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    inputs = []
    build_lines = ["const body = {};"]
    for name, prop in props.items():
        if not isinstance(prop, dict):
            continue
        typ = prop.get("type")
        is_req = name in set(required or [])
        example = prop.get("example")
        placeholder = example if isinstance(example, (str, int, float)) else name
        input_id = f"fld_{name}"
        if typ in ("string", "number", "integer"):
            input_type = "number" if typ in ("number", "integer") else "text"
            inputs.append(f'<label style="display:block;margin:6px 0 2px">{name} {"*" if is_req else ""}</label>'
                         f'<input id="{input_id}" type="{input_type}" placeholder="{placeholder}"'
                         f' style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px">')
            cast = "Number" if typ in ("number", "integer") else "String"
            build_lines.append(f'{{ const v = document.getElementById("{input_id}").value;'
                               f' if(v!=="" || {str(is_req).lower()}) body["{name}"] = ({cast})(v); }}')
        elif typ == "boolean":
            inputs.append(f'<label style="display:block;margin:6px 0 2px">{name} {"*" if is_req else ""}</label>'
                         f'<select id="{input_id}" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px">'
                         f'<option value="true">true</option><option value="false">false</option></select>')
            build_lines.append(f'{{ const v = document.getElementById("{input_id}").value; body["{name}"] = (v === "true"); }}')
        else:
            # Fallback JSON textarea
            t_id = f"fld_{name}_json"
            inputs.append(f'<label style="display:block;margin:6px 0 2px">{name} (JSON)</label>'
                         f'<textarea id="{t_id}" rows="4" placeholder="{{}}"'
                         f' style="width:100%;padding:8px;border:1px solid #ddd;border-radius:6px"></textarea>')
            build_lines.append(
                f'{{ const v = document.getElementById("{t_id}").value.trim(); if(v){{ try{{ body["{name}"] = JSON.parse(v) }}catch(e){{ console.warn("Invalid JSON for {name}") }} }} }}'
            )
    return "\n".join(inputs), "\n".join(build_lines)


def build_form_block(server_url: str, path: str, method: str, schema: Dict) -> str:
    required = schema.get("required", []) if isinstance(schema, dict) else []
    inputs_html, body_builder_js = build_fields_html(schema, required)
    uid = (method + path).replace("/", "_").replace("{", "").replace("}", "").lower()
    action_url = server_url.rstrip("/") + path
    block = f"""
<!-- GeneratedFieldsUI:{uid} -->
<Panel>
  <div id="form-{uid}">
    <form id="f-{uid}" style="display:block;max-width:720px">
      {inputs_html}
      <div style="margin-top:12px;display:flex;gap:8px">
        <button type="submit" style="padding:8px 12px;border:1px solid #0ea5e9;border-radius:6px;background:#0ea5e9;color:#fff">Send</button>
        <button type="button" id="reset-{uid}" style="padding:8px 12px;border:1px solid #ddd;border-radius:6px;background:#fff">Reset</button>
      </div>
    </form>
    <pre id="resp-{uid}" style="margin-top:12px;background:#0b1020; color:#e2e8f0; padding:12px;border-radius:8px;overflow:auto"></pre>
  </div>
</Panel>

<script>
(function(){{
  const form = document.getElementById('f-{uid}');
  const out = document.getElementById('resp-{uid}');
  const resetBtn = document.getElementById('reset-{uid}');
  if(!form||!out) return;
  resetBtn && resetBtn.addEventListener('click', ()=>{{ form.reset(); out.textContent=''; }});
  form.addEventListener('submit', async (e)=>{{
    e.preventDefault();
    try {{
      {body_builder_js}
      const res = await fetch('{action_url}', {{
        method: '{method}',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const text = await res.text();
      try {{ out.textContent = JSON.stringify(JSON.parse(text), null, 2); }} catch {{ out.textContent = text; }}
    }} catch(err) {{
      out.textContent = String(err);
    }}
  }});
}})();
</script>
"""
    return block


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate per-field request UIs for JSON bodies and inject into MDX.")
    parser.add_argument("--root", type=str, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    updated = []
    for mdx in (root / API_DIR).rglob("*.mdx"):
        text = mdx.read_text(encoding="utf-8")
        spec_ref, method, path = parse_frontmatter(text)
        if not spec_ref:
            continue
        # Resolve spec path
        spec_path = (root / spec_ref) if not spec_ref.startswith("/") else (root / spec_ref.lstrip("/"))
        if not spec_path.exists():
            alt = root / SPEC_DIR / Path(spec_ref).name
            if alt.exists():
                spec_path = alt
            else:
                continue
        try:
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        op = get_operation(spec, method or "", path or "")
        if not op:
            continue
        schema = extract_request_schema(spec, op)
        if not schema:
            continue
        server = pick_server(spec)
        if not server:
            continue
        uid = (method + path).replace("/", "_").replace("{", "").replace("}", "").lower()
        marker = f"<!-- GeneratedFieldsUI:{uid} -->"
        if marker in text:
            continue
        block = build_form_block(server, path, method, schema)
        new_text = text + ("\n\n" if not text.endswith("\n") else "\n") + block
        updated.append(mdx)
        if args.apply:
            if args.backup:
                (mdx.with_suffix(mdx.suffix + ".bak.fields-ui")).write_text(text, encoding="utf-8")
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

