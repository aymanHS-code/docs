#!/usr/bin/env python3
"""
Normalize OpenAPI specs for Mintlify API Playground and add x-mint metadata.
Also augment MDX pages to reference OpenAPI operations in frontmatter so the
interactive playground renders with parameters and headers.

What it does:
  - Ensure each spec has a 'servers' array (adds default based on spec name)
  - Add reusable header parameters ('x-unit-id', 'x-user-id') into components.parameters
  - For target specs (Devices, Services), ensure every operation includes the
    required header parameters unless already present
  - Inject "x-mint.metadata" per operation using summary/description when missing
  - Update MDX frontmatter to add `openapi: "<spec-file> <METHOD> <PATH>"` when
    the operation can be matched (exact path or '/v1' to '/api' mapping)

Usage (dry-run by default):
  python scripts/update_openapi_and_mdx.py --root /absolute/path/to/docs

Apply changes:
  python scripts/update_openapi_and_mdx.py --root /absolute/path/to/docs --apply --backup
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


SPEC_DIR = "openapi-specs"
MDX_DIR = "api-reference"


DEFAULT_SERVER_BY_SPEC_TITLE: Dict[str, str] = {
    "Roomi AI": "https://ai-{env}-ae.roomi-services.com",
    "Roomi Auth": "https://auth-{env}-ae.roomi-services.com",
    "Roomi Devices": "https://devices-{env}-ae.roomi-services.com",
    "Roomi Services": "https://services-{env}-ae.roomi-services.com",
    "Roomi Logger": "https://logger-{env}-ae.roomi-services.com",
    "Roomi Handler": "https://handler-{env}-ae.roomi-services.com",
}


TARGET_SPECS_REQUIRE_UNIT_HEADERS = {
    "Roomi Devices.json",
    "Roomi Services.json",
}


X_UNIT_HEADER_PARAM = {
    "name": "x-unit-id",
    "in": "header",
    "description": "Unit identifier",
    "required": True,
    "schema": {"type": "string"},
    "example": "unit-12345",
}

X_USER_HEADER_PARAM = {
    "name": "x-user-id",
    "in": "header",
    "description": "User identifier",
    "required": True,
    "schema": {"type": "string"},
    "example": "user-67890",
}


def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Dict) -> None:
    # Write compact but stable JSON
    path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def ensure_servers(spec: Dict, spec_file: Path) -> bool:
    changed = False
    if "servers" not in spec or not isinstance(spec["servers"], list) or len(spec["servers"]) == 0:
        title = spec.get("info", {}).get("title")
        default_url = DEFAULT_SERVER_BY_SPEC_TITLE.get(title)
        if default_url:
            spec["servers"] = [{"url": default_url}]
            changed = True
    return changed


def ensure_components_parameters(spec: Dict) -> bool:
    changed = False
    components = spec.setdefault("components", {})
    parameters = components.setdefault("parameters", {})
    if "XUnitIdHeader" not in parameters:
        parameters["XUnitIdHeader"] = X_UNIT_HEADER_PARAM
        changed = True
    if "XUserIdHeader" not in parameters:
        parameters["XUserIdHeader"] = X_USER_HEADER_PARAM
        changed = True
    return changed


def iter_operations(spec: Dict) -> Iterable[Tuple[str, str, Dict]]:
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"} and isinstance(op, dict):
                yield path, method.upper(), op


def ensure_unit_user_headers_on_ops(spec: Dict, spec_filename: str) -> bool:
    if spec_filename not in TARGET_SPECS_REQUIRE_UNIT_HEADERS:
        return False
    changed = False
    for _path, _method, op in iter_operations(spec):
        params: List[Dict] = op.setdefault("parameters", [])
        header_names = {p.get("name") for p in params if p.get("in") == "header"}
        # Add via $ref so they remain DRY
        if "x-unit-id" not in header_names:
            params.append({"$ref": "#/components/parameters/XUnitIdHeader"})
            changed = True
        if "x-user-id" not in header_names:
            params.append({"$ref": "#/components/parameters/XUserIdHeader"})
            changed = True
    return changed


def ensure_x_mint_metadata(spec: Dict) -> bool:
    changed = False
    for _path, _method, op in iter_operations(spec):
        x_mint = op.setdefault("x-mint", {})
        metadata = x_mint.setdefault("metadata", {})
        if "title" not in metadata:
            summary = op.get("summary") or ""
            if summary:
                metadata["title"] = summary
                changed = True
        if "description" not in metadata:
            desc = op.get("description") or ""
            if desc:
                metadata["description"] = desc
                changed = True
    return changed


API_FIELD_RE = re.compile(r"^api:\s*\"?([A-Z]+)\s+([^\"]+)\"?\s*$", re.IGNORECASE)


def parse_frontmatter(mdx_text: str) -> Tuple[int, int, Dict[str, str]]:
    if not mdx_text.startswith("---\n"):
        return -1, -1, {}
    end = mdx_text.find("\n---\n", 4)
    if end == -1:
        return -1, -1, {}
    fm_text = mdx_text[4:end]
    fm: Dict[str, str] = {}
    for line in fm_text.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            fm[key.strip()] = val.strip().strip('"')
    return 0, end + 5, fm


def build_frontmatter_text(fm: Dict[str, str]) -> str:
    lines = ["---"]
    for key, val in fm.items():
        # Quote values that contain spaces or slashes for safety
        if any(ch in val for ch in [" ", "/"]):
            lines.append(f"{key}: \"{val}\"")
        else:
            lines.append(f"{key}: {val}")
    lines.append("---\n")
    return "\n".join(lines)


def normalize_mdx_openapi_reference(root: Path, specs: Dict[str, Dict], apply: bool) -> List[Path]:
    mdx_root = root / MDX_DIR
    if not mdx_root.exists():
        return []

    # Build a map from (method, path) to (spec_file)
    path_index: Dict[Tuple[str, str], str] = {}
    for spec_file, spec in specs.items():
        for path, method, _op in iter_operations(spec):
            path_index[(method, path)] = spec_file

    # Heuristic preferences based on MDX subfolder → target spec
    folder_to_spec = {
        "devices": "Roomi Devices.json",
        "services": "Roomi Services.json",
        "auth": "Roomi Auth.json",
        "ai": "Roomi AI.json",
        "logger": "Roomi Logger.json",
        "handler": "Roomi Handler.json",
    }

    changed_files: List[Path] = []
    for mdx_path in mdx_root.rglob("*.mdx"):
        text = mdx_path.read_text(encoding="utf-8")
        start, end, fm = parse_frontmatter(text)
        if start == -1:
            continue
        if "openapi" in fm:
            # Already references OpenAPI
            continue
        api_val = fm.get("api")
        if not api_val:
            continue

        # Extract METHOD and PATH from api field
        match = API_FIELD_RE.search(f"api: {api_val}")
        if not match:
            continue
        method = match.group(1).upper()
        mdx_path_str = match.group(2).strip()

        candidate_paths = [mdx_path_str]
        # Try mapping '/v1/...' to '/api/...'
        if mdx_path_str.startswith("/v1/"):
            candidate_paths.append("/api/" + mdx_path_str[len("/v1/"):])

        chosen: Optional[Tuple[str, str]] = None
        chosen_spec: Optional[str] = None
        for p in candidate_paths:
            key = (method, p)
            if key in path_index:
                # If multiple specs contain the same (method, path), prefer the one
                # that matches the MDX folder context when possible.
                candidate_spec = path_index[key]
                mdx_parts = mdx_path.relative_to(mdx_root).parts
                preferred_spec = None
                if len(mdx_parts) > 1:
                    folder = mdx_parts[0]
                    preferred_spec = folder_to_spec.get(folder)
                if preferred_spec and preferred_spec == candidate_spec:
                    chosen = key
                    chosen_spec = candidate_spec
                    break
                # Fallback to first match if no preference is set or no match
                if chosen is None:
                    chosen = key
                    chosen_spec = candidate_spec

        if not chosen or not chosen_spec:
            continue

        fm["openapi"] = f"/{SPEC_DIR}/{chosen_spec} {chosen[0]} {chosen[1]}"
        new_fm = build_frontmatter_text(fm)
        new_text = new_fm + text[end:]

        if new_text != text:
            changed_files.append(mdx_path)
            if apply:
                mdx_path.write_text(new_text, encoding="utf-8")

    return changed_files


def process_specs(root: Path, apply: bool, backup: bool) -> List[Path]:
    spec_root = root / SPEC_DIR
    changed_paths: List[Path] = []
    specs: Dict[str, Dict] = {}
    for path in spec_root.glob("*.json"):
        try:
            spec = load_json(path)
        except Exception:
            continue
        specs[path.name] = spec

    for spec_file, spec in specs.items():
        changed = False
        if ensure_servers(spec, root / SPEC_DIR / spec_file):
            changed = True
        if ensure_components_parameters(spec):
            changed = True
        if ensure_unit_user_headers_on_ops(spec, spec_file):
            changed = True
        if ensure_x_mint_metadata(spec):
            changed = True

        if changed:
            changed_paths.append(root / SPEC_DIR / spec_file)
            if apply:
                if backup:
                    (root / SPEC_DIR / f"{spec_file}.bak").write_text(
                        (root / SPEC_DIR / spec_file).read_text(encoding="utf-8"), encoding="utf-8"
                    )
                save_json(root / SPEC_DIR / spec_file, spec)

    # After spec normalization, update MDX frontmatters
    mdx_changed = normalize_mdx_openapi_reference(root, specs, apply)
    changed_paths.extend(mdx_changed)
    return changed_paths


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize OpenAPI specs and link MDX pages to enable Mintlify API Playground.")
    parser.add_argument("--root", type=str, required=True, help="Absolute path to docs root")
    parser.add_argument("--apply", action="store_true", help="Write changes in-place. Default is dry-run.")
    parser.add_argument("--backup", action="store_true", help="Write .bak backups when applying changes.")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"Root path not found: {root}", file=sys.stderr)
        return 2

    changed = process_specs(root, apply=args.apply, backup=args.backup)
    if args.apply:
        print(f"Updated {len(changed)} files:")
    else:
        print(f"[Dry-run] Would update {len(changed)} files:")
    for p in changed:
        print(f" - {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

