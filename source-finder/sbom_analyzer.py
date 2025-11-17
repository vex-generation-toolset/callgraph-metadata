#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys
from pathlib import Path

from cyclonedx.model.bom import Bom
from packageurl import PackageURL

from maven_resolver import MavenArtifact, MavenResolver, POMNotFound


def purl_to_maven_coords(purl_str: str) -> MavenArtifact:
    p = PackageURL.from_string(purl_str)

    if p.type != "maven":
        raise ValueError(f"Expected maven purl, got type={p.type!r}")

    if not p.namespace or not p.name or not p.version:
        raise ValueError(f"Incomplete Maven purl: {p}")

    return MavenArtifact(p.namespace, p.name, p.version)


def parse_bom(path: str) -> Bom:
    """
    Parse a CycloneDX SBOM from JSON into a Bom object.
    """
    with open(path, "rb") as f:
        data = f.read()

    bom = Bom.from_json(data=json.loads(data))
    return bom


def is_jar(purl_str: str) -> bool:
    try:
        p = PackageURL.from_string(purl_str)
    except ValueError:
        return False
    return p.type == "maven" and isinstance(p.qualifiers, dict) and p.qualifiers.get("type") == "jar"


def process_bom(path: str):
    bom = parse_bom(path)

    print(f"Loaded BOM from {path}", file=sys.stderr)
    print(f"Components: {len(bom.components)}", file=sys.stderr)
    print()

    resolver = MavenResolver()

    for comp in bom.components:
        # comp.purl may be a string or a PackageURL depending on library version;
        # handle both.
        raw_purl = None

        if hasattr(comp, "purl") and comp.purl:
            raw_purl = str(comp.purl)

        if not raw_purl:
            # No PURL -> skip
            continue

        if not is_jar(raw_purl):
            # Only handling JARs
            continue

        artifact = purl_to_maven_coords(raw_purl)
        print("=" * 80, file=sys.stderr)
        print(f"Artifact: {artifact}", file=sys.stderr)

        try:
            location = resolver.resolve_source_location(artifact)
        except Exception as e:
            print(f"SCM       : error while fetching SCM info: {e}", file=sys.stderr)
            continue

        if location is None:
            print("Location: <none>", file=sys.stderr)
            continue
        print(f"Location URL: {location.vcs_url}", file=sys.stderr)
        print(f"Location tag: {location.tag or '<none>'}", file=sys.stderr)

        if not location.github_repo():
            print(f"Could not convert SCM connection to GitHub repo: {location.vcs_url!r}", file=sys.stderr)
            continue

        if not location.tag:
            print("No tag found in SCM location", file=sys.stderr)
            continue

        # Only include artifacts when the tag contains the artifact version
        if artifact.version not in location.tag:
            print(f"Tag {location.tag!r} does not contain version {artifact.version!r}", file=sys.stderr)
            continue

        tag_template = location.tag.replace(artifact.version, "%s")
        print(f"Tag template: {tag_template}", file=sys.stderr)

        location_meta_dir = f"callgraphs/{artifact.group_id}/{artifact.artifact_id}"
        try:
            Path(location_meta_dir).mkdir(parents=True, exist_ok=True)
        except Exception:
            print(f"Unable to create metadata directory {location_meta_dir}", file=sys.stderr)

        location_meta_file = f"{location_meta_dir}/location.json"
        if os.path.isfile(location_meta_file):
            print(f"Metadata file {location_meta_file} already exists, skipping", file=sys.stderr)
            continue

        location_data = {
            "repository": location.github_repo(),
            "tag": f"refs/tags/{tag_template}",
            "relative_path": ""
        }
        with open(location_meta_file, "w", encoding="utf-8") as f:
            json.dump(location_data, f, indent=2)
            print(f"Wrote metadata to {location_meta_file}", file=sys.stderr)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <cyclonedx-sbom.json>", file=sys.stderr)
        sys.exit(1)

    sbom_path = sys.argv[1]
    if not os.path.isfile(sbom_path):
        print(f"Error: file not found: {sbom_path}", file=sys.stderr)
        sys.exit(2)

    process_bom(sbom_path)


if __name__ == "__main__":
    main()
