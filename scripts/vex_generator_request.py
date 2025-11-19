#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import os.path
import sys
from collections.abc import Iterable

from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.dependency import Dependency

from maven import MavenArtifact

CALLGRAPH_BASE_URL = "https://raw.githubusercontent.com/vex-generation-toolset/callgraph-metadata/refs/heads/main/"


class Chain:
    def __init__(self, artifact: MavenArtifact, callgraph_url: str):
        self.artifact = artifact
        self.callgraph_url = callgraph_url

    def to_json(self) -> dict[str, str]:
        return {
            "purl": self.artifact.to_purl().to_string(),
            "callgraph": self.callgraph_url
        }


def __get_root_cause_path(cve: str) -> str:
    cve_parts = cve.split("-", 3)
    if len(cve_parts) != 3 or cve_parts[0] != "CVE":
        raise ValueError(f"Invalid CVE identifier: {cve}")
    return f"vulnerabilities/{cve_parts[1]}/{cve_parts[2]}/root-cause.json"


def __create_if_absent(dependencies_by_ref: dict[BomRef, Dependency], ref: BomRef) -> Dependency:
    dep = dependencies_by_ref.get(ref)
    if not dep:
        dep = Dependency(ref)
        dependencies_by_ref[ref] = dep
    return dep


def __reverse_graph(dependencies: Iterable[Dependency], root_ref: BomRef) -> Dependency:
    root = Dependency(root_ref)
    dependencies_by_ref: dict[BomRef, Dependency] = {root_ref: root}

    for dep in dependencies:
        parent = __create_if_absent(dependencies_by_ref, dep.ref)
        for child in dep.dependencies:
            # parent depends on child
            child_dep = __create_if_absent(dependencies_by_ref, child.ref)
            # Prevent cycles
            child_dep.dependencies.add(parent)

    return root


def __chains_by_ref(sbom: Bom) -> dict[BomRef, Chain]:
    chains: dict[BomRef, Chain] = {}
    for comp in sbom.components:
        purl = comp.purl
        if not purl:
            continue

        artifact = MavenArtifact.from_purl(purl)
        callgraph_path = f"callgraphs/{artifact.group_id}/{artifact.artifact_id}/{artifact.version}/callgraph.json"

        if os.path.exists(callgraph_path):
            callgraph_url = CALLGRAPH_BASE_URL + callgraph_path
            chain = Chain(artifact, callgraph_url)
            chains[comp.bom_ref] = chain
    return chains


def find_dependency_chains(root: Dependency, chains_by_ref: dict[BomRef, Chain]) -> list[list[Chain]]:
    all_chains = []

    def dfs(current: Dependency, chain: list[dict[str, str]], visited: set[Dependency]):
        current_chain = chains_by_ref.get(current.ref)
        if current in visited:
            # There is a cycle; stop this branch (or handle differently)
            return

        visited.add(current)
        if current_chain:
            chain.append(current_chain.to_json())

        if len(current.dependencies) == 0:
            all_chains.append(chain[::-1])  # append a copy of the current path in reverse order
        else:
            for child in current.dependencies:
                dfs(child, chain, visited)

        # backtrack
        if current_chain:
            chain.pop()
        visited.remove(current)

    dfs(root, [], set())
    return all_chains


def generate_vex_request(sbom_path: str, artifact: MavenArtifact, cve: str) -> str:
    """
    Generate a VEX generator request for the given artifact string.
    """
    with open(sbom_path, "rb") as f:
        data = f.read()

    sbom = Bom.from_json(data=json.loads(data))

    bom_ref: BomRef | None = None
    for comp in sbom.components:
        if artifact.matches(comp.purl):
            bom_ref = comp.bom_ref
            break

    if not bom_ref:
        raise ValueError(f"Artifact {artifact} not found in SBOM components")

    cve_path = __get_root_cause_path(cve)

    with open(cve_path, "rb") as f:
        cve_data: dict = json.load(f)

    root: Dependency = __reverse_graph(sbom.dependencies, bom_ref)
    chains_by_ref: dict[BomRef, Chain] = __chains_by_ref(sbom)
    chains = find_dependency_chains(root, chains_by_ref)
    cve_data["chains"] = chains

    # Temporary conversion between the output of the root cause analysis
    # and the expected input format for the VEX generator
    new_root_cause_functions = []
    root_cause_functions = cve_data.get("root_cause_functions", [])
    for func in root_cause_functions:
        methods = func.get("methods", [])
        new_root_cause_functions.extend(methods)
    cve_data["root_cause_functions"] = new_root_cause_functions

    cve_data["cve_id"] = cve_data.pop("cve")
    cve_data["purl"] = cve_data.pop("package")
    return json.dumps(cve_data, indent=2, sort_keys=True)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <sbom-path> <artifact> <cve-id>", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print(f"SBOM file {sys.argv[1]} does not exist", file=sys.stderr)
        sys.exit(1)

    artifact = MavenArtifact.from_string(sys.argv[2])
    vex_request_json = generate_vex_request(sys.argv[1], artifact, sys.argv[3])
    print(vex_request_json)


if __name__ == "__main__":
    main()
