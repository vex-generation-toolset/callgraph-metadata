#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json
import sys
import xml.etree.ElementTree as ET
from location import SourceLocation

class MavenArtifact:
    def __init__(self, group_id: str, artifact_id: str, version: str):
        self.group_id = group_id
        self.artifact_id = artifact_id
        self.version = version

    def __str__(self):
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    def to_path(self) -> str:
        group_path = self.group_id.replace(".", "/")
        return f"{group_path}/{self.artifact_id}/{self.version}/{self.artifact_id}-{self.version}"


class POMNotFound(Exception):
    pass


class MavenResolver:
    MAVEN_CENTRAL_BASE = "https://repo.maven.apache.org/maven2"
    MAVEN_NS = {"m": "http://maven.apache.org/POM/4.0.0"}

    @staticmethod
    def __build_pom_url(artifact: MavenArtifact) -> str:
        return f"{MavenResolver.MAVEN_CENTRAL_BASE}/{artifact.to_path()}.pom"

    @staticmethod
    def extract_parent_coords(pom_xml: str) -> MavenArtifact | None:
        root = ET.fromstring(pom_xml)

        parent = root.find("m:parent", MavenResolver.MAVEN_NS)
        if parent is None:
            return None

        group_id = parent.findtext("m:groupId", default=None, namespaces=MavenResolver.MAVEN_NS)
        artifact_id = parent.findtext("m:artifactId", default=None, namespaces=MavenResolver.MAVEN_NS)
        version = parent.findtext("m:version", default=None, namespaces=MavenResolver.MAVEN_NS)

        if group_id and artifact_id and version:
            return MavenArtifact(group_id.strip(), artifact_id.strip(), version.strip())
        return None

    @staticmethod
    def __extract_scm_info(pom_xml: str) -> SourceLocation | None:
        root = ET.fromstring(pom_xml)

        scm = root.find("m:scm", MavenResolver.MAVEN_NS)
        if scm is None:
            return None

        connection = scm.findtext("m:connection", default=None, namespaces=MavenResolver.MAVEN_NS)
        tag = scm.findtext("m:tag", default=None, namespaces=MavenResolver.MAVEN_NS)

        if connection is None:
            return None

        return SourceLocation(
            MavenResolver.__convert_to_spdx_connection(connection.strip()),
            tag.strip() if tag else None
        )

    @staticmethod
    def __convert_to_spdx_connection(connection: str) -> str:
        if connection.startswith("scm:git:"):
            return "git+" + connection[len("scm:git:") :]
        elif connection.startswith("scm:svn:"):
            return "svn+" + connection[len("scm:svn:") :]
        return connection

    def resolve_source_location(self, artifact: MavenArtifact) -> SourceLocation | None:
        import requests

        visited = set()
        current_artifact = artifact

        while current_artifact and str(current_artifact) not in visited:
            visited.add(str(current_artifact))
            pom_url = MavenResolver.__build_pom_url(current_artifact)

            response = requests.get(pom_url)
            if response.status_code != 200:
                raise POMNotFound(f"POM not found for {current_artifact} at {pom_url}")

            pom_xml = response.text

            scm_info = MavenResolver.__extract_scm_info(pom_xml)
            if scm_info:
                return scm_info

            current_artifact = MavenResolver.extract_parent_coords(pom_xml)

        return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <groupId:artifactId:version>", file=sys.stderr)
        sys.exit(1)

    artifact = MavenArtifact(*sys.argv[1].split(":", maxsplit=3))
    resolver = MavenResolver()
    try:
        location = resolver.resolve_source_location(artifact)
        if location:
            if location.tag and artifact.version in location.tag:
                tag_template = location.tag.replace(artifact.version, "%s")
                print(f"Location template for {artifact.group_id}:{artifact.artifact_id}:")
            else:
                tag_template = location.tag
                print(f"Location for {artifact}:")

            location_data = {
                "vcs_url": location.vcs_url,
                "repository": location.github_repo(),
                "tag": f"refs/tags/{tag_template}" if tag_template else None,
                "relative_path": ""
            }
            json.dump(location_data, sys.stdout, indent=2)
        else:
            print("No SCM information found.")
    except POMNotFound as e:
        print(e)

if __name__ == "__main__":
    main()