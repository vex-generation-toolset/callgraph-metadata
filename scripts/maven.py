# SPDX-License-Identifier: Apache-2.0
from packageurl import PackageURL

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

    @staticmethod
    def from_purl(purl: PackageURL) -> 'MavenArtifact':
        if purl.type != "maven":
            raise ValueError(f"Expected maven purl, got type={purl.type!r}")

        if not purl.namespace or not purl.name or not purl.version:
            raise ValueError(f"Incomplete Maven purl: {p}")

        return MavenArtifact(purl.namespace, purl.name, purl.version)