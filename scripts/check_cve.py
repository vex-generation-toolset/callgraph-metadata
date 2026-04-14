# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys
from os import PathLike

from cyclonedx.model.bom import Bom
from github import Auth, Github
from github.PaginatedList import PaginatedList
from github.PullRequest import PullRequest
from packageurl import PackageURL

BATCH_SIZE = 100

class Advisory:
    def __init__(self, cve_id: str, purl: PackageURL):
        self.cve_id = cve_id
        self.purl = purl

    def to_json(self):
        return {
            "artifact": f"{self.purl.namespace}:{self.purl.name}:{self.purl.version}",
            "cve": self.cve_id
        }


def get_github_client() -> Github:
    """
    Create and return a GitHub client using the GITHUB_TOKEN environment variable.
    """
    github_token = os.environ.get("GH_TOKEN")
    if not github_token:
        raise RuntimeError("GH_TOKEN environment variable is not set")
    auth = Auth.Token(github_token)
    g = Github(auth=auth)
    return g


def get_advisories_by_purl(purls: list[PackageURL], g: Github) -> list[Advisory]:
    """
    Given a PackageURL, return a list of associated CVE IDs.
    """
    package_to_purl = {f"{p.namespace}:{p.name}": p for p in purls}
    affected = [f"{p.namespace}:{p.name}@{p.version}" for p in purls]
    advisories: list[Advisory] = []
    for gh_advisory in g.get_global_advisories(ecosystem="maven", affects=affected):
        for gh_vulnerability in gh_advisory.vulnerabilities:
            purl = package_to_purl.get(gh_vulnerability.package.name, None)
            if purl and gh_advisory.cve_id:
                advisories.append(Advisory(cve_id=gh_advisory.cve_id, purl=purl))
    return advisories


def get_purls(sbom: Bom) -> list[PackageURL]:
    """
    Extract PackageURLs from the SBOM components.
    """
    purls: list[PackageURL] = []
    for comp in sbom.components:
        if hasattr(comp, "purl"):
            purls.append(comp.purl)
    return purls


def list_advisories(sbom: Bom) -> list[Advisory]:
    """
    Generate a list of CVE IDs from the given SBOM file.
    """
    purls = get_purls(sbom)
    g = get_github_client()

    advisories: list[Advisory] = []
    for i in range(0, len(purls), BATCH_SIZE):
        batch = purls[i:i + BATCH_SIZE]
        advisories.extend(get_advisories_by_purl(batch, g))

    # Return unique advisories sorted by cve_id
    result = sorted({adv.cve_id: adv for adv in advisories}.values(), key=lambda a: a.cve_id)
    return result

def should_generate_root_cause(repo: str, vuln_metadata: str | PathLike, cve_id: str) -> bool:
    """
    Determine whether a root cause analysis should be generated for the given CVE ID.
    """
    _, year, number = cve_id.split("-")
    expected_path = os.path.join(vuln_metadata, year, number, "root-cause.json")
    if os.path.exists(expected_path):
        return False
    return not __has_open_pull_request(repo, cve_id)

def __has_open_pull_request(repo: str, cve: str) -> bool:
    """
    Check if there is an open pull request for the given CVE.
    """
    github_token = os.environ.get("GH_TOKEN")
    if not github_token:
        raise RuntimeError("GH_TOKEN environment variable is not set")

    auth = Auth.Token(github_token)
    g = Github(auth=auth)
    pull_requests: PaginatedList[PullRequest] = g.get_repo(repo).get_pulls(state="open")
    for pr in pull_requests:
        if cve in pr.title:
            return True
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sbom-path>...", file=sys.stderr)
        sys.exit(1)

    # The GitHub repository in the format "owner/repo" is required to check for open pull requests
    # The variable is always present in GitHub Actions.
    gh_repo = os.environ.get("GITHUB_REPOSITORY")
    if not gh_repo:
        print("GITHUB_REPOSITORY environment variable is not set", file=sys.stderr)
        sys.exit(1)

    for sbom_file in sys.argv[1:]:
        if not os.path.exists(sbom_file):
            print(f"SBOM file {sbom_file} does not exist", file=sys.stderr)
            sys.exit(1)

        with open(sbom_file, "rb") as f:
            data = f.read()

        sbom: Bom = Bom.from_json(data=json.loads(data))
        advisories = list_advisories(sbom)
        for advisory in advisories:
            if should_generate_root_cause(gh_repo, "vulnerabilities", advisory.cve_id):
                print(json.dumps(advisory.to_json()))
