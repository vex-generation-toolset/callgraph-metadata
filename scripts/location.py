# SPDX-License-Identifier: Apache-2.0

class SourceLocation:
    def __init__(self, vcs_url: str, tag: str | None):
        self.vcs_url = vcs_url
        self.tag = tag

    def github_repo(self) -> str | None:
        """
        Convert SCM connection URL to GitHub repository path.
        """
        if not self.vcs_url.startswith("git+"):
            return None

        connection = self.vcs_url[4:]
        repository = None

        # Try GitHub prefixes
        prefixes = [
            "git@github.com:",
            "git://github.com/",
            "ssh://github.com/",
            "https://github.com/"
        ]
        for prefix in prefixes:
            if connection.startswith(prefix):
                repository = connection[len(prefix):]
                break

        # Try mapping Apache GitBox URLs to GitHub
        asf_prefix = "https://gitbox.apache.org/repos/asf/"
        if not repository and connection.startswith(asf_prefix):
            repository = "apache/" + connection[len(asf_prefix):]

        # Remove .git suffix if present
        if repository and repository.endswith(".git"):
            repository = repository[:-4]
        return repository