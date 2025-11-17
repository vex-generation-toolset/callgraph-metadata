#!/bin/bash

SBOM="$1"
if [ -z "$SBOM" ]; then
    echo "Usage: $0 <path-to-sbom>"
    exit 1
fi

jq -r '.components[].purl' "$SBOM" | while read -r purl; do
    # Add your processing logic here
    tmp=${purl#pkg:maven/}
    tmp=${tmp%\?*}
    groupId=${tmp%%/*}
    tmp=${tmp#*/}
    artifactId=${tmp%%@*}
    version=${tmp#*@}
    callgraph_file="callgraphs/$groupId/$artifactId/$version/callgraph.json"
    if [ -f "$callgraph_file" ]; then
        continue
    fi
    location_file="callgraphs/$groupId/$artifactId/location.json"
    if [ -f "$location_file" ]; then
        gh workflow run generate-call-graph.yaml -f artifact="$groupId:$artifactId:$version"
    else
        echo "Missing location file for: $groupId:$artifactId:$version" >&2
    fi
done