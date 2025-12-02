#!/bin/bash

function log_debug() {
    if [ "$DEBUG" -eq 1 ]; then
        echo "[DEBUG] $1" >&2
    fi
}

function log_info() {
    echo "[INFO] $1" >&2
}

SBOM=""
SHOW_USAGE=0
DEBUG=0
while [ $# -gt 0 ]; do
    case "$1" in
        -d) DEBUG=1; shift ;;
        -h|--help) SHOW_USAGE=1; break ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) if [ -z "$SBOM" ]; then
               SBOM="$1";
               shift;
           else
               echo "Only one path-to-sbom allowed" >&2;
               exit 1;
          fi ;;
    esac
done

if [[ -z "$SBOM" || $SHOW_USAGE -eq 1 ]]; then
    echo "Usage: $0 <options> <path-to-sbom>"
    echo "Options:"
    echo "  -d  Debug mode"
    if [ "$SHOW_USAGE" -eq 1 ]; then
        exit 0
    else
        exit 1
    fi
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
        gh workflow run generate-call-graph.yaml -f artifact="$groupId:$artifactId:$version" >&2
        log_info "Triggered workflow for: $groupId:$artifactId:$version"
    else
        log_debug "Missing location file for: $groupId:$artifactId:$version"
    fi
done
