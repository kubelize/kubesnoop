#!/bin/bash

# Extract Bitnami containers from kubesnoop output
# Usage: ./extract-bitnami.sh [kubesnoop-output.json] [--csv]

INPUT_FILE=${1:-kubesnoop-output.json}
OUTPUT_FORMAT="table"

# Check for CSV flag
if [[ "$2" == "--csv" ]] || [[ "$1" == "--csv" ]]; then
    OUTPUT_FORMAT="csv"
    if [[ "$1" == "--csv" ]]; then
        INPUT_FILE=${2:-kubesnoop-output.json}
    fi
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    echo "Error: File '$INPUT_FILE' not found"
    echo "Usage: $0 [kubesnoop-output.json]"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    echo "Install with: brew install jq (macOS) or apt-get install jq (Ubuntu)"
    exit 1
fi

# Output header based on format
if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
    echo "Name,Namespace,Image"
else
    echo "Bitnami Containers Found:"
    echo "========================="
    printf "%-40s %-30s %-80s\n" "NAME" "NAMESPACE" "IMAGE"
    printf "%-40s %-30s %-80s\n" "$(printf '%*s' 40 '' | tr ' ' '-')" "$(printf '%*s' 30 '' | tr ' ' '-')" "$(printf '%*s' 80 '' | tr ' ' '-')"
fi

jq -r '
.pods[]? |
select(.containers[]?.image | test("bitnami"; "i")) |
. as $pod |
.containers[] |
select(.image | test("bitnami"; "i")) |
[
    $pod.name // "unknown",
    $pod.namespace // "unknown",
    .image
] | @tsv
' "$INPUT_FILE" | while IFS=$'\t' read -r name namespace image; do
    if [[ "$OUTPUT_FORMAT" == "csv" ]]; then
        echo "\"$name\",\"$namespace\",\"$image\""
    else
        printf "%-40s %-30s %-80s\n" "$name" "$namespace" "$image"
    fi
done

# Count total Bitnami containers
TOTAL=$(jq -r '.pods[]? | select(.containers[]?.image | test("bitnami"; "i")) | .containers[] | select(.image | test("bitnami"; "i")) | .image' "$INPUT_FILE" | wc -l)

if [[ "$OUTPUT_FORMAT" == "table" ]]; then
    echo ""
    echo "Total Bitnami containers found: $TOTAL"
fi
