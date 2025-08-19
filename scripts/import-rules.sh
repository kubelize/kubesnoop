#!/bin/bash

# Import rules from JSON file to KubeSnoop database

set -e

DB_PATH="${1:-kubesnoop.db}"
RULES_FILE="${2:-examples/default-rules.json}"

echo "Importing rules from $RULES_FILE to database $DB_PATH"

if [ ! -f "$RULES_FILE" ]; then
    echo "Error: Rules file $RULES_FILE not found"
    exit 1
fi

# Build kubesnoop if not exists
if [ ! -f "bin/kubesnoop" ]; then
    echo "Building kubesnoop..."
    make build
fi

echo "Current rules in database:"
./bin/kubesnoop rules list --db "$DB_PATH"

echo ""
echo "To add rules manually, use:"
echo "./bin/kubesnoop rules add --db $DB_PATH"
echo ""
echo "Or edit the JSON file and reimport with this script"
echo ""
echo "Available rule management commands:"
echo "./bin/kubesnoop rules list --db $DB_PATH"
echo "./bin/kubesnoop rules show <id> --db $DB_PATH"  
echo "./bin/kubesnoop rules toggle <id> <true|false> --db $DB_PATH"
echo "./bin/kubesnoop rules delete <id> --db $DB_PATH"
