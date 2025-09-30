#!/usr/bin/env bash

# Generates go.md

set -e

echo "## Modules and org dependencies
\`\`\`mermaid
flowchart LR
"
gomods graph | modgraph -prefix github.com/smartcontractkit/
echo "\`\`\`"
