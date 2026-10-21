#!/usr/bin/env bash

set -euo pipefail

OUTDIR="$(node -p 'require("./docs/config.js").outputDir')"

rm -rf "$OUTDIR"

hardhat docgen
