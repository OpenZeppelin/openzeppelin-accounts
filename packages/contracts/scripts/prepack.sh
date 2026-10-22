#!/usr/bin/env bash

# Build step for the `@openzeppelin-accounts/contracts` npm package.
#
# The published package is rooted at `src/` (see `publishConfig.directory` in
# the outer `package.json`), so consumers import as
# `@openzeppelin-accounts/contracts/OpenAccount.sol` without a `src/` segment
# in the path. This script stages the compiled artifacts and README into
# `src/` before pack/publish.
#
# Modeled on `openzeppelin-contracts/scripts/prepack.sh` — same shape, adjusted
# for our layout and the pnpm `publishConfig.directory` trick.

set -euo pipefail

# cd to the contracts package root (this script lives at scripts/prepack.sh).
cd "$(dirname "$0")/.."

pnpm run clean
COMPILE_MODE=production pnpm run compile

mkdir -p src/build/contracts
# `find … -exec cp` instead of `**` globs so this runs on the bash 3.2 that
# ships with macOS. `-name '*.json' ! -name '*.dbg.json'` also folds the
# debug-artifact removal into the copy step.
find artifacts/src -name '*.json' ! -name '*.dbg.json' -exec cp {} src/build/contracts/ \;
node scripts/remove-ignored-artifacts.js

cp README.md src/README.md
