#!/usr/bin/env bash

# Build step for the `@openzeppelin-accounts/contracts` npm package.
#
# Compiles the sources with Hardhat, then extracts the shipped JSON artifacts
# to `build/contracts/` and strips out anything the `files` allowlist marks as
# ignored (mocks, debug output). Modeled on
# `openzeppelin-contracts/scripts/prepack.sh` — same shape, adjusted for our
# `packages/contracts` layout where sources live under `src/`.

set -euo pipefail

# cd to the contracts package root (this script lives at scripts/prepack.sh).
cd "$(dirname "$0")/.."

pnpm run clean
pnpm run compile

mkdir -p build/contracts
# `find … -exec cp` instead of `**` globs so this runs on the bash 3.2 that
# ships with macOS. `-name '*.json' ! -name '*.dbg.json'` also folds the
# debug-artifact removal into the copy step.
find artifacts/src -name '*.json' ! -name '*.dbg.json' -exec cp {} build/contracts/ \;
node scripts/remove-ignored-artifacts.js
