#!/usr/bin/env node

// Deletes the compiled JSON artifacts for any source that `package.json`'s
// `files` allowlist marks as ignored (e.g. mocks). Ported from
// `openzeppelin-contracts/scripts/remove-ignored-artifacts.js`, adjusted for
// the `packages/contracts` layout where Hardhat compiles `src/**/*.sol` and
// this script runs after prepack has flattened outputs into `build/contracts/`.

const fs = require('fs');
const path = require('path');
const match = require('micromatch');

const readJSON = p => JSON.parse(fs.readFileSync(p));

const pkgFiles = readJSON('package.json').files;

// `files` uses `!/…` for negations. Drop the `!` (micromatch takes plain
// patterns) and the leading `/` (npm anchors to package root; micromatch
// matches relative paths).
const ignorePatterns = pkgFiles
  .filter(pat => pat.startsWith('!'))
  .map(pat => pat.slice(1).replace(/^\//, ''));

// A directory pattern like `src/mocks/**/*` matches the directory's children
// but not the directory itself. Add both so we catch either shape.
const ignorePatternsSubtrees = ignorePatterns.concat(ignorePatterns.map(pat => path.join(pat, '**/*')));

const artifactsDir = 'build/contracts';
const buildInfo = 'artifacts/build-info';

let removed = 0;
for (const filename of fs.readdirSync(buildInfo)) {
  const solcOutput = readJSON(path.join(buildInfo, filename)).output;
  for (const sourcePath in solcOutput.contracts) {
    if (!match.any(sourcePath, ignorePatternsSubtrees)) continue;
    for (const contract in solcOutput.contracts[sourcePath]) {
      const artifact = path.join(artifactsDir, contract + '.json');
      if (fs.existsSync(artifact)) {
        fs.unlinkSync(artifact);
        removed += 1;
      }
    }
  }
}

console.error(`Removed ${removed} ignored artifacts`);
