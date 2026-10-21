const path = require('path');
const fs = require('fs');

// The MDX templates in `docs/templates-md` are injected by https://github.com/OpenZeppelin/docs at generation time,
// which also overwrites this file with its canonical config.

/** @type import('solidity-docgen/dist/config').UserConfig */
module.exports = {
  outputDir: 'docs/modules/api/pages',
  templates: 'docs/templates-md',
  exclude: ['mocks'],
  pageExtension: '.mdx',
  pages: (_, file, config) => {
    // For each contract file, find the closest README.mdx (or README.adoc) and return its location as the output page path.
    // A README at the sources root documents root-level contracts on the index page.
    const sourcesDir = path.resolve(config.root, config.sourcesDir);
    let dir = path.resolve(config.root, file.absolutePath);
    while (dir.startsWith(sourcesDir)) {
      dir = path.dirname(dir);
      if (['README.mdx', 'README.adoc'].some(readme => fs.existsSync(path.join(dir, readme)))) {
        return (path.relative(sourcesDir, dir) || 'index') + config.pageExtension;
      }
    }
  },
};
