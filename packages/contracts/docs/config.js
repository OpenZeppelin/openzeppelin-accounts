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
    // For each contract file, find the closest README.adoc and return its location as the output page path.
    // A README.adoc at the sources root documents root-level contracts on the index page.
    const sourcesDir = path.resolve(config.root, config.sourcesDir);
    let dir = path.resolve(config.root, file.absolutePath);
    while (dir.startsWith(sourcesDir)) {
      dir = path.dirname(dir);
      if (fs.existsSync(path.join(dir, 'README.adoc'))) {
        return (path.relative(sourcesDir, dir) || 'index') + config.pageExtension;
      }
    }
  },
};
