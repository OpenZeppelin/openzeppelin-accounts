module.exports = {
  require: ['ts-node/register'],
  timeout: '600s',
  typescript: {
    rewritePaths: {
      'src/': 'dist/',
    },
    compile: false,
  },
};
