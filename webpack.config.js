const path = require('path');

module.exports = {
  mode: 'production',
  entry: './build/index.js',
  devtool: 'source-map',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'cryptoseal.js',
    library: {
      name: 'cryptoSeal',
      type: 'umd',
    },
  },
};