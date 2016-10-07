var crypto        = require('crypto'),
    packageInfo   = require('../../../package.json');

module.exports = function generateAssetHash() {
    //:bm, we can use this to hash files
    return (crypto.createHash('md5').update(packageInfo.version + Date.now()).digest('hex')).substring(0, 10);
};
