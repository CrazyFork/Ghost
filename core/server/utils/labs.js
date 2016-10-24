//:todo-what this file used for?
var config = require('../config'),
    flagIsSet;

flagIsSet = function flagIsSet(flag) {
    var labsConfig = config.get('labs');//labs, 功能性实验配置？

    return labsConfig && labsConfig[flag] && labsConfig[flag] === true;
};

module.exports.isSet = flagIsSet;
