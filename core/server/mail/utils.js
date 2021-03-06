/*
this module is helper util for generate content from ./templates/ folder
*/
var _ = require('lodash').runInContext(),// :todo - 创建一个干净的loadash对象？因为下边更改了lodash模板全局设置
    fs = require('fs'),
    Promise = require('bluebird'),
    path = require('path'),
    htmlToText = require('html-to-text'),
    config = require('../config'),
    templatesDir = path.resolve(__dirname, '..', 'mail', 'templates');

_.templateSettings.interpolate = /{{([\s\S]+?)}}/g; // change lodash template settings

exports.generateContent = function generateContent(options) {
    var defaults,
        data;

    defaults = {
        siteUrl: config.get('forceAdminSSL') ? (config.get('urlSSL') || config.get('url')) : config.get('url')
    };

    data = _.defaults(defaults, options.data);

    // read the proper email body template
    return Promise.promisify(fs.readFile)(path.join(templatesDir, options.template + '.html'), 'utf8')
        .then(function (content) {
            var compiled,
                htmlContent,
                textContent;

            // insert user-specific data into the email
            compiled = _.template(content);
            htmlContent = compiled(data);

            // generate a plain-text version of the same email
            textContent = htmlToText.fromString(htmlContent);

            return {
                html: htmlContent,
                text: textContent
            };
        });
};
