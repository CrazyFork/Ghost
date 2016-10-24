// jscs:disable
var _ = require('lodash'),
    moment = require('moment'),
    Stream = require('stream').Stream,
    util = require('util'),
    format = util.format, //nodejs's util module
    prettyjson = require('prettyjson'),
    __private__ = {
        levelFromName: {
            10: 'trace',
            20: 'debug',
            30: 'info',
            40: 'warn',
            50: 'error',
            60: 'fatal'
        },
        colorForLevel: {
            10: 'grey',
            20: 'grey',
            30: 'cyan',
            40: 'magenta',
            50: 'red',
            60: 'inverse'
        },
        colors: {
            'bold': [1, 22],
            'italic': [3, 23],
            'underline': [4, 24],
            'inverse': [7, 27],
            'white': [37, 39],
            'grey': [90, 39],
            'black': [30, 39],
            'blue': [34, 39],
            'cyan': [36, 39],
            'green': [32, 39],
            'magenta': [35, 39],
            'red': [31, 39],
            'yellow': [33, 39]
        }
    };

// 这个模块将data格式化颜色/格式后(按照terminal的格式)输出
function PrettyStream() {
}
util.inherits(PrettyStream, Stream);


function colorize(color, value) {
    return '\x1B[' + __private__.colors[color][0] + 'm' + value + '\x1B[' + __private__.colors[color][1] + 'm';
}


PrettyStream.prototype.write = function write(data) {
    if (typeof data === 'string') {
        try {
            data = JSON.parse(data);
        } catch (err) {
            this.emit('data', err);
        }
    }

    var body = {},
        time = moment(data.time).format('YYYY-MM-DD HH:mm:ss'),
        logLevel = __private__.levelFromName[data.level].toUpperCase(),
        codes = __private__.colors[__private__.colorForLevel[data.level]],
        bodyPretty = '';

    logLevel = '\x1B[' + codes[0] + 'm' + logLevel + '\x1B[' + codes[1] + 'm';

    if (data.msg) {
        body.msg = data.msg;
    }

    if (data.req && data.res) {
        _.each(data.req, function (value, key) {
            if (['headers', 'query', 'body'].indexOf(key) !== -1 && !_.isEmpty(value)) {
                bodyPretty += colorize('yellow', key.toUpperCase()) + '\n';
                bodyPretty += prettyjson.render(value, {}) + '\n';
            }
        });

        bodyPretty += '\n';
        if (data.err) {
            if (data.err.level) {
                bodyPretty += colorize('yellow', 'ERROR (' + data.err.level + ')') + '\n';
            } else {
                bodyPretty += colorize('yellow', 'ERROR\n');
            }

            _.each(data.err, function (value, key) {
                if (['message', 'context', 'help', 'stack'].indexOf(key) !== -1 && !_.isEmpty(value)) {
                    bodyPretty += value + '\n';
                }
            });
        }
    } else if (data.err) {
        _.each(data.err, function (value, key) {
            if (_.isEmpty(value)) {
                return;
            }

            if (key === 'level') {
                bodyPretty += colorize('underline', key + ':' + value) + '\n\n';
            }
            else if (key === 'message') {
                bodyPretty += colorize('red', value) + '\n';
            }
            else if (key === 'context') {
                bodyPretty += colorize('white', value) + '\n';
            }
            else if (key === 'help') {
                bodyPretty += colorize('yellow', value) + '\n';
            }
            else if (key === 'stack' && !data.err['hideStack']) {
                bodyPretty += colorize('white', value) + '\n';
            }
        });
    } else {
        // print string
        bodyPretty += data.msg;
    }

    try {
        if (data.req && data.res) {
            this.emit('data', format('[%s] %s --> %s %s (%s) \n%s\n\n',
                time,
                logLevel,
                data.req.method,
                data.req.url,
                data.res.statusCode,
                colorize('grey', bodyPretty)
            ));
        } else if (data.err) {
            this.emit('data', format('[%s] %s \n%s\n\n',
                time,
                logLevel,
                colorize('grey', bodyPretty)
            ));
        } else {
            this.emit('data', format('[%s] %s %s\n',
                time,
                logLevel,
                colorize('grey', bodyPretty)
            ));
        }
    } catch (err) {
        this.emit('data', err);
    }

    return true;
};


module.exports = PrettyStream;
