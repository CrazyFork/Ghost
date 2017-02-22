/*
这个模块从3种方式验证用户登录权限

这个文件和auth-strategies.js的区别在于什么？一个是express middleware， 一个是passport的strategy么
*/
var passport = require('passport'),
    errors = require('../errors'),
    events = require('../events'),
    i18n = require('../i18n'),
    authenticate;

function isBearerAutorizationHeader(req) {// Authorization: Bearer AbCdEf123456
    var parts,
        scheme,
        credentials;

    if (req.headers && req.headers.authorization) {
        parts = req.headers.authorization.split(' ');
    } else if (req.query && req.query.access_token) {
        return true;
    } else {
        return false;
    }

    if (parts.length === 2) {
        scheme = parts[0];
        credentials = parts[1];
        if (/^Bearer$/i.test(scheme)) {
            return true;
        }
    }
    return false;
}

authenticate = {
    // ### Authenticate Client Middleware
    //用于oauth2验证资源请求者的身份. 如果有bearer header 就skip掉验证
    authenticateClient: function authenticateClient(req, res, next) {
        // skip client authentication if bearer token is present
        if (isBearerAutorizationHeader(req)) {
            return next();
        }

        if (req.query && req.query.client_id) {
            req.body.client_id = req.query.client_id;
        }

        if (req.query && req.query.client_secret) {
            req.body.client_secret = req.query.client_secret;
        }

        if (!req.body.client_id || !req.body.client_secret) {
            return next(new errors.UnauthorizedError({
                message: i18n.t('errors.middleware.auth.accessDenied'),
                context: i18n.t('errors.middleware.auth.clientCredentialsNotProvided'),
                help: i18n.t('errors.middleware.auth.forInformationRead', {url: 'http://api.ghost.org/docs/client-authentication'})
            }));
        }

        return passport.authenticate(['oauth2-client-password'], {session: false, failWithError: false},
            function authenticate(err, client) {
                if (err) {
                    return next(err); // will generate a 500 error
                }

                // req.body needs to be null for GET requests to build options correctly
                delete req.body.client_id;
                delete req.body.client_secret;

                if (!client) {
                    return next(new errors.UnauthorizedError({
                        message: i18n.t('errors.middleware.auth.accessDenied'),
                        context: i18n.t('errors.middleware.auth.clientCredentialsNotValid'),
                        help: i18n.t('errors.middleware.auth.forInformationRead', {url: 'http://api.ghost.org/docs/client-authentication'})
                    }));
                }

                req.client = client;

                //:done - why use event emiter here?
                // 搜了下代码并没有其他地方用到，怀疑没有什么用
                events.emit('client.authenticated', client);
                return next(null, client);
            }
        )(req, res, next);
    },

    // ### Authenticate User Middleware
    // 通过 bearer token 验证用户信息, 如果是 oauth2 client request 则 bypass 掉
    authenticateUser: function authenticateUser(req, res, next) {
        //session, 不在session中记录用户登录状态, failWithError: true 未验证通过会抛出一个 error
        return passport.authenticate('bearer', {session: false, failWithError: false},
            function authenticate(err, user, info) {
                if (err) {
                    return next(err); // will generate a 500 error
                }

                if (user) {
                    req.authInfo = info;
                    req.user = user;

                    events.emit('user.authenticated', user);
                    return next(null, user, info);//todo: 这个信息传递到哪里去了？ 以参数的形式传递到下一个middleware中了？
                } else if (isBearerAutorizationHeader(req)) {
                    return next(new errors.UnauthorizedError({
                        message: i18n.t('errors.middleware.auth.accessDenied')
                    }));
                } else if (req.client) {// oauth2 client request falls through
                    req.user = {id: 0};
                    return next();
                }

                return next(new errors.UnauthorizedError({
                    message: i18n.t('errors.middleware.auth.accessDenied')
                }));
            }
        )(req, res, next);
    },

    // ### Authenticate Ghost.org User
    authenticateGhostUser: function authenticateGhostUser(req, res, next) {
        req.query.code = req.body.authorizationCode;

        if (!req.query.code) {
            return next(new errors.UnauthorizedError({message: i18n.t('errors.middleware.auth.accessDenied')}));
        }

        passport.authenticate('ghost', {session: false, failWithError: false}, function authenticate(err, user, info) {
            if (err) {
                return next(err);
            }

            if (!user) {
                return next(new errors.UnauthorizedError({message: i18n.t('errors.middleware.auth.accessDenied')}));
            }

            req.authInfo = info;
            req.user = user;
            next();
        })(req, res, next);
    }
};

module.exports = authenticate;
