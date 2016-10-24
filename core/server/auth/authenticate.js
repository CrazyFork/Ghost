/*
这个模块从3种方式验证用户登录权限

:todo - authenticateUser vs authenticateClient 的区别?
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

                events.emit('client.authenticated', client);//:todo - why use event emiter here?
                return next(null, client);
            }
        )(req, res, next);
    },

    // ### Authenticate User Middleware
    authenticateUser: function authenticateUser(req, res, next) {
        //:todo - `{session: false, failWithError: false}` what this options is ?
        // is this options related to passport project ?
        return passport.authenticate('bearer', {session: false, failWithError: false},
            function authenticate(err, user, info) {
                if (err) {
                    return next(err); // will generate a 500 error
                }

                if (user) {
                    req.authInfo = info;
                    req.user = user;

                    events.emit('user.authenticated', user);
                    return next(null, user, info);
                } else if (isBearerAutorizationHeader(req)) {
                    return next(new errors.UnauthorizedError({
                        message: i18n.t('errors.middleware.auth.accessDenied')
                    }));
                } else if (req.client) {//:todo - why this?
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
