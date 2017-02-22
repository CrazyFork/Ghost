/*
this module implemented some passport authenticate strategies
*/
var models = require('../models'),
    utils = require('../utils'),
    i18n = require('../i18n'),
    errors = require('../errors'),
    _ = require('lodash'),
    strategies;

strategies = {

    /**
     * ClientPasswordStrategy
     *
     * This strategy is used to authenticate registered OAuth clients.  It is
     * employed to protect the `token` endpoint, which consumers use to obtain
     * access tokens.  The OAuth 2.0 specification suggests that clients use the
     * HTTP Basic scheme to authenticate (not implemented yet).
     * Use of the client password strategy is implemented to support ember-simple-auth.
     */
    clientPasswordStrategy: function clientPasswordStrategy(clientId, clientSecret, done) {//用于验证oauth的client的
        return models.Client.findOne({slug: clientId}, {withRelated: ['trustedDomains']})
            .then(function then(model) {
                if (model) {
                    var client = model.toJSON({include: ['trustedDomains']});
                    if (client.status === 'enabled' && client.secret === clientSecret) {
                        return done(null, client);
                    }
                }
                return done(null, false);
            });
    },

    /**
     * BearerStrategy - auth by `bearer token`
     *
     * This strategy is used to authenticate users based on an access token (aka a
     * bearer token).  The user must have previously authorized a client
     * application, which is issued an access token to make requests on behalf of
     * the authorizing user.
     */
    bearerStrategy: function bearerStrategy(accessToken, done) { // 用于验证用户的
        return models.Accesstoken.findOne({token: accessToken})
            .then(function then(model) {
                if (model) {
                    var token = model.toJSON();
                    if (token.expires > Date.now()) {
                        return models.User.findOne({id: token.user_id})
                            .then(function then(model) {
                                if (model) {
                                    var user = model.toJSON(),
                                        info = {scope: '*'};
                                    return done(null, {id: user.id}, info);
                                }
                                return done(null, false);
                            });// todo: 没有catch这个地方， 也许是个bug
                    } else {
                        return done(null, false);
                    }
                } else {
                    return done(null, false);
                }
            });
    },

    /**
     * Ghost Strategy
     * ghostAuthRefreshToken: will be null for now, because we don't need it right now
     * 这个strategy貌似没有做什么验证 access_token 没有用到过，只是保存了对应的access_token在user中。
     * 估计是组合着用的
     *
     * CASES:
     * - via invite token
     * - via normal auth
     * - via setup
     *
     * @TODO: validate GhostAuth profile?
     */
    ghostStrategy: function ghostStrategy(req, ghostAuthAccessToken, ghostAuthRefreshToken, profile, done) {
        var inviteToken = req.body.inviteToken,
            options = {context: {internal: true}},
            handleInviteToken, handleSetup;

        // 处理 invite 过来的用户
        handleInviteToken = function handleInviteToken() {// create a new user with invited token
            var user, invite;
            inviteToken = utils.decodeBase64URLsafe(inviteToken);

            return models.Invite.findOne({token: inviteToken}, options)
                .then(function addInviteUser(_invite) {
                    invite = _invite;

                    if (!invite) {
                        throw new errors.NotFoundError({message: i18n.t('errors.api.invites.inviteNotFound')});
                    }

                    if (invite.get('expires') < Date.now()) {
                        throw new errors.NotFoundError({message: i18n.t('errors.api.invites.inviteExpired')});
                    }

                    return models.User.add({ // :done [add, edit 这些方法哪来的], User model中定义的
                        email: profile.email_address,
                        name: profile.email_address,
                        password: utils.uid(50),
                        roles: invite.toJSON().roles
                    }, options);
                })
                .then(function destroyInvite(_user) {
                    user = _user;
                    return invite.destroy(options);
                })
                .then(function () {
                    return user;
                });
        };

        handleSetup = function handleSetup() {// update user info with options
            return models.User.findOne({slug: 'ghost-owner', status: 'all'}, options)//:todo - what is this slug guy?
                .then(function fetchedOwner(owner) {
                    if (!owner) {
                        throw new errors.NotFoundError({message: i18n.t('errors.models.user.userNotFound')});
                    }

                    return models.User.edit({
                        email: profile.email_address,
                        status: 'active'
                    }, _.merge({id: owner.id}, options));
                });
        };

        models.User.getByEmail(profile.email_address, options)
            .then(function fetchedUser(user) {
                if (user) {
                    return user;
                }

                if (inviteToken) {
                    return handleInviteToken();
                }

                return handleSetup();
            })
            .then(function updateGhostAuthToken(user) {
                options.id = user.id;
                return models.User.edit({ghost_auth_access_token: ghostAuthAccessToken}, options);
            })
            .then(function returnResponse(user) {
                done(null, user, profile);
            })
            .catch(done);
    }
};

module.exports = strategies;
