// # SpamPrevention Middleware
// Usage: spamPrevention
// After:
// Before:
// App: Admin|Blog|API
//
// Helpers to handle spam detection on signin, forgot password, and protected pages.
// 这个方式的实现，要比我认为的hashmap的方式可能还高效一些，牺牲内存主要是这种方式节省了cpu运算，主观感觉上
// 但这种方式的问题就是只能控制单一node进程，如果能用nginx进行精细控制就好了，当然也可以将访问记录存储的redis中
// 也不失为一种方式

var _ = require('lodash'),
    errors    = require('../errors'),
    config    = require('../config'),
    i18n      = require('../i18n'),
    loginSecurity = [],
    forgottenSecurity = [],
    spamPrevention;

spamPrevention = {
    /*jslint unparam:true*/
    // limit signin requests to ten failed requests per IP per hour
    signin: function signin(req, res, next) {
        var currentTime = process.hrtime()[0],
            remoteAddress = req.connection.remoteAddress,
            deniedRateLimit = '',
            ipCount = '',
            rateSigninPeriod = config.rateSigninPeriod || 3600,
            rateSigninAttempts = config.rateSigninAttempts || 10;

        if (req.body.username && req.body.grant_type === 'password') {
            loginSecurity.push({ip: remoteAddress, time: currentTime, email: req.body.username});
        } else if (req.body.grant_type === 'refresh_token') {
            return next();
        } else {
            return next(new errors.BadRequestError({message: i18n.t('errors.middleware.spamprevention.noUsername')}));
        }

        // filter entries that are older than rateSigninPeriod
        loginSecurity = _.filter(loginSecurity, function filter(logTime) { //:bm: this is where loginSecurity got reset.
            return (logTime.time + rateSigninPeriod > currentTime);
        });

        // check number of tries per IP address
        ipCount = _.chain(loginSecurity).countBy('ip').value();
        deniedRateLimit = (ipCount[remoteAddress] > rateSigninAttempts);

        if (deniedRateLimit) {
            return next(new errors.TooManyRequestsError({
                message: i18n.t('errors.middleware.spamprevention.tooManyAttempts') + rateSigninPeriod === 3600 ? i18n.t('errors.middleware.spamprevention.waitOneHour') : i18n.t('errors.middleware.spamprevention.tryAgainLater'),
                context: i18n.t('errors.middleware.spamprevention.tooManySigninAttempts.error', {rateSigninAttempts: rateSigninAttempts, rateSigninPeriod: rateSigninPeriod}),
                help: i18n.t('errors.middleware.spamprevention.tooManySigninAttempts.context')
            }));
        }
        next();
    },

    // limit forgotten password requests to five requests per IP per hour for different email addresses
    // limit forgotten password requests to five requests per email address
    forgotten: function forgotten(req, res, next) {
        var currentTime = process.hrtime()[0],
            remoteAddress = req.connection.remoteAddress,
            rateForgottenPeriod = config.rateForgottenPeriod || 3600,
            rateForgottenAttempts = config.rateForgottenAttempts || 5,
            email = req.body.passwordreset[0].email,
            ipCount = '',
            deniedRateLimit = '',
            deniedEmailRateLimit = '',
            index = _.findIndex(forgottenSecurity, function findIndex(logTime) {
                return (logTime.ip === remoteAddress && logTime.email === email);
            });

        if (email) {
            if (index !== -1) {
                forgottenSecurity[index].count = forgottenSecurity[index].count + 1;
            } else {
                forgottenSecurity.push({ip: remoteAddress, time: currentTime, email: email, count: 0});
            }
        } else {
            return next(new errors.BadRequestError({message: i18n.t('errors.middleware.spamprevention.noEmail')}));
        }

        // filter entries that are older than rateForgottenPeriod
        forgottenSecurity = _.filter(forgottenSecurity, function filter(logTime) {
            return (logTime.time + rateForgottenPeriod > currentTime);
        });

        // check number of tries with different email addresses per IP
        ipCount = _.chain(forgottenSecurity).countBy('ip').value();
        deniedRateLimit = (ipCount[remoteAddress] > rateForgottenAttempts);

        if (index !== -1) {
            deniedEmailRateLimit = (forgottenSecurity[index].count > rateForgottenAttempts);
        }

        if (deniedEmailRateLimit) {
            return next(new errors.TooManyRequestsError({
                message: i18n.t('errors.middleware.spamprevention.tooManyAttempts') + rateForgottenPeriod === 3600 ? i18n.t('errors.middleware.spamprevention.waitOneHour') : i18n.t('errors.middleware.spamprevention.tryAgainLater'),
                context: i18n.t('errors.middleware.spamprevention.forgottenPasswordEmail.error', {
                    rfa: rateForgottenAttempts,
                    rfp: rateForgottenPeriod
                }),
                help: i18n.t('errors.middleware.spamprevention.forgottenPasswordEmail.context')
            }));
        }

        if (deniedRateLimit) {
            return next(new errors.TooManyRequestsError({
                message: i18n.t('errors.middleware.spamprevention.tooManyAttempts') + rateForgottenPeriod === 3600 ? i18n.t('errors.middleware.spamprevention.waitOneHour') : i18n.t('errors.middleware.spamprevention.tryAgainLater'),
                context: i18n.t('errors.middleware.spamprevention.forgottenPasswordIp.error', {rfa: rateForgottenAttempts, rfp: rateForgottenPeriod}),
                help: i18n.t('errors.middleware.spamprevention.forgottenPasswordIp.context')
            }));
        }

        next();
    },

    resetCounter: function resetCounter(email) {
        loginSecurity = _.filter(loginSecurity, function filter(logTime) {
            return (logTime.email !== email);
        });
    }
};

module.exports = spamPrevention;
