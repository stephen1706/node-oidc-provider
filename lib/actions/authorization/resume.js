const url = require('url');

const uuid = require('uuid/v4');
const _ = require('lodash');

const { SessionNotFound } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const getParams = require('../../helpers/params');

module.exports = function getResumeAction(provider, whitelist, resumeRouteName) {
  const Params = getParams(whitelist);
  return async function resumeAction(ctx, next) {
    const cookieOptions = _.omit(instance(provider).configuration('cookies.short'), 'maxAge', 'expires');

    const cookieId = ctx.cookies.get(provider.cookieName('resume'), cookieOptions);
    if (!cookieId || cookieId !== ctx.oidc.uuid) {
      throw new SessionNotFound('authorization request has expired');
    }

    const interactionSession = await provider.Session.find(cookieId, { upsert: false });
    if (!interactionSession) {
      throw new SessionNotFound('interaction session not found');
    }

    const {
      result,
      params: storedParams = {},
      signed = [],
    } = interactionSession;

    await interactionSession.destroy();

    const params = new Params(storedParams);
    ctx.oidc.params = params;
    ctx.oidc.signed = signed;
    ctx.oidc.redirectUriCheckPerformed = true;

    const clearOpts = _.defaults({}, cookieOptions, {
      path: url.parse(ctx.oidc.urlFor(resumeRouteName, {
        grant: ctx.oidc.uuid,
        ...(ctx.params.user_code ? { user_code: ctx.params.user_code } : undefined),
      })).pathname,
    });
    ctx.cookies.set(provider.cookieName('resume'), null, clearOpts);

    if (result && result.error) {
      ctx.throw(400, result.error, {
        error_description: result.error_description,
      });
    }
    const { session } = ctx.oidc;

    if (result && result.login) {
      if (!result.login.remember) session.transient = true;

      if (session.account !== result.login.account) {
        delete session.authorizations;
      }

      session.account = result.login.account;
      session.loginTs = result.login.ts;
    }

    if (result && result.consent) {
      const { scope, rejectedClaims } = result.consent;

      if (scope !== undefined) {
        params.scope = String(scope);
      }

      if (rejectedClaims) {
        session.rejectedClaimsFor(params.client_id, rejectedClaims);
      }
    }

    const acceptedScopes = params.scope.split(' ').filter(Boolean);
    session.acceptedScopesFor(params.client_id, acceptedScopes);

    if (!_.isEmpty(result) && !session.sidFor(params.client_id)) {
      session.sidFor(params.client_id, uuid());
    }

    if (!_.isEmpty(result) && _.isObjectLike(result.meta)) {
      session.metaFor(params.client_id, result.meta);
    }

    ctx.oidc.result = result;

    await next();
  };
};
