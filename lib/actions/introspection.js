const Debug = require('debug');

const debug = new Debug('oidc-provider:introspection');
const uuidToGrantId = new Debug('oidc-provider:uuid');

const presence = require('../helpers/validate_presence');
const tokenAuth = require('../shared/token_auth');
const noCache = require('../shared/no_cache');
const mask = require('../helpers/claims');
const instance = require('../helpers/weak_cache');
const bodyParser = require('../shared/selective_body');
const rejectDupes = require('../shared/reject_dupes');
const getParams = require('../shared/assemble_params');
const { InvalidRequest } = require('../helpers/errors');

const introspectable = new Set(['AccessToken', 'ClientCredentials', 'RefreshToken']);
const PARAM_LIST = new Set(['token', 'token_type_hint', ...tokenAuth.AUTH_PARAMS]);
const JWT = 'application/jwt';

module.exports = function introspectionAction(provider) {
  const configuration = instance(provider).configuration();
  const { features: { jwtIntrospection } } = configuration;
  const Claims = mask(configuration);
  const parseBody = bodyParser('application/x-www-form-urlencoded');
  const buildParams = getParams(PARAM_LIST);
  const { grantTypeHandlers } = instance(provider);
  const {
    IdToken, AccessToken, ClientCredentials, RefreshToken, Client,
  } = provider;

  function getAccessToken(token) {
    return AccessToken.find(token);
  }

  function getClientCredentials(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('client_credentials')) return undefined;
    return ClientCredentials.find(token);
  }

  function getRefreshToken(token) {
    /* istanbul ignore if */
    if (!grantTypeHandlers.has('refresh_token')) return undefined;
    return RefreshToken.find(token);
  }

  function findResult(results) {
    return results.find(found => !!found);
  }

  return [
    noCache,
    parseBody,
    buildParams,
    ...tokenAuth(provider, 'introspection'),
    rejectDupes,

    async function validateTokenPresence(ctx, next) {
      presence(ctx, 'token');
      await next();
    },

    async function debugOutput(ctx, next) {
      await next();
      debug(
        'uuid=%s by client=%s token=%s response=%o',
        ctx.oidc.uuid,
        ctx.oidc.client.clientId,
        ctx.oidc.params.token, ctx.body,
      );
    },

    async function jwtIntrospectionResponse(ctx, next) {
      if (jwtIntrospection) {
        const { client } = ctx.oidc;

        const {
          introspectionEncryptedResponseAlg: encrypt,
          introspectionSignedResponseAlg: sign,
          introspectionEndpointAuthMethod: method,
        } = client;

        const accepts = ctx.accepts('json', JWT);
        if (encrypt && method === 'none' && accepts !== JWT) {
          throw new InvalidRequest(`introspection must be requested with Accept: ${JWT} for this client`);
        }

        await next();

        if ((encrypt || sign) && accepts === JWT) {
          const token = new IdToken({});
          token.extra = ctx.body;

          ctx.body = await token.sign(client, { use: 'introspection' });
          ctx.type = 'application/jwt; charset=utf-8';
        }
      } else {
        await next();
      }
    },

    async function renderTokenResponse(ctx, next) {
      const { params } = ctx.oidc;

      ctx.body = { active: false };

      let token;

      switch (params.token_type_hint) {
        case 'access_token':
          token = await getAccessToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getClientCredentials(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'client_credentials':
          token = await getClientCredentials(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getRefreshToken(params.token),
              ]).then(findResult);
            });
          break;
        case 'refresh_token':
          token = await getRefreshToken(params.token)
            .then((result) => {
              if (result) return result;
              return Promise.all([
                getAccessToken(params.token),
                getClientCredentials(params.token),
              ]).then(findResult);
            });
          break;
        default:
          token = await Promise.all([
            getAccessToken(params.token),
            getClientCredentials(params.token),
            getRefreshToken(params.token),
          ]).then(findResult);
      }

      if (!token || !token.isValid) {
        return;
      }
      if (token.grantId) {
        uuidToGrantId('switched from uuid=%s to value of grantId=%s', ctx.oidc.uuid, token.grantId);
        ctx.oidc.uuid = token.grantId;
      }

      if (ctx.oidc.client.introspectionEndpointAuthMethod === 'none') {
        if (token.clientId !== ctx.oidc.client.clientId) {
          return;
        }
      }

      if (introspectable.has(token.kind)) {
        ctx.oidc.entity(token.kind, token);
      } else {
        return;
      }

      if (token.clientId !== ctx.oidc.client.clientId) {
        ctx.body.sub = Claims.sub(
          token.accountId,
          (await Client.find(token.clientId)).sectorIdentifier,
        );
      } else {
        ctx.body.sub = Claims.sub(token.accountId, ctx.oidc.client.sectorIdentifier);
      }

      Object.assign(ctx.body, {
        active: true,
        client_id: token.clientId,
        exp: token.exp,
        iat: token.iat,
        sid: token.sid,
        iss: token.iss,
        jti: token.jti,
        aud: token.aud,
        perms: token.perms,
        scope: token.scope,
      });

      await next();
    },
  ];
};
