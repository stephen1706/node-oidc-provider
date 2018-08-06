const url = require('url');

const _ = require('lodash');
const uuid = require('uuid/v4');
const debug = require('debug')('oidc-provider:bearer');

const { InvalidRequest } = require('./errors');
const instance = require('./weak_cache');

module.exports = function getContext(provider) {
  class OIDCContext {
    constructor(ctx) {
      this.ctx = ctx;
      this.route = ctx._matchedRouteName;
      this.authorization = {};
      this.redirectUriCheckPerformed = false;
      this.webMessageUriCheckPerformed = false;
      this.uuid = (ctx.params && ctx.params.grant) || uuid();
      this.entities = {};
      this.claims = {};
      this.issuer = provider.issuer;
    }

    entity(key, value) {
      this.entities[key] = value;
    }

    urlFor(name, opt) {
      const mountPath = (this.ctx.req.originalUrl && this.ctx.req.originalUrl.substring(
        0,
        this.ctx.req.originalUrl.indexOf(this.ctx.request.url),
      ))
        || this.ctx.mountPath // koa-mount
        || this.ctx.req.baseUrl // expressApp.use('/op', provider.callback);
        || ''; // no mount

      return url.resolve(this.ctx.href, provider.pathFor(name, { mountPath, ...opt }));
    }

    promptPending(name) {
      // result pass
      if (this.ctx.oidc.route.endsWith('resume')) {
        if (name === 'none') return true;

        const should = _.difference(this.prompts, Object.keys(this.result || {}));
        return should.includes(name);
      }

      // first pass
      return this.prompts && this.prompts.includes(name);
    }

    get claims() {
      const rejected = this.session.rejectedClaimsFor(this.client.clientId);
      return {
        ...instance(this).claims,
        ...(rejected
          ? { rejected: this.session.rejectedClaimsFor(this.client.clientId) } : undefined),
      };
    }

    set claims(value) {
      instance(this).claims = value;
    }

    get acr() {
      return _.get(this, 'result.login.acr');
    }

    get amr() {
      return _.get(this, 'result.login.amr');
    }

    get prompts() { return this.params.prompt ? this.params.prompt.split(' ') : []; }

    get bearer() {
      if ('bearer' in instance(this)) {
        return instance(this).bearer;
      }
      const { ctx } = this;
      const mechanisms = _.omitBy({
        body: _.get(ctx.oidc, 'body.access_token'),
        header: ctx.headers.authorization,
        query: ctx.query.access_token,
      }, _.isUndefined);

      debug('uuid=%s received bearer via %o', this.uuid, mechanisms);

      let mechanism;
      let length;
      let bearer;

      try {
        ({ 0: [mechanism, bearer], length } = Object.entries(mechanisms));
      } catch (err) {}

      if (!length) {
        throw new InvalidRequest('no bearer auth mechanism provided');
      }

      if (length > 1) {
        throw new InvalidRequest('bearer token must only be provided using one mechanism');
      }

      if (mechanism === 'header') {
        const header = bearer;
        const { 0: scheme, 1: value, length: parts } = header.split(' ');

        if (parts !== 2 || scheme !== 'Bearer') {
          throw new InvalidRequest('invalid authorization header value format');
        }

        bearer = value;
      }

      if (!bearer) {
        throw new InvalidRequest('no bearer token provided');
      }

      instance(this).bearer = bearer;
      return bearer;
    }

    get registrationAccessToken() {
      return this.entities.RegistrationAccessToken;
    }

    get deviceCode() {
      return this.entities.DeviceCode;
    }

    get account() {
      return this.entities.Account;
    }

    get client() {
      return this.entities.Client;
    }
  }

  return OIDCContext;
};
