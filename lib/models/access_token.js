const setAudiences = require('./mixins/set_audiences');
const setPermissions = require('./mixins/set_permissions');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const apply = require('./mixins/apply');

module.exports = provider => class AccessToken extends apply([
  setAudiences,
  setPermissions,
  hasGrantType,
  hasFormat(provider, 'AccessToken', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,

      'accountId',
      'claims',
      'grantId',
      'sid',
      'aud',
      'scope',
      'astroAccountLink',
      'profileId',
      'perms',
    ];
  }
};
