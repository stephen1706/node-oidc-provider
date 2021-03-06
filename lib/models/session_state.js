const storesAuth = require('./mixins/stores_auth');
const hasFormat = require('./mixins/has_format');
const consumable = require('./mixins/consumable');
const hasGrantType = require('./mixins/has_grant_type');
const apply = require('./mixins/apply');

module.exports = provider => class SessionState extends apply([
  consumable(provider),
  storesAuth,
  hasGrantType,
  hasFormat(provider, 'SessionState', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
    ];
  }
};
