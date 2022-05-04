const Strategy = require('./BaseStrategy');
const OAuth2 = require('oauth').OAuth2;

class MultiStrategy extends Strategy {
  constructor(options, verify) {
    if (!options || typeof options.getOpenIdConfig !== 'function') {
      throw new Error('getOpenIdConfig param must be a function');
    }

    const openIdConfig = {
      ...options,
    };

    super(openIdConfig, verify, false);
    this._options = openIdConfig;
  }

  authenticate(req, options) {
    this._options.getOpenIdConfig(req, (err, openIdOptions) => {
      if (err) {
        return this.error(err);
      }

      const openIdService = new OAuth2(openIdOptions.clientID,  openIdOptions.clientSecret, '', openIdOptions.authorizationURL, openIdOptions.tokenURL, openIdOptions.customHeaders);
      openIdService.useAuthorizationHeaderforGET(true);

      if (openIdOptions.agent) {
        openIdService.setAgent(options.agent);
      }
      
      const strategy = Object.assign({}, this, { _oauth2: openIdService });
      Object.setPrototypeOf(strategy, this);
      super.authenticate.call(strategy, req, options);
    });
  }

  error(err) {
    super.error(err);
  }
}

module.exports = MultiStrategy;