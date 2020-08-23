const passport = require("passport-strategy");
const url = require("url");
const utils = require("./utils");
const random = require("bcrypto/lib/random");
const secp256k1 = require("bcrypto/lib/secp256k1");

function DomainStrategy(options, verify) {
  if (!options) throw new TypeError("DomainStrategy requires options");

  if (!options.callbackURL)
    throw new TypeError("DomainStrategy requires options.callbackURL");

  if (!verify) throw new TypeError("DomainStrategy requires a verify callback");

  passport.Strategy.call(this);
  this.name = "domain";

  this._verify = verify;
  this._callbackURL = options.callbackURL;
  this._trustProxy = options.proxy;
  this._authenticator = options.authenticator;
  this._sessionKey = options.sessionKey || "DomainStrategy";
  this._keyResolver =
    options.keyResolver || utils.keyResolver(options.dig || {});
}

DomainStrategy.prototype.authenticate = function (req, options = {}) {
  let callbackURL = options.callbackURL || this._callbackURL;
  const authenticator = options.authenticator || this._authenticator;
  const sessionKey = options.sessionKey || this._sessionKey;

  if (!req.session) {
    return this.error(
      "DomainStrategy requires session support. Did you forget to use express-session middleware?"
    );
  }

  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(
        utils.originalURL(req, { proxy: this._trustProxy }),
        callbackURL
      );
    }
  }

  if (req.query && req.query.signature) {
    const { challenge, key, signature, domain } = req.query;

    if (!challenge || !key || !signature || !domain) {
      return this.fail({ message: "Response incomplete" });
    }

    const expectedChallenge = req.session[sessionKey];
    if (challenge !== expectedChallenge)
      return this.fail({ message: "Invalid challenge" });

    const isValidSignature = secp256k1.verify(
      Buffer.from(challenge, "hex"),
      Buffer.from(signature, "hex"),
      Buffer.from(key, "hex")
    );

    if (!isValidSignature) return this.fail({ message: "Invalid signature" });

    const done = (err, user) => {
      if (err) return this.fail(err);
      if (!user) return this.fail("No user");

      this.success(user);
    };

    return this._keyResolver(domain)
      .then((domainKey) => {
        if (key !== domainKey) return this.fail({ message: "Invalid key" });

        try {
          return this._verify(domain, done);
        } catch (e) {
          return this.error(e);
        }
      })
      .catch((e) => {
        this.error(e);
      });
  } else {
    const challenge = random.randomBytes(32).toString("hex");
    req.session[sessionKey] = challenge;

    if (authenticator) {
      const provider = url.parse(authenticator);
      const search = new URLSearchParams(provider.search);
      search.append("challenge", challenge);
      search.append("callback", encodeURIComponent(callbackURL.toString()));
      provider.search = search.toString();

      this.redirect(provider.format());
    } else {
      this.redirect(`web+auth:${challenge}@${callbackURL}`);
    }
  }
};

module.exports = DomainStrategy;
