const DomainStrategy = require("../lib");
const chai = require("chai");
const sinon = require("sinon");
const utils = require("../lib/utils");

const OPTIONS = { callbackURL: "https://example.com/callback" };
const noop = () => {};

describe("DomainStrategy", function () {
  afterEach(() => {
    sinon.restore();
  });

  describe("constructed", function () {
    describe("with normal options", function () {
      var strategy = new DomainStrategy(OPTIONS, noop);

      it("should be named domain", function () {
        expect(strategy.name).to.equal("domain");
      });
    }); // with normal options

    describe("without a verify callback", function () {
      it("should throw", function () {
        expect(function () {
          new DomainStrategy({});
        }).to.throw(TypeError, "DomainStrategy requires options.callbackURL");
      });
    }); // without a verify callback

    describe("with only a verify callback", function () {
      it("should throw", function () {
        expect(function () {
          new DomainStrategy(noop);
        }).to.throw(TypeError, "DomainStrategy requires options.callbackURL");
      });
    }); // with only a verify callback
  }); // constructed

  describe("Session", function () {
    var strategy = new DomainStrategy(OPTIONS, noop);
    var err;

    before(function (done) {
      chai.passport
        .use(strategy)
        .error(function (e) {
          err = e;
          done();
        })
        // .req(function (req) {
        //   req.query = {};
        //   req.query.error = "invalid_scope";
        // })
        .authenticate();
    });

    it("should throw error if there's no session", function () {
      expect(err).to.equal(
        "DomainStrategy requires session support. Did you forget to use express-session middleware?"
      );
    });
  }); // session

  describe("Redirecting requests", function () {
    describe("using web+auth", function () {
      var strategy = new DomainStrategy(OPTIONS, noop);
      var url;

      before(function (done) {
        chai.passport
          .use(strategy)
          .redirect(function (u) {
            url = u;
            done();
          })
          .req(function (req) {
            req.session = {};
          })
          .authenticate();
      });

      it("should be redirected", function () {
        console.log(url);
        expect(url).to.match(
          /web\+auth:[a-f0-9]{64}@https:\/\/example\.com\/callback/
        );
      });
    }); // web+auth

    describe("using authenticator", function () {
      var strategy = new DomainStrategy(
        { ...OPTIONS, authenticator: "https://service.com/?sess=123" },
        noop
      );
      var url;

      before(function (done) {
        chai.passport
          .use(strategy)
          .redirect(function (u) {
            url = u;
            done();
          })
          .req(function (req) {
            req.session = {};
          })
          .authenticate();
      });

      it("should be redirected", function () {
        expect(url).to.match(
          /https:\/\/service\.com\/\?sess=123&challenge=[a-f0-9]{64}&callback=https%253A%252F%252Fexample.com%252Fcallback/
        );
      });
    }); // authenticator
  }); // that redirects to service provider with redirect URI

  describe("Callback", () => {
    describe("Success case", () => {
      var keyResolver = sinon.stub();
      sinon.stub(utils, "keyResolver").returns(keyResolver);

      var strategy = new DomainStrategy(OPTIONS, (_, done) => {
        return done(null, { id: "1234" });
      });

      var user;

      before(function (done) {
        keyResolver
          .withArgs("example.com")
          .resolves(
            "024033389cf6632a172546748fda79e7fbabce944b552db5dba81b16c01fec377b"
          );

        chai.passport
          .use(strategy)
          .success(function (u) {
            user = u;
            done();
          })
          .req(function (req) {
            req.session = {
              DomainStrategy:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
            };

            req.query = {
              challenge:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
              key:
                "024033389cf6632a172546748fda79e7fbabce944b552db5dba81b16c01fec377b",
              signature:
                "d4bbe31bee163a32b778db64c7f9ce2dfa6f1c0ed5837e8f9c1f5b39fac1e11f0a23db625bcd1e414d249896b5f0519c3f8dd5bd02b41ffa58b4f73b18c359cc",
              domain: "example.com",
            };
          })
          .authenticate();
      });

      it("should supply user", function () {
        expect(user).to.be.an("object");
        expect(user.id).to.equal("1234");
      });
    });

    describe("Custom keyResolver", () => {
      var keyResolver = sinon.stub();

      var strategy = new DomainStrategy(
        { ...OPTIONS, keyResolver },
        (domain, done) => {
          if (domain !== "example.com") {
            return done(new Error("incorrect domain"));
          }

          return done(null, { id: "1234" });
        }
      );

      var user;

      before(function (done) {
        keyResolver
          .withArgs("example.com")
          .resolves(
            "024033389cf6632a172546748fda79e7fbabce944b552db5dba81b16c01fec377b"
          );

        chai.passport
          .use(strategy)
          .success(function (u) {
            user = u;
            done();
          })
          .req(function (req) {
            req.session = {
              DomainStrategy:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
            };

            req.query = {
              challenge:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
              key:
                "024033389cf6632a172546748fda79e7fbabce944b552db5dba81b16c01fec377b",
              signature:
                "d4bbe31bee163a32b778db64c7f9ce2dfa6f1c0ed5837e8f9c1f5b39fac1e11f0a23db625bcd1e414d249896b5f0519c3f8dd5bd02b41ffa58b4f73b18c359cc",
              domain: "example.com",
            };
          })
          .authenticate();
      });

      it("should supply user", function () {
        expect(user).to.be.an("object");
        expect(user.id).to.equal("1234");
      });
    });

    describe("Missing param", () => {
      var strategy = new DomainStrategy(OPTIONS, noop);

      var error;

      before(function (done) {
        chai.passport
          .use(strategy)
          .fail(function (e) {
            error = e;
            done();
          })
          .req(function (req) {
            req.session = {};
            req.query = {
              // no challenge nor key
              signature: "example",
              domain: "example.com",
            };
          })
          .authenticate();
      });

      it("should get a fail message", function () {
        expect(error).to.deep.equal({ message: "Response incomplete" });
      });
    });

    describe("Invalid challenge", () => {
      var strategy = new DomainStrategy(OPTIONS, noop);

      var error;

      before(function (done) {
        chai.passport
          .use(strategy)
          .fail(function (e) {
            error = e;
            done();
          })
          .req(function (req) {
            req.session = { DomainStrategy: "EXPECTED" };
            req.query = {
              challenge: "WRONG",
              key: "KEY",
              signature: "SIG",
              domain: "example.com",
            };
          })
          .authenticate();
      });

      it("should get a fail message", function () {
        expect(error).to.deep.equal({ message: "Invalid challenge" });
      });
    });

    describe("Invalid signature", () => {
      var strategy = new DomainStrategy(OPTIONS, noop);

      var error;

      before(function (done) {
        chai.passport
          .use(strategy)
          .fail(function (e) {
            error = e;
            done();
          })
          .req(function (req) {
            req.session = {
              DomainStrategy:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
            };
            req.query = {
              challenge:
                "443658c2040afa6867f63ca73e2bbc71bc58dc77ddccc1004a75cef426983023",
              key:
                "024033389cf6632a172546748fda79e7fbabce944b552db5dba81b16c01fec377b",
              signature: "INVALID_SIG",
              domain: "example.com",
            };
          })
          .authenticate();
      });

      it("should get a fail message", function () {
        expect(error).to.deep.equal({ message: "Invalid signature" });
      });
    });
  });

  //   describe("processing response to authorization request", function () {
  //     describe("that was approved without redirect URI", function () {
  //

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (options.redirect_uri !== undefined) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved without redirect URI

  //     describe("that was approved with redirect URI", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved with redirect URI

  //     describe("that was approved with redirect URI option", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback/alt1"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate({
  //             callbackURL: "https://www.example.net/auth/example/callback/alt1",
  //           });
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved with redirect URI option

  //     describe("that was approved with relative redirect URI option", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback/alt2"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.url = "/auth/example/callback/alt2";
  //             req.headers.host = "www.example.net";
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //             req.connection = { encrypted: true };
  //           })
  //           .authenticate({ callbackURL: "/auth/example/callback/alt2" });
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved with relative redirect URI option

  //     describe("that was approved using verify callback that accepts params", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (params.example_parameter !== "example_value") {
  //             return done(new Error("incorrect params argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           {
  //             token_type: "example",
  //             expires_in: 3600,
  //             example_parameter: "example_value",
  //           }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved using verify callback that accepts params

  //     describe("that was approved using verify callback, in passReqToCallback mode", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //           passReqToCallback: true,
  //         },
  //         function (req, accessToken, refreshToken, profile, done) {
  //           if (req.method != "GET") {
  //             return done(new Error("incorrect req argument"));
  //           }
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example", expires_in: 3600 }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved using verify callback, in passReqToCallback mode

  //     describe("that was approved using verify callback that accepts params, in passReqToCallback mode", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //           passReqToCallback: true,
  //         },
  //         function (req, accessToken, refreshToken, params, profile, done) {
  //           if (req.method != "GET") {
  //             return done(new Error("incorrect req argument"));
  //           }
  //           if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //             return done(new Error("incorrect accessToken argument"));
  //           }
  //           if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //             return done(new Error("incorrect refreshToken argument"));
  //           }
  //           if (params.example_parameter !== "example_value") {
  //             return done(new Error("incorrect params argument"));
  //           }
  //           if (typeof profile !== "object") {
  //             return done(new Error("incorrect profile argument"));
  //           }
  //           if (Object.keys(profile).length !== 0) {
  //             return done(new Error("incorrect profile argument"));
  //           }

  //           return done(null, { id: "1234" }, { message: "Hello" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           {
  //             token_type: "example",
  //             expires_in: 3600,
  //             example_parameter: "example_value",
  //           }
  //         );
  //       };

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .success(function (u, i) {
  //             user = u;
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply user", function () {
  //         expect(user).to.be.an.object;
  //         expect(user.id).to.equal("1234");
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Hello");
  //       });
  //     }); // that was approved using verify callback that accepts params, in passReqToCallback mode

  //     describe("that fails due to verify callback supplying false", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {
  //           return done(null, false);
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .fail(function (i) {
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should not supply info", function () {
  //         expect(info).to.be.undefined;
  //       });
  //     }); // that fails due to verify callback supplying false

  //     describe("that fails due to verify callback supplying false with additional info", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {
  //           return done(null, false, { message: "Invite required" });
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //           return callback(new Error("incorrect code argument"));
  //         }
  //         if (options.grant_type !== "authorization_code") {
  //           return callback(new Error("incorrect options.grant_type argument"));
  //         }
  //         if (
  //           options.redirect_uri !==
  //           "https://www.example.net/auth/example/callback"
  //         ) {
  //           return callback(new Error("incorrect options.redirect_uri argument"));
  //         }

  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .fail(function (i) {
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should supply info", function () {
  //         expect(info).to.be.an.object;
  //         expect(info.message).to.equal("Invite required");
  //       });
  //     }); // that fails due to verify callback supplying false with additional info

  //     describe("that was denied", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .fail(function (i) {
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.error = "access_denied";
  //           })
  //           .authenticate();
  //       });

  //       it("should fail without message", function () {
  //         expect(info).to.not.be.undefined;
  //         expect(info.message).to.be.undefined;
  //       });
  //     }); // that was denied

  //     describe("that was denied with description", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       var user, info;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .fail(function (i) {
  //             info = i;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.error = "access_denied";
  //             req.query.error_description = "Why oh why?";
  //           })
  //           .authenticate();
  //       });

  //       it("should fail with message", function () {
  //         expect(info).to.not.be.undefined;
  //         expect(info.message).to.equal("Why oh why?");
  //       });
  //     }); // that was denied with description

  //     describe("that was returned with an error without description", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.error = "invalid_scope";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(AuthorizationError);
  //         expect(err.message).to.be.undefined;
  //         expect(err.code).to.equal("invalid_scope");
  //         expect(err.uri).to.be.undefined;
  //         expect(err.status).to.equal(500);
  //       });
  //     }); // that was returned with an error without description

  //     describe("that was returned with an error with description", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.error = "invalid_scope";
  //             req.query.error_description = "The scope is invalid";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(AuthorizationError);
  //         expect(err.message).to.equal("The scope is invalid");
  //         expect(err.code).to.equal("invalid_scope");
  //         expect(err.uri).to.be.undefined;
  //         expect(err.status).to.equal(500);
  //       });
  //     }); // that was returned with an error with description

  //     describe("that was returned with an error with description and link", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.error = "invalid_scope";
  //             req.query.error_description = "The scope is invalid";
  //             req.query.error_uri = "http://www.example.com/oauth2/help";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(AuthorizationError);
  //         expect(err.message).to.equal("The scope is invalid");
  //         expect(err.code).to.equal("invalid_scope");
  //         expect(err.uri).to.equal("http://www.example.com/oauth2/help");
  //         expect(err.status).to.equal(500);
  //       });
  //     }); // that was returned with an error with description and link

  //     describe("that errors due to token request error", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           return done(new Error("verify callback should not be called"));
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback(new Error("something went wrong"));
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(InternalOAuthError);
  //         expect(err.message).to.equal("Failed to obtain access token");
  //         expect(err.oauthError.message).to.equal("something went wrong");
  //       });
  //     }); // that errors due to token request error

  //     describe("that errors due to token request error, in node-oauth object literal form with OAuth 2.0-compatible body", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           return done(new Error("verify callback should not be called"));
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback({
  //           statusCode: 400,
  //           data:
  //             '{"error":"invalid_grant","error_description":"The provided value for the input parameter \'code\' is not valid."} ',
  //         });
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(TokenError);
  //         expect(err.message).to.equal(
  //           "The provided value for the input parameter 'code' is not valid."
  //         );
  //         expect(err.code).to.equal("invalid_grant");
  //         expect(err.oauthError).to.be.undefined;
  //       });
  //     }); // that errors due to token request error, in node-oauth object literal form with OAuth 2.0-compatible body

  //     describe("that errors due to token request error, in node-oauth object literal form with JSON body", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           return done(new Error("verify callback should not be called"));
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback({
  //           statusCode: 400,
  //           data: '{"error_code":"invalid_grant"}',
  //         });
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(InternalOAuthError);
  //         expect(err.message).to.equal("Failed to obtain access token");
  //         expect(err.oauthError.statusCode).to.equal(400);
  //         expect(err.oauthError.data).to.equal('{"error_code":"invalid_grant"}');
  //       });
  //     }); // that errors due to token request error, in node-oauth object literal form with JSON body

  //     describe("that errors due to token request error, in node-oauth object literal form with text body", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           return done(new Error("verify callback should not be called"));
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback({ statusCode: 500, data: "Something went wrong" });
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(InternalOAuthError);
  //         expect(err.message).to.equal("Failed to obtain access token");
  //         expect(err.oauthError.statusCode).to.equal(500);
  //         expect(err.oauthError.data).to.equal("Something went wrong");
  //       });
  //     }); // that errors due to token request error, in node-oauth object literal form with text body

  //     describe("that errors due to verify callback supplying error", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           return done(new Error("something went wrong"));
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(Error);
  //         expect(err.message).to.equal("something went wrong");
  //       });
  //     }); // that errors due to verify callback supplying error

  //     describe("that errors due to verify callback throwing error", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "https://www.example.net/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, params, profile, done) {
  //           throw new Error("something was thrown");
  //         }
  //       );

  //       strategy._oauth2.getOAuthAccessToken = function (
  //         code,
  //         options,
  //         callback
  //       ) {
  //         return callback(
  //           null,
  //           "2YotnFZFEjr1zCsicMWpAA",
  //           "tGzv3JOkF0XG5Qx2TlKWIA",
  //           { token_type: "example" }
  //         );
  //       };

  //       var err;

  //       before(function (done) {
  //         chai.passport
  //           .use(strategy)
  //           .error(function (e) {
  //             err = e;
  //             done();
  //           })
  //           .req(function (req) {
  //             req.query = {};
  //             req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //           })
  //           .authenticate();
  //       });

  //       it("should error", function () {
  //         expect(err).to.be.an.instanceof(Error);
  //         expect(err.message).to.equal("something was thrown");
  //       });
  //     }); // that errors due to verify callback throwing error
  //   }); // processing response to authorization request

  //   describe("using a relative redirect URI", function () {
  //     describe("issuing authorization request", function () {
  //       var strategy = new DomainStrategy(
  //         {
  //           authorizationURL: "https://www.example.com/oauth2/authorize",
  //           tokenURL: "https://www.example.com/oauth2/token",
  //           clientID: "ABC123",
  //           clientSecret: "secret",
  //           callbackURL: "/auth/example/callback",
  //         },
  //         function (accessToken, refreshToken, profile, done) {}
  //       );

  //       describe("that redirects to service provider from secure connection", function () {
  //         var url;

  //         before(function (done) {
  //           chai.passport
  //             .use(strategy)
  //             .redirect(function (u) {
  //               url = u;
  //               done();
  //             })
  //             .req(function (req) {
  //               req.url = "/auth/example";
  //               req.headers.host = "www.example.net";
  //               req.connection = { encrypted: true };
  //             })
  //             .authenticate();
  //         });

  //         it("should be redirected", function () {
  //           expect(url).to.equal(
  //             "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //           );
  //         });
  //       }); // that redirects to service provider from secure connection

  //       describe("that redirects to service provider from insecure connection", function () {
  //         var url;

  //         before(function (done) {
  //           chai.passport
  //             .use(strategy)
  //             .redirect(function (u) {
  //               url = u;
  //               done();
  //             })
  //             .req(function (req) {
  //               req.url = "/auth/example";
  //               req.headers.host = "www.example.net";
  //               req.connection = {};
  //             })
  //             .authenticate();
  //         });

  //         it("should be redirected", function () {
  //           expect(url).to.equal(
  //             "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //           );
  //         });
  //       }); // that redirects to service provider from insecure connection

  //       describe("from behind a secure proxy", function () {
  //         describe("that is trusted by app and sets x-forwarded-proto", function () {
  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.app = {
  //                   get: function (name) {
  //                     return name == "trust proxy" ? true : false;
  //                   },
  //                 };

  //                 req.url = "/auth/example";
  //                 req.headers.host = "www.example.net";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is trusted by app and sets x-forwarded-proto

  //         describe("that is trusted by app and sets x-forwarded-proto and x-forwarded-host", function () {
  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.app = {
  //                   get: function (name) {
  //                     return name == "trust proxy" ? true : false;
  //                   },
  //                 };

  //                 req.url = "/auth/example";
  //                 req.headers.host = "server.internal";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.headers["x-forwarded-host"] = "www.example.net";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is trusted by app and sets x-forwarded-proto and x-forwarded-host

  //         describe("that is not trusted by app and sets x-forwarded-proto", function () {
  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.app = {
  //                   get: function (name) {
  //                     return name == "trust proxy" ? false : false;
  //                   },
  //                 };

  //                 req.url = "/auth/example";
  //                 req.headers.host = "www.example.net";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is trusted by app and sets x-forwarded-proto and x-forwarded-host

  //         describe("that is not trusted by app and sets x-forwarded-proto and x-forwarded-host", function () {
  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.app = {
  //                   get: function (name) {
  //                     return name == "trust proxy" ? false : false;
  //                   },
  //                 };

  //                 req.url = "/auth/example";
  //                 req.headers.host = "server.internal";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.headers["x-forwarded-host"] = "www.example.net";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fserver.internal%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is not trusted by app and sets x-forwarded-proto and x-forwarded-host

  //         describe("that is trusted by strategy and sets x-forwarded-proto", function () {
  //           var strategy = new DomainStrategy(
  //             {
  //               authorizationURL: "https://www.example.com/oauth2/authorize",
  //               tokenURL: "https://www.example.com/oauth2/token",
  //               clientID: "ABC123",
  //               clientSecret: "secret",
  //               callbackURL: "/auth/example/callback",
  //               proxy: true,
  //             },
  //             function (accessToken, refreshToken, profile, done) {}
  //           );

  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.url = "/auth/example";
  //                 req.headers.host = "www.example.net";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is trusted by strategy and sets x-forwarded-proto

  //         describe("that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host", function () {
  //           var strategy = new DomainStrategy(
  //             {
  //               authorizationURL: "https://www.example.com/oauth2/authorize",
  //               tokenURL: "https://www.example.com/oauth2/token",
  //               clientID: "ABC123",
  //               clientSecret: "secret",
  //               callbackURL: "/auth/example/callback",
  //               proxy: true,
  //             },
  //             function (accessToken, refreshToken, profile, done) {}
  //           );

  //           var url;

  //           before(function (done) {
  //             chai.passport
  //               .use(strategy)
  //               .redirect(function (u) {
  //                 url = u;
  //                 done();
  //               })
  //               .req(function (req) {
  //                 req.url = "/auth/example";
  //                 req.headers.host = "server.internal";
  //                 req.headers["x-forwarded-proto"] = "https";
  //                 req.headers["x-forwarded-host"] = "www.example.net";
  //                 req.connection = {};
  //               })
  //               .authenticate();
  //           });

  //           it("should be redirected", function () {
  //             expect(url).to.equal(
  //               "https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123"
  //             );
  //           });
  //         }); // that is trusted by strategy and sets x-forwarded-proto and x-forwarded-host
  //       }); // from behind a secure proxy
  //     }); // issuing authorization request

  //     describe("processing response to authorization request", function () {
  //       describe("that was approved over secure connection", function () {
  //         var strategy = new DomainStrategy(
  //           {
  //             authorizationURL: "https://www.example.com/oauth2/authorize",
  //             tokenURL: "https://www.example.com/oauth2/token",
  //             clientID: "ABC123",
  //             clientSecret: "secret",
  //             callbackURL: "/auth/example/callback",
  //           },
  //           function (accessToken, refreshToken, profile, done) {
  //             if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //               return done(new Error("incorrect accessToken argument"));
  //             }
  //             if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //               return done(new Error("incorrect refreshToken argument"));
  //             }
  //             if (typeof profile !== "object") {
  //               return done(new Error("incorrect profile argument"));
  //             }
  //             if (Object.keys(profile).length !== 0) {
  //               return done(new Error("incorrect profile argument"));
  //             }

  //             return done(null, { id: "1234" }, { message: "Hello" });
  //           }
  //         );

  //         strategy._oauth2.getOAuthAccessToken = function (
  //           code,
  //           options,
  //           callback
  //         ) {
  //           if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //             return callback(new Error("incorrect code argument"));
  //           }
  //           if (options.grant_type !== "authorization_code") {
  //             return callback(new Error("incorrect options.grant_type argument"));
  //           }
  //           if (
  //             options.redirect_uri !==
  //             "https://www.example.net/auth/example/callback"
  //           ) {
  //             return callback(
  //               new Error("incorrect options.redirect_uri argument")
  //             );
  //           }

  //           return callback(
  //             null,
  //             "2YotnFZFEjr1zCsicMWpAA",
  //             "tGzv3JOkF0XG5Qx2TlKWIA",
  //             { token_type: "example" }
  //           );
  //         };

  //         var user, info;

  //         before(function (done) {
  //           chai.passport
  //             .use(strategy)
  //             .success(function (u, i) {
  //               user = u;
  //               info = i;
  //               done();
  //             })
  //             .req(function (req) {
  //               req.url = "/auth/example";
  //               req.headers.host = "www.example.net";
  //               req.query = {};
  //               req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //               req.connection = { encrypted: true };
  //             })
  //             .authenticate();
  //         });

  //         it("should supply user", function () {
  //           expect(user).to.be.an.object;
  //           expect(user.id).to.equal("1234");
  //         });

  //         it("should supply info", function () {
  //           expect(info).to.be.an.object;
  //           expect(info.message).to.equal("Hello");
  //         });
  //       }); // that was approved over secure connection

  //       describe("that was approved over insecure connection", function () {
  //         var strategy = new DomainStrategy(
  //           {
  //             authorizationURL: "https://www.example.com/oauth2/authorize",
  //             tokenURL: "https://www.example.com/oauth2/token",
  //             clientID: "ABC123",
  //             clientSecret: "secret",
  //             callbackURL: "/auth/example/callback",
  //           },
  //           function (accessToken, refreshToken, profile, done) {
  //             if (accessToken !== "2YotnFZFEjr1zCsicMWpAA") {
  //               return done(new Error("incorrect accessToken argument"));
  //             }
  //             if (refreshToken !== "tGzv3JOkF0XG5Qx2TlKWIA") {
  //               return done(new Error("incorrect refreshToken argument"));
  //             }
  //             if (typeof profile !== "object") {
  //               return done(new Error("incorrect profile argument"));
  //             }
  //             if (Object.keys(profile).length !== 0) {
  //               return done(new Error("incorrect profile argument"));
  //             }

  //             return done(null, { id: "1234" }, { message: "Hello" });
  //           }
  //         );

  //         strategy._oauth2.getOAuthAccessToken = function (
  //           code,
  //           options,
  //           callback
  //         ) {
  //           if (code !== "SplxlOBeZQQYbYS6WxSbIA") {
  //             return callback(new Error("incorrect code argument"));
  //           }
  //           if (options.grant_type !== "authorization_code") {
  //             return callback(new Error("incorrect options.grant_type argument"));
  //           }
  //           if (
  //             options.redirect_uri !==
  //             "http://www.example.net/auth/example/callback"
  //           ) {
  //             return callback(
  //               new Error("incorrect options.redirect_uri argument")
  //             );
  //           }

  //           return callback(
  //             null,
  //             "2YotnFZFEjr1zCsicMWpAA",
  //             "tGzv3JOkF0XG5Qx2TlKWIA",
  //             { token_type: "example" }
  //           );
  //         };

  //         var user, info;

  //         before(function (done) {
  //           chai.passport
  //             .use(strategy)
  //             .success(function (u, i) {
  //               user = u;
  //               info = i;
  //               done();
  //             })
  //             .req(function (req) {
  //               req.url = "/auth/example";
  //               req.headers.host = "www.example.net";
  //               req.query = {};
  //               req.query.code = "SplxlOBeZQQYbYS6WxSbIA";
  //               req.connection = {};
  //             })
  //             .authenticate();
  //         });

  //         it("should supply user", function () {
  //           expect(user).to.be.an.object;
  //           expect(user.id).to.equal("1234");
  //         });

  //         it("should supply info", function () {
  //           expect(info).to.be.an.object;
  //           expect(info.message).to.equal("Hello");
  //         });
  //       }); // that was approved over insecure connection
  //     }); // processing response to authorization request
  //   }); // using a relative redirect URI
});
