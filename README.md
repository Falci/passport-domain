## Install

    $ npm install passport-domain

## Usage

#### Configure Strategy

The domain authentication strategy authenticates users using a third-party
authenticator and domain. The strategy
requires a `verify` callback, which receives an access token and profile,
and calls `cb` providing a user.

```js
passport.use(
  new DomainStrategy(
    {
      callbackURL: "http://localhost:3000/auth/domain/callback",
    },
    function (domain, cb) {
      User.findOrCreate({ domain: domain }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'domain'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get("/auth/domain", passport.authenticate("domain"));

app.get(
  "/auth/domain/callback",
  passport.authenticate("domain", { failureRedirect: "/auth" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/");
  }
);
```
