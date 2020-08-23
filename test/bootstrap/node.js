// from https://github.com/jaredhanson/passport-oauth2/blob/master/test/bootstrap/node.js
const chai = require("chai");
const passport = require("chai-passport-strategy");
const sinonChai = require("sinon-chai");

chai.use(passport);
chai.use(sinonChai);

global.$require = require("proxyquire");
global.expect = chai.expect;
