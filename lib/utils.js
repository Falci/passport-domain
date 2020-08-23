const { exec } = require("child_process");
// from: https://github.com/jaredhanson/passport-oauth2/blob/master/lib/utils.js

/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy, assuming that the proxy has been flagged as trusted.
 *
 * @param {http.IncomingMessage} req
 * @param {Object} [options]
 * @return {String}
 * @api private
 */
exports.originalURL = function (req, options) {
  options = options || {};
  var app = req.app;
  if (app && app.get && app.get("trust proxy")) {
    options.proxy = true;
  }
  var trustProxy = options.proxy;

  var proto = (req.headers["x-forwarded-proto"] || "").toLowerCase(),
    tls =
      req.connection.encrypted ||
      (trustProxy && "https" == proto.split(/\s*,\s*/)[0]),
    host = (trustProxy && req.headers["x-forwarded-host"]) || req.headers.host,
    protocol = tls ? "https" : "http",
    path = req.url || "";
  return protocol + "://" + host + path;
};

exports.keyResolver = ({ host, port }) => (domain) =>
  new Promise((resolve, reject) => {
    const command = ["dig"];
    if (host) command.push(`@${host}`);
    if (port) command.push(`-p ${port}`);
    command.push(encodeURIComponent(domain));
    command.push("TXT +short");

    exec(command.join(" "), (error, out) => {
      if (error) {
        return reject(error);
      }

      const txt = out
        .split("\n")
        .map((line) => line.substring(1, line.length - 1)) // remove "quotes"
        .find((line) => line.indexOf("auth=") === 0);

      if (!txt) {
        return reject(new Error("auth TXT not found"));
      }

      resolve(txt.substring(5));
    });
  });
