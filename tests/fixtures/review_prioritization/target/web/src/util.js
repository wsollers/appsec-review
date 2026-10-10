const https = require("https");

exports.agent = new https.Agent({ rejectUnauthorized: false });

exports.render = function render(text) {
  return String(text).replace(/</g, "&lt;");
};
