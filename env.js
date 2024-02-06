const dotenv = require("dotenv");
dotenv.config();

function get(key) {
  const value = process.env[key];
  if (!value) throw new Error(`Environment with key '${key}' not found`);
  return value;
}

module.exports = {
  get,
};
