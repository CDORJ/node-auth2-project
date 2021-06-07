const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets/index");

const makeToken = (user) => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "24h",
  };

  return jwt.sign(payload, JWT_SECRET, options);
};

module.exports = {
  makeToken,
};
