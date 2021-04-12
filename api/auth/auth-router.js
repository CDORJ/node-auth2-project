const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model.js");
const bcrypt = require("bcryptjs");

router.post("/register", validateRoleName, async (req, res, next) => {
  const credentials = req.body;
  try {
    const hash = bcrypt.hashSync(credentials.password, 5);
    credentials.password = hash;
    const user = await Users.add(credentials);
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});
/**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const user = await Users.findBy({ username }).first();
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = generateToken(user);
      res.status(200).json({ user, token });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

/**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

function generateToken(user) {
  const payload = {
    sub: user.user_id,
    username: user.username,
    role_name: user.role_id,
  };
  const options = {
    expiresIn: "1h",
  };
  const secret = JWT_SECRET;
  return jwt.sign(payload, secret, options);
}
module.exports = router;
