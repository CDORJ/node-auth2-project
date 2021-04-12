const { secret } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model.js");
const { typeOf } = require("react-is");

const restricted = (req, res, next) => {
  const token = req.headers?.authorization?.split(" ")[1];
  if (token) {
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        res.status(401).json({ message: "Error logging in" });
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
};

/*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */

const only = (role_name) => (req, res, next) => {
  const reqRole = req.decodedToken?.role;
  if (reqRole === role_name) {
    next();
  } else {
    res.status(403).json({ message: "This is not for you!" });
  }
};

/*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */

const checkUsernameExists = async (req, res, next) => {
  try {
    const user = await Users.findBy({ username: req.body.username });
    if (user.length > 0) {
      next();
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
};

/*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
// NOTE this is trimming: role_name: "admin"
const validateRoleName = async (req, res, next) => {
  if (!req.body.username || !req.body.password) {
    res.status(400).json({
      message:
        "must have username and password to register. role_name is optional",
    });
  }
  try {
    const { role_name } = req.body;
    const isValid = (role) => {
      return Boolean(role && typeof role === "string");
    };
    if (!req.body.role_name || req.body.role_name === " ") {
      req.body.role_name = "student";
      next();
    } else if (isValid(role_name)) {
      if (req.body.role_name.trim() === "admin") {
        res.status(422).json({ message: "Role can not be admin" });
      } else if (req.body.role_name.trim().length > 32) {
        res.status(422).json({
          message: "Role name can not be longer than 32 chars",
        });
      } else {
        next();
      }
    }
  } catch (err) {
    next(err);
  }
};
/*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
