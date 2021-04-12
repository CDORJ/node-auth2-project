const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const User = require("../users/users-model.js");

const restricted = (req, res, next) => {
  const token = req.headers?.authorization?.split(" ")[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        res.status(401).json({ message: "error logging in " });
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ message: "you can't log in with these credentials" });
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
  const realRole = req.decodedToken?.role;
  if (realRole === role_name) {
    next();
  } else {
    res.status(403).json({ message: "this is not for you" });
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
    const user = await User.findBy({ username: req.body.username });
    if (user.length > 0) {
      next();
    } else {
      res.status(401).json({ message: "Invalid Creds" });
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

/* const validateRoleName = (req, res, next) => {
  if (!req.body.username || !req.body.password) {
    res.status(400).json({
      message: "must contain a username, password and optional role_name",
    });
  } else {
    let desiredRole = req.body.role_name;
    const isValid = (role_name) => {
      return Boolean(role_name && typeof role_name === "string");
    };
    if (isValid(desiredRole)) {
      if (desiredRole.trim() === "admin") {
        res.status(422).json({ message: "role can not be admin" });
      } else if (desiredRole.trim().length > 32) {
        res
          .status(422)
          .json({ message: "Role name can not be longer than 32 characters" });
      }
    } else if (!desiredRole || desiredRole === "") {
      req.body.role_name = "student";
      next();
    }
  }
}; */
const validateRoleName = async (req, res, next) => {
  if (!req.body.username || !req.body.password) {
    res.status(400).json({
      message:
        "must have a username and password to register. optional: role_name .",
    });
  }
  try {
    let { role_name } = req.body;
    const isValid = (role_name) => {
      return Boolean(role_name && typeof role_name === "string");
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
