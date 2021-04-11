const router = require("express").Router();
const jwt = require("jsonwebtoken");

const {
  validateRoleName,
  checkUsernameExists,
} = require("./auth-middleware.js");

const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const User = require("../users/users-model.js");

router.post("/register", validateRoleName, async (req, res, next) => {
  const user = req.body;
  let hash = bcrypt.hashSync(user.password, 15);
  user.password = hash;
  try {
    const newUser = await User.add(user);
    res.status(201).json(newUser);
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

// router.post("/login", checkUsernameExists, (req, res, next) => {
//   /**
//     [POST] /api/auth/login { "username": "sue", "password": "1234" }

//     response:
//     status 200
//     {
//       "message": "sue is back!",
//       "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
//     }

//     The token must expire in one day, and must provide the following information
//     in its payload:

//     {
//       "subject"  : 1       // the user_id of the authenticated user
//       "username" : "bob"   // the username of the authenticated user
//       "role_name": "admin" // the role of the authenticated user
//     }
//    */
// });

module.exports = router;
