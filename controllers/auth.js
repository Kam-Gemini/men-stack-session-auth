const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");

const User = require("../models/user.js");

router.get("/sign-up", (req, res) => {
  res.render("auth/sign-up.ejs");
});

router.post("/sign-up", async (req, res) => {
  // enforce unique usernames, the username should not already exist in the db
  const userInDatabase = await User.findOne({});
  if (userInDatabase) {
    return res.send("Username is already taken.");
  }
  // ensure the password is the same as the confirm password
  if (req.body.password !== req.body.confirmPassword) {
    return res.send("Passwords do not match!");
  }
  // Ensure the password store in the DB is encrypted for security
  // using bcrypt to hash the password before storing
  const hashedPassword = bcrypt.hashSync(
    req.body.password,
    process.env.SALT_ROUNDS,
  );
  req.body.password = hashedPassword;

  // create the user in the DB
  // validation logic

  const user = await User.create(req.body);
  res.send(`Thanks for signing up ${user.username}`);
});

// GET /auth/sign-in/
router.get("/sign-in", async (req, res) => {
  res.render("auth/sign-in.ejs");
});

// POST /auth/sign-in
router.post("/sign-in", async (req, res) => {
  if (!(req.body.username && req.body.password)) {
    return res.send("Username or Password is missing");
  }
  // check if user is found in the DB
  const foundUser = await User.findOne({username: req.body.username})
  if (!foundUser) {
    res.send("Invalid credentials");
  }

  // Get pass word from the DB
  // Unhash the password
  const validPassword = bcrypt.compareSync(
    req.body.password,
    foundUser.password,
  );
  if (!validPassword) {
    return res.send("Login failed, try again.");
  }

  req.session.user = {
    username: foundUser.username,
  };

  // compare the unhashed to the password submitted by the user
  // if all good, we rediredt them.
  res.redirect("/");
});

router.get("/sign-out", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;
