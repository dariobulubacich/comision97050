const { Router } = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");

const router = Router();

router.post(
  "/login",
  passport.authenticate("login", { session: false }),
  async (req, res) => {
    const user = req.user;

    const token = jwt.sign(
      {
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
        },
      },
      "jwtSecretKey",
      { expiresIn: "1h" },
    );

    res.send({
      status: "success",
      token,
    });
  },
);

module.exports = router;
