const passport = require("passport");
const local = require("passport-local");
const jwt = require("passport-jwt");
const UserModel = require("../dao/models/user.model");
const { createHash, isValidPassword } = require("../utils/hash");

const LocalStrategy = local.Strategy;
const JwtStrategy = jwt.Strategy;
const ExtractJwt = jwt.ExtractJwt;

const initializePassport = () => {
  // 🔐 REGISTER
  passport.use(
    "register",
    new LocalStrategy(
      { usernameField: "email", passReqToCallback: true },
      async (req, email, password, done) => {
        try {
          const userExists = await UserModel.findOne({ email });
          if (userExists) return done(null, false);

          const newUser = {
            ...req.body,
            password: createHash(password),
          };

          const user = await UserModel.create(newUser);
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      },
    ),
  );

  // 🔐 LOGIN
  passport.use(
    "login",
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const user = await UserModel.findOne({ email });
          if (!user) return done(null, false);

          if (!isValidPassword(user, password)) return done(null, false);

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      },
    ),
  );

  // 🔐 JWT
  passport.use(
    "jwt",
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: "jwtSecretKey",
      },
      async (jwt_payload, done) => {
        try {
          return done(null, jwt_payload.user);
        } catch (error) {
          return done(error);
        }
      },
    ),
  );
};

module.exports = initializePassport;
