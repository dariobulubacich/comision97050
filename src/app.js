const passport = require("passport");
const initializePassport = require("./config/passport.config");

initializePassport();
app.use(passport.initialize());
