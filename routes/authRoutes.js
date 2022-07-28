const {
  register,
  login,
  verifyOTP,
  logout,
  resetPassword,
  changePassword,
} = require("../controllers/AuthControllers");
const { checkUser } = require("../Middlewares/AuthMiddleware");
const router = require("express").Router();

router.post("/register", register);
router.post("/login", login);
router.post("/", checkUser);
router.post("/verifyOTP", verifyOTP);
router.post("/logout", logout);
router.post("/resetPassword", resetPassword);
router.post("/changePassword", changePassword);
module.exports = router;