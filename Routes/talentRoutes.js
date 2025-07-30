const express = require("express");
const multer = require("multer");
const {
  registerTalent,
  loginTalent,
  verifyTalentOTP,
  forgotTalentPassword,
  resetTalentPassword,
  resendTalentOTP,
  updateTalentProfile,
  getTalentProfile,
  getAllTalents,
} = require("../Controllers/talentController");
const authHandler = require("../Middleware/authMiddleware");

const upload = multer({ storage: multer.memoryStorage() });
const talentRouter = express.Router();

talentRouter.post("/register", registerTalent);
talentRouter.post("/login", loginTalent);
talentRouter.post("/verify-otp", authHandler, verifyTalentOTP);
talentRouter.post("/forgot-password", forgotTalentPassword);
talentRouter.post("/reset-password/:token", resetTalentPassword);
talentRouter.post("/resend-otp", authHandler, resendTalentOTP);
talentRouter.put(
  "/update-profile",
  authHandler,
  upload.fields([
    { name: "front", maxCount: 1 },
    { name: "left", maxCount: 1 },
    { name: "right", maxCount: 1 },
    { name: "profilePic", maxCount: 1 },
  ]),
  updateTalentProfile
);
talentRouter.get("/get-profile", authHandler, getTalentProfile);
talentRouter.get("/all-talents", getAllTalents); // Public for dashboard

module.exports = talentRouter;
