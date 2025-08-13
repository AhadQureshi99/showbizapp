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
const talentModel = require("../Models/talentModel");
const handler = require("express-async-handler");

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
talentRouter.get("/all-talents", authHandler, getAllTalents);

// New public endpoint to get all talents without authentication
talentRouter.get("/public-talents", handler(async (req, res) => {
  // Fetch all verified talents with required fields including email and phone
  const talents = await talentModel
    .find({ isVerified: true })
    .select(
      "_id name email phone role gender age height weight bodyType skinTone language skills images.profilePic.url video.url makeoverNeeded willingToWorkAsExtra aboutYourself createdAt updatedAt"
    )
    .lean();

  if (!talents || talents.length === 0) {
    res.status(404);
    throw new Error("No talents found");
  }

  // Format talents to match the response structure
  const formattedTalents = talents.map((talent) => ({
    id: talent._id.toString(),
    name: talent.name || null,
    email: talent.email || null,
    phone: talent.phone || null,
    role: talent.role,
    gender: talent.gender,
    age: talent.age || null,
    height: talent.height || null,
    weight: talent.weight || null,
    bodyType: talent.bodyType || null,
    skinTone: talent.skinTone || null,
    language: talent.language || null,
    skills: talent.skills || null,
    profilePic: talent.images?.profilePic?.url || null,
    video: talent.video?.url || null,
    makeoverNeeded: talent.makeoverNeeded || false,
    willingToWorkAsExtra: talent.willingToWorkAsExtra || false,
    aboutYourself: talent.aboutYourself || null,
    createdAt: talent.createdAt,
    updatedAt: talent.updatedAt,
  }));

  res.json({
    message: "Talents retrieved successfully",
    talents: formattedTalents,
  });
}));

module.exports = talentRouter;