const express = require("express");
const multer = require("multer");
const {
  registerHirer,
  loginHirer,
  verifyHirerOTP,
  forgotHirerPassword,
  resetHirerPassword,
  resendHirerOTP,
  updateHirerProfile,
  getHirerProfile,
  submitHirerSubmission,
  getAllHirerSubmissions,
  deleteHirerSubmission,
  updateHirerSubmission,
  getSubmissionsByHirerId,
  manageHirerStatus,
  getPendingHirers,
  getAllHirers,
  getAcceptedHirers, // New controller function
} = require("../Controllers/hirerController");
const authHandler = require("../Middleware/authMiddleware");

const upload = multer({ storage: multer.memoryStorage() });
const hirerRouter = express.Router();

hirerRouter.post("/register", registerHirer);
hirerRouter.post("/login", loginHirer);
hirerRouter.post("/verify-otp", authHandler, verifyHirerOTP);
hirerRouter.post("/forgot-password", forgotHirerPassword);
hirerRouter.post("/reset-password/:token", resetHirerPassword);
hirerRouter.post("/resend-otp", authHandler, resendHirerOTP);
hirerRouter.put(
  "/update-profile",
  authHandler,
  upload.fields([{ name: "profilePic", maxCount: 1 }]),
  updateHirerProfile
);
hirerRouter.get("/get-profile", authHandler, getHirerProfile);
hirerRouter.post("/submit", authHandler, submitHirerSubmission);
hirerRouter.put(
  "/submissions/:submissionId",
  authHandler,
  updateHirerSubmission
);
hirerRouter.delete(
  "/submissions/:submissionId",
  authHandler,
  deleteHirerSubmission
);
hirerRouter.get("/submissions",  getAllHirerSubmissions);
hirerRouter.get(
  "/hirer/:hirerId/submissions",
  authHandler,
  getSubmissionsByHirerId
);
hirerRouter.post("/manage-status/:hirerId", manageHirerStatus); // Public for dashboard
hirerRouter.get("/pending-hirers", getPendingHirers); // Public for dashboard
hirerRouter.get("/all-hirers", getAllHirers); // Public for dashboard
hirerRouter.get("/accepted-hirers", getAcceptedHirers); // New public route for accepted hirers

module.exports = hirerRouter;
