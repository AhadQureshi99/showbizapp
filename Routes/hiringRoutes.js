const express = require("express");
const {
  sendHiringRequest,
  getTalentRequests,
  getHirerRequests,
  updateRequestStatus,
} = require("../Controllers/hiringController");
const authHandler = require("../Middleware/authMiddleware");

const hiringRouter = express.Router();

// Route to send a hiring request (hirer only)
hiringRouter.post("/send", authHandler, sendHiringRequest);

// Route to get requests received by a talent (talent only)
hiringRouter.get("/talent/:talentId", getTalentRequests);

// Route to get requests sent by a hirer (hirer only)
hiringRouter.get("/hirer", authHandler, getHirerRequests);

// Route to accept or reject a hiring request (talent only)
hiringRouter.put("/status", authHandler, updateRequestStatus);

module.exports = hiringRouter;
