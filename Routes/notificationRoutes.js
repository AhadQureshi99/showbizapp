const express = require("express");
const notificationRouter = express.Router();
const {
  sendNotificationToAll,
  sendNotificationToUser,
  getGlobalNotifications,
  getUserSpecificNotifications,
} = require("../Controllers/notificationController");
const authHandler = require("../Middleware/authMiddleware");

// Send notification to all users (requires authentication)
notificationRouter.post("/all", authHandler, sendNotificationToAll);

// Send notification to a specific user (requires authentication)
notificationRouter.post("/user", authHandler, sendNotificationToUser);

// Get global notifications (public, no authentication)
notificationRouter.get("/global", getGlobalNotifications);

// Get user-specific notifications (requires authentication)
notificationRouter.get("/user", authHandler, getUserSpecificNotifications);

module.exports = notificationRouter;