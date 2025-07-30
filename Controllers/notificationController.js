const handler = require("express-async-handler");
const notificationModel = require("../Models/notificationModel");
const Talent = require("../Models/talentModel");
const Hirer = require("../Models/hirerModel");

const sendNotificationToUser = handler(async (req, res) => {
  console.log("Request headers:", req.headers);
  console.log("Request body:", req.body);
  console.log("Authenticated user:", req.user);

  const { title, status, body, userId } = req.body;

  // Validate input fields
  if (!title && !status && !body) {
    res.status(400);
    throw new Error(
      "At least one of title, status, or body should be provided"
    );
  }

  // Ensure authenticated user exists
  if (!req.user) {
    res.status(401);
    throw new Error("User not authenticated");
  }

  // Use userId from body if provided, otherwise use authenticated user's ID
  const targetUserId = userId || req.user._id;
  console.log("Target user ID:", targetUserId);

  // Look up user in Talent or Hirer models
  let user = await Talent.findById(targetUserId).lean();
  let userType = user ? "Talent" : null;

  if (!user) {
    user = await Hirer.findById(targetUserId).lean();
    userType = user ? "Hirer" : null;
  }

  if (!user) {
    console.error("User lookup failed for ID:", targetUserId);
    res.status(404);
    throw new Error("User not found");
  }

  console.log("Found user:", {
    id: user._id,
    email: user.email,
    role: user.role,
  });

  // Create the notification
  const notification = await notificationModel.create({
    user: targetUserId,
    userType: userType || req.user.role, // Fallback to req.user.role if needed
    title,
    status,
    body,
    date: new Date(),
  });

  res.status(201).json({
    message: "Notification sent to user successfully",
    notification: {
      _id: notification._id,
      title: notification.title || "Untitled",
      status: notification.status || "No status",
      body: notification.body || "No body",
      date: notification.date || new Date(),
    },
  });
});

// Other functions (unchanged)
const sendNotificationToAll = handler(async (req, res) => {
  const { title, status, body } = req.body;
  if (!title && !status && !body) {
    res.status(400);
    throw new Error(
      "At least one of title, status, or body should be provided"
    );
  }
  const notification = await notificationModel.create({
    title,
    status,
    body,
    date: new Date(),
  });
  res.status(201).json({
    message: "Notification sent to all users successfully",
    notification: {
      _id: notification._id,
      title: notification.title || "Untitled",
      status: notification.status || "No status",
      body: notification.body || "No body",
      date: notification.date || new Date(),
    },
  });
});

const getGlobalNotifications = handler(async (req, res) => {
  const notifications = await notificationModel
    .find({ user: null, userType: null })
    .select("title status body date")
    .sort({ date: -1 })
    .lean();
  if (!notifications || notifications.length === 0) {
    res.status(404);
    throw new Error("No global notifications found");
  }
  const formattedNotifications = notifications.map((notification) => ({
    _id: notification._id,
    title: notification.title || "Untitled",
    status: notification.status || "No status",
    body: notification.body || "No body",
    date: notification.date || new Date(),
  }));
  res.json({
    message: "Global notifications retrieved successfully",
    notifications: formattedNotifications,
  });
});

const getUserSpecificNotifications = handler(async (req, res) => {
  if (!req.user) {
    res.status(401);
    throw new Error("User not authenticated");
  }
  const userId = req.user._id;
  const userType = req.user.role;
  const notifications = await notificationModel
    .find({
      $or: [
        { user: userId, userType },
        { user: null, userType: null },
      ],
    })
    .select("title status body date")
    .sort({ date: -1 })
    .lean();
  if (!notifications || notifications.length === 0) {
    return res.json({
      message: "No notifications found",
      notifications: [],
    });
  }
  const formattedNotifications = notifications.map((notification) => ({
    _id: notification._id,
    title: notification.title || "Untitled",
    status: notification.status || "No status",
    body: notification.body || "No body",
    date: notification.date || new Date(),
  }));
  res.json({
    message: "User notifications retrieved successfully",
    notifications: formattedNotifications,
  });
});

module.exports = {
  sendNotificationToAll,
  sendNotificationToUser,
  getGlobalNotifications,
  getUserSpecificNotifications,
};
