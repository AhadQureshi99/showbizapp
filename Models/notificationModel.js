const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Hirer Talent", // Can reference either Hirer or Talent
    default: null,
  },
  userType: {
    type: String,
    enum: ["Hirer", "Talent", null],
    default: null,
  },
  title: {
    type: String,
    default: "Untitled",
  },
  status: {
    type: String,
    default: "No status",
  },
  body: {
    type: String,
    default: "No body",
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("Notification", notificationSchema);
