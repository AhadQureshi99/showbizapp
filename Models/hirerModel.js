const mongoose = require("mongoose");

const hirerSchema = mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    gender: {
      type: String,
      enum: ["Male", "Female"],
      required: true,
    },
    role: {
      type: String,
      enum: [
        "Director",
        "Assistant Director",
        "Casting Director",
        "Event Manager",
        "Other",
      ],
      required: true,
    },
    password: { type: String, required: true },
    otp: { type: String, default: null },
    isVerified: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    resetToken: { type: String },
    resetTokenExpire: { type: Date },
    age: { type: Number, required: false },
    country: { type: String, required: false },
    city: { type: String, required: false },
    profilePic_url: { type: String },
    profilePic_id: { type: String },
    deviceToken: { type: String },
  },
  {
    timestamps: true,
  }
);

const Hirer = mongoose.model("Hirer", hirerSchema);
module.exports = Hirer;
