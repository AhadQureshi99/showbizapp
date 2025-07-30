const mongoose = require("mongoose");

const TalentSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    phone: {
      type: String,
      required: true,
    },
    gender: {
      type: String,
      required: true,
      enum: ["Male", "Female"],
    },
    role: {
      type: String,
      enum: [
        "Actor",
        "Model",
        "Actor/Model",
        "MakeupArtist",
        "Cinematographer",
      ],
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    otp: {
      type: String,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    resetToken: {
      type: String,
    },
    resetTokenExpire: {
      type: Date,
    },
    age: {
      type: Number,
    },
    height: {
      type: String,
    },
    weight: {
      type: String,
    },
    bodyType: {
      type: String,
      enum: ["Slim", "Average", "Athletic", "PlusSize"],
    },
    skinTone: {
      type: String,
      enum: ["Fair", "Wheatish", "Dusky"],
    },
    language: {
      type: String,
    },
    skills: {
      type: String,
      enum: ["Dance", "Comedy", "Action"],
    },
    images: {
      front: {
        url: { type: String },
        id: { type: String },
      },
      left: {
        url: { type: String },
        id: { type: String },
      },
      right: {
        url: { type: String },
        id: { type: String },
      },
      profilePic: {
        url: { type: String },
        id: { type: String },
      },
    },
    video: {
      url: { type: String }, // Updated to only include URL
    },
    makeoverNeeded: {
      type: Boolean,
      default: false,
    },
    willingToWorkAsExtra: {
      type: Boolean,
      default: false,
    },
    aboutYourself: {
      type: String,
    },
    deviceToken: { type: String }, // Optional device token for push notifications
  },
  { timestamps: true }
);

module.exports = mongoose.model("Talent", TalentSchema);
