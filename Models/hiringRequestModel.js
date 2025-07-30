// models/hiringRequestModel.js
const mongoose = require("mongoose");

const hiringRequestSchema = new mongoose.Schema(
  {
    hirer: { type: mongoose.Schema.Types.ObjectId, ref: "Hirer", required: true },
    talent: { type: mongoose.Schema.Types.ObjectId, ref: "Talent", required: true },
    message: { type: String },
    status: {
      type: String,
      enum: ["Pending", "Accepted", "Rejected"],
      default: "Pending",
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("HiringRequest", hiringRequestSchema);
