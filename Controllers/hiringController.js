const handler = require("express-async-handler");
const mongoose = require("mongoose");
const hiringRequestModel = require("../Models/hiringRequestModel");
const talentModel = require("../Models/talentModel");
const Hirer = require("../Models/hirerModel"); // Use Hirer model instead of User

// Send a hiring request
const sendHiringRequest = handler(async (req, res) => {
  const { talentId, message } = req.body;
  const hirerId = req.user._id;

  // Validate IDs
  if (
    !mongoose.isValidObjectId(talentId) ||
    !mongoose.isValidObjectId(hirerId)
  ) {
    res.status(400);
    throw new Error("Invalid hirer or talent ID");
  }

  // Check if user is a Hirer
  if (
    req.user.role !== "Director" &&
    req.user.role !== "Assistant Director" &&
    req.user.role !== "Casting Director" &&
    req.user.role !== "Event Manager" &&
    req.user.role !== "Other"
  ) {
    res.status(403);
    throw new Error("Only hirers can send hiring requests");
  }

  // Check if talent exists
  const talent = await talentModel.findById(talentId);
  console.log("Found talent:", talent);
  if (!talent) {
    res.status(404);
    throw new Error("Talent not found");
  }

  // Check for existing request
  const existingRequest = await hiringRequestModel.findOne({
    hirer: hirerId,
    talent: talentId,
  });
  console.log("Existing request:", existingRequest);
  if (existingRequest) {
    res.status(400);
    throw new Error("You have already sent a request to this talent");
  }

  // Create new request
  const request = await hiringRequestModel.create({
    hirer: hirerId,
    talent: talentId,
    message,
  });
  console.log("Created request:", request);

  res
    .status(201)
    .json({ message: "Hiring request sent successfully", request });
});

// Get requests received by a talent
const getTalentRequests = handler(async (req, res) => {
  const { talentId } = req.params;

  // Validate talentId
  if (!talentId || !mongoose.isValidObjectId(talentId)) {
    res.status(400);
    throw new Error("Valid talent ID is required");
  }

  // Check if talent exists
  const talent = await talentModel.findById(talentId);
  if (!talent) {
    res.status(404);
    throw new Error("Talent not found");
  }

  // Fetch requests
  const requests = await hiringRequestModel
    .find({ talent: talentId, deletedAt: null })
    .select("hirer message status createdAt")
    .populate("hirer", "name profilePic_url role")
    .sort({ createdAt: -1 });

  res.json({
    message: requests.length
      ? "Requests retrieved successfully"
      : "No requests found",
    requests,
  });
});

// Get requests sent by a hirer
const getHirerRequests = handler(async (req, res) => {
  const hirerId = req.user._id;

  // Check if user is a Hirer
  if (
    req.user.role !== "Director" &&
    req.user.role !== "Assistant Director" &&
    req.user.role !== "Casting Director" &&
    req.user.role !== "Event Manager" &&
    req.user.role !== "Other"
  ) {
    res.status(403);
    throw new Error("Only hirers can view sent requests");
  }

  console.log("Querying hirer requests for ID:", hirerId);
  const requests = await hiringRequestModel
    .find({ hirer: mongoose.Types.ObjectId(hirerId) })
    .populate("talent", "name images.profilePic.url role")
    .populate("hirer", "name profilePic_url role")
    .lean();
  console.log("Found requests:", requests);

  // Format requests for response
  const formattedRequests = requests.map((request) => ({
    _id: request._id,
    message: request.message,
    status: request.status,
    createdAt: request.createdAt,
    hirer: {
      _id: request.hirer._id,
      name: request.hirer.name || "Unknown Hirer",
      profilePic: request.hirer.profilePic_url || null,
      role: request.hirer.role || "Unknown Role",
    },
    talent: {
      _id: request.talent._id,
      name: request.talent.name || "Unknown Talent",
      profilePic: request.talent.images?.profilePic?.url || null,
      role: request.talent.role || "Unknown Role",
    },
  }));

  res.json({
    message: requests.length
      ? "Hiring requests retrieved successfully"
      : "No requests found",
    requests: formattedRequests,
  });
});

// Update request status (accept/reject) - Only talent can update
const updateRequestStatus = handler(async (req, res) => {
  const { requestId, status } = req.body;
  const talentId = req.user._id;

  // Check if user is a Talent
  const talent = await talentModel.findById(talentId);
  if (!talent) {
    res.status(403);
    throw new Error("Only talents can update request status");
  }

  if (!["Accepted", "Rejected"].includes(status)) {
    res.status(400);
    throw new Error("Invalid status");
  }

  if (!mongoose.isValidObjectId(requestId)) {
    res.status(400);
    throw new Error("Invalid request ID");
  }

  const request = await hiringRequestModel.findById(requestId);
  if (!request) {
    res.status(404);
    throw new Error("Request not found");
  }

  // Check if the user is the talent associated with the request
  if (request.talent.toString() !== talentId.toString()) {
    res.status(403);
    throw new Error("Only the talent can accept or reject this request");
  }

  if (status === "Rejected") {
    // Delete the request if rejected
    await request.deleteOne();
    res.json({ message: "Request rejected and deleted" });
  } else {
    // Update status if accepted
    request.status = status;
    await request.save();
    res.json({ message: "Request updated", request });
  }
});

module.exports = {
  sendHiringRequest,
  getTalentRequests,
  getHirerRequests,
  updateRequestStatus,
};
