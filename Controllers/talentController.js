const handler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cloudinary = require("cloudinary").v2;
const talentModel = require("../Models/talentModel");
const talentSubmissionModel = require("../Models/hirerSubmissionModel");
const hiringRequestModel = require("../Models/hiringRequestModel");
const { Readable } = require("stream");

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const generateOTP = () => Math.floor(100000 + Math.random() * 900000);

const sendOTP = (email, otp) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailOptions = {
    from: '"Showbiz App" <' + process.env.MAIL_USER + ">",
    to: email,
    subject: "Verify Your Showbiz App Account",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
        <h2 style="color: #1a73e8;">Welcome to Showbiz App!</h2>
        <p>Thank you for joining Showbiz App. To complete your registration, please use the following One-Time Password (OTP):</p>
        <h3 style="background: #f1f3f4; padding: 10px; border-radius: 5px; text-align: center; color: #1a73e8;">
          ${otp}
        </h3>
        <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
        <p>If you did not request this OTP, please ignore this email or contact our support team at support@showbizapp.com.</p>
        <p style="margin-top: 20px;">Best regards,<br>The Showbiz App Team</p>
        <hr style="border-top: 1px solid #ddd; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;">
          © ${new Date().getFullYear()} Showbiz App. All rights reserved.<br>
          <a href="https://www.showbizapp.com" style="color: #1a73e8; text-decoration: none;">Visit our website</a> | 
          <a href="https://www.showbizapp.com/privacy" style="color: #1a73e8; text-decoration: none;">Privacy Policy</a>
        </p>
      </div>
    `,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Email sending error:", error);
      throw new Error("Failed to send OTP");
    }
    console.log(`OTP sent to email: ${email} | OTP: ${otp}`);
  });
};

const generateToken = (id, role) => {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined");
  }
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: "15d",
  });
};

// Register Talent
const registerTalent = handler(async (req, res) => {
  const { name, email, phone, gender, role, password, deviceToken } = req.body;

  if (!name || !email || !phone || !gender || !role || !password) {
    res.status(400);
    throw new Error("All fields are required");
  }

  const existing = await talentModel.findOne({ email });
  if (existing && existing.isVerified) {
    res.status(409);
    throw new Error("Email already registered");
  }

  const hashedPass = await bcrypt.hash(password, 10);
  const otp = generateOTP();
  let createdTalent;

  if (existing && !existing.isVerified) {
    createdTalent = await talentModel.findOneAndUpdate(
      { email },
      {
        name,
        phone,
        gender,
        role,
        password: hashedPass,
        otp,
        isVerified: false,
        deviceToken,
      },
      { new: true }
    );
  } else {
    createdTalent = await talentModel.create({
      name,
      email,
      phone,
      gender,
      role,
      password: hashedPass,
      otp,
      isVerified: false,
      deviceToken,
    });
  }

  sendOTP(email, otp);

  const token = generateToken(createdTalent._id, createdTalent.role);

  res.json({
    message: "OTP sent to email. Please verify to complete registration.",
    userId: createdTalent._id,
    token,
  });
});

// Login Talent
const loginTalent = handler(async (req, res) => {
  const { email, password, deviceToken } = req.body;

  const talent = await talentModel.findOne({ email });
  if (!talent || !(await bcrypt.compare(password, talent.password))) {
    res.status(401);
    throw new Error("Invalid email or password");
  }

  if (!talent.isVerified) {
    res.status(403);
    throw new Error("Please verify your OTP before logging in");
  }

  if (deviceToken) {
    talent.deviceToken = deviceToken;
    await talent.save();
  }

  res.json({
    _id: talent._id,
    name: talent.name,
    email: talent.email,
    phone: talent.phone,
    role: talent.role,
    token: generateToken(talent._id, talent.role),
  });
});

// Verify OTP
const verifyTalentOTP = handler(async (req, res) => {
  const { otp } = req.body;

  if (!req.user) {
    res.status(401);
    throw new Error("User not authenticated");
  }

  const user = await talentModel.findById(req.user._id);
  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
  }

  if (String(user.otp) !== String(otp)) {
    res.status(401);
    throw new Error("Invalid OTP");
  }

  user.otp = null;
  user.isVerified = true;
  await user.save();

  res.json({
    _id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    token: generateToken(user._id, user.role),
    message: "OTP verified successfully",
  });
});

// Forgot Password for Talent
const forgotTalentPassword = handler(async (req, res) => {
  const { email } = req.body;
  const user = await talentModel.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  const resetToken = generateOTP();
  user.resetToken = resetToken;
  user.resetTokenExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
  await user.save();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  const mailOptions = {
    from: '"Showbiz App" <' + process.env.MAIL_USER + ">",
    to: email,
    subject: "Showbiz App Password Reset",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #333;">
        <h2 style="color: #1a73e8;">Password Reset Request</h2>
        <p>We received a request to reset your Showbiz App account password. Please use the following One-Time Password (OTP) to reset your password:</p>
        <h3 style="background: #f1f3f4; padding: 10px; border-radius: 5px; text-align: center; color: #1a73e8;">
          ${resetToken}
        </h3>
        <p>This OTP is valid for 10 minutes. Please do not share it with anyone.</p>
        <p>If you did not request a password reset, please ignore this email or contact our support team at support@showbizapp.com.</p>
        <p style="margin-top: 20px;">Best regards,<br>The Showbiz App Team</p>
        <hr style="border-top: 1px solid #ddd; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;">
          © ${new Date().getFullYear()} Showbiz App. All rights reserved.<br>
          <a href="https://www.showbizapp.com" style="color: #1a73e8; text-decoration: none;">Visit our website</a> | 
          <a href="https://www.showbizapp.com/privacy" style="color: #1a73e8; text-decoration: none;">Privacy Policy</a>
        </p>
      </div>
    `,
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) {
      console.error("Email sending error:", error);
      res.status(500);
      throw new Error("Failed to send reset code");
    }
    console.log(
      `Password reset OTP sent to email: ${email} | OTP: ${resetToken}`
    );
    res.json({ message: "Reset code sent to email" });
  });
});

// Reset Password
const resetTalentPassword = handler(async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  const user = await talentModel.findOne({
    resetToken: token,
    resetTokenExpire: { $gt: Date.now() },
  });

  if (!user) {
    res.status(400);
    throw new Error("Invalid or expired reset token");
  }

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = null;
  user.resetTokenExpire = null;
  await user.save();

  res.json({ message: "Password reset successfully" });
});

// Resend OTP
const resendTalentOTP = handler(async (req, res) => {
  const user = await talentModel.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("Talent is already verified");
  }

  const otp = generateOTP();
  user.otp = otp;
  await user.save();

  sendOTP(user.email, otp);

  res.json({ message: "New OTP sent to email" });
});

// Update Talent Profile
const updateTalentProfile = handler(async (req, res) => {
  const user_id = req.user._id;
  const {
    name,
    email,
    phone,
    age,
    height,
    weight,
    bodyType,
    skinTone,
    language,
    skills,
    makeoverNeeded,
    willingToWorkAsExtra,
    aboutYourself,
    deviceToken,
    video,
  } = req.body || {};
  const files = req.files || {};

  const currentUser = await talentModel.findById(user_id);
  if (!currentUser) {
    res.status(404);
    throw new Error("Talent not found");
  }

  if (email && email !== currentUser.email) {
    const existing = await talentModel.findOne({ email });
    if (existing && existing._id.toString() !== user_id.toString()) {
      res.status(409);
      throw new Error("Email already in use");
    }
  }

  const updateFields = {};
  const images = currentUser.images ? { ...currentUser.images } : {};

  const isNonEmpty = (value) =>
    value !== undefined && value !== null && value !== "";

  if (isNonEmpty(name)) updateFields.name = name;
  if (isNonEmpty(email)) updateFields.email = email;
  if (isNonEmpty(phone)) updateFields.phone = phone;
  if (isNonEmpty(age)) updateFields.age = parseInt(age);
  if (isNonEmpty(height)) updateFields.height = height;
  if (isNonEmpty(weight)) updateFields.weight = weight;
  if (isNonEmpty(bodyType)) updateFields.bodyType = bodyType;
  if (isNonEmpty(skinTone)) updateFields.skinTone = skinTone;
  if (isNonEmpty(language)) updateFields.language = language;
  if (isNonEmpty(skills)) updateFields.skills = skills;
  if (isNonEmpty(makeoverNeeded))
    updateFields.makeoverNeeded =
      makeoverNeeded === "true" || makeoverNeeded === true;
  if (isNonEmpty(willingToWorkAsExtra))
    updateFields.willingToWorkAsExtra =
      willingToWorkAsExtra === "true" || willingToWorkAsExtra === true;
  if (isNonEmpty(aboutYourself)) updateFields.aboutYourself = aboutYourself;
  if (isNonEmpty(deviceToken)) updateFields.deviceToken = deviceToken;
  if (isNonEmpty(video)) updateFields.video = { url: video };

  const imageFields = ["front", "left", "right", "profilePic"];
  for (const field of imageFields) {
    if (files[field] && files[field][0]) {
      if (currentUser.images && currentUser.images[field]?.id) {
        await cloudinary.uploader.destroy(currentUser.images[field].id);
      }

      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: `talent_profiles/${user_id}`,
            resource_type: "image",
          },
          (error, result) => {
            if (error) reject(new Error(`Failed to upload ${field} image`));
            else resolve(result);
          }
        );

        const bufferStream = new Readable();
        bufferStream.push(files[field][0].buffer);
        bufferStream.push(null);
        bufferStream.pipe(uploadStream);
      });

      images[field] = {
        url: uploadResult.secure_url,
        id: uploadResult.public_id,
      };
    }
  }

  if (Object.keys(images).length > 0) {
    updateFields.images = images;
  }

  if (Object.keys(updateFields).length === 0) {
    res.status(400);
    throw new Error(
      "At least one field, image, or video URL must be provided for update"
    );
  }

  const updatedProfile = await talentModel
    .findByIdAndUpdate(user_id, { $set: updateFields }, { new: true })
    .select("-password -otp -resetToken -resetTokenExpire");

  res.json({
    message: "Profile updated successfully",
    profile: updatedProfile,
  });
});

// Get Talent Profile
const getTalentProfile = handler(async (req, res) => {
  const user = await talentModel
    .findById(req.user._id)
    .select("-password -otp -resetToken -resetTokenExpire");

  if (!user) {
    res.status(404);
    throw new Error("Talent not found");
  }

  res.json({
    message: "Profile retrieved successfully",
    profile: {
      ...user._doc,
      profilePic: user.images?.profilePic?.url || null,
    },
  });
});

// Get All Talents
const getAllTalents = handler(async (req, res) => {
  // Check if user is authenticated and is a hirer
  if (!req.user || req.user.userType !== "Hirer") {
    res.status(403);
    throw new Error("Only authenticated hirers can access this endpoint");
  }

  // Verify hirer exists and is approved
  const hirer = await require("../Models/hirerModel").findById(req.user._id);
  if (!hirer) {
    res.status(404);
    throw new Error("Hirer not found");
  }
  if (hirer.status !== "approved") {
    res.status(403);
    throw new Error("Hirer account is not approved");
  }

  // Fetch all verified talents
  const talents = await talentModel
    .find({ isVerified: true })
    .select(
      "_id name email phone role gender age skills createdAt images.profilePic.url"
    )
    .lean();

  if (!talents || talents.length === 0) {
    res.status(404);
    throw new Error("No talents found");
  }

  // Fetch accepted hiring requests for the hirer
  const acceptedRequests = await hiringRequestModel
    .find({
      hirer: req.user._id,
      status: "Accepted",
    })
    .select("talent")
    .lean();

  // Create a set of talent IDs with accepted requests
  const connectedTalentIds = new Set(
    acceptedRequests.map((request) => request.talent.toString())
  );

  // Format talents, including email and phone only for connected talents
  const formattedTalents = talents.map((talent) => ({
    _id: talent._id,
    name: talent.name,
    email: connectedTalentIds.has(talent._id.toString()) ? talent.email : null,
    phone: connectedTalentIds.has(talent._id.toString()) ? talent.phone : null,
    role: talent.role,
    gender: talent.gender,
    age: talent.age,
    skills: talent.skills,
    createdAt: talent.createdAt,
    profilePic: talent.images?.profilePic?.url || null,
  }));

  res.json({
    message: "Talents retrieved successfully",
    talents: formattedTalents,
  });
});

module.exports = {
  registerTalent,
  loginTalent,
  verifyTalentOTP,
  forgotTalentPassword,
  resetTalentPassword,
  resendTalentOTP,
  updateTalentProfile,
  getTalentProfile,
  getAllTalents,
};
