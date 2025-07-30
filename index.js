require("dotenv").config({ path: require("path").resolve(__dirname, ".env") });
require("colors");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const connectDB = require("./config/connectDB");
const errorHandler = require("./Middleware/errorMiddleware");
const talentRouter = require("./Routes/talentRoutes");
const hirerRouter = require("./Routes/hirerRoutes");
const hiringRouter = require("./Routes/hiringRoutes");
const notificationRouter = require("./Routes/notificationRoutes");

console.log("Environment Variables in index.js:", {
  CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET,
});

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Connect to DB
connectDB();

// Routes
app.use("/api/talents", talentRouter);
app.use("/api/hirers", hirerRouter);
app.use("/api/hiring", hiringRouter);
app.use("/api/notifications", notificationRouter);

// Error Handler
app.use(errorHandler);

// Start Server
app.listen(process.env.PORT, () => {
  console.log(`Server started on port: ${process.env.PORT}`.yellow);
});
