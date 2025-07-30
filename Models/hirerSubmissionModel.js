const mongoose = require("mongoose");

const HirerSubmissionSchema = new mongoose.Schema(
  {
    hirer: { type: mongoose.Schema.Types.ObjectId, ref: "Hirer", required: true },
    subject: { type: String, required: true },
    description: { type: String, required: true },
  },
  { collection: "hirerSubmissions" } // Specify exact collection name
);
module.exports = mongoose.model("HirerSubmission", HirerSubmissionSchema);
