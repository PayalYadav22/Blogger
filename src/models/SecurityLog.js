import mongoose from "mongoose";

const SecurityLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  performedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  targetUser: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  timestamp: { type: Date, default: Date.now },
});

const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);

export default SecurityLog;
