import mongoose from "mongoose";

const slugAuditSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  oldSlug: { type: String, required: true },
  newSlug: { type: String, required: true },
  changedAt: { type: Date, default: Date.now },
});

const SlugAudit = mongoose.model("SlugAudit", slugAuditSchema);

export default SlugAudit;
