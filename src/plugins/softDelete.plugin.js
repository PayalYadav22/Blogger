/**
 * Soft delete plugin adds `deletedAt`, softDelete method, and findActive helper.
 * Enables non-destructive deletion of documents.
 */
function softDeletePlugin(schema) {
  schema.add({ deletedAt: { type: Date, default: null } });

  schema.methods.softDelete = function () {
    this.deletedAt = new Date();
    return this.save();
  };

  schema.statics.findActive = function (filter = {}) {
    return this.find({ ...filter, deletedAt: null });
  };

  const excludeDeleted = function (next) {
    if (!this.getFilter().includeDeleted) {
      this.where({ deletedAt: null });
    }
    next();
  };

  schema.pre("find", excludeDeleted);
  schema.pre("findOne", excludeDeleted);
  schema.pre("findOneAndUpdate", excludeDeleted);
  schema.pre("countDocuments", excludeDeleted);
}

export default softDeletePlugin;
