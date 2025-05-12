const mongoose = require('mongoose');

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String }, // Optional group description
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Group admin
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Group members
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Group', groupSchema);