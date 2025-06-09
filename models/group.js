const mongoose = require('mongoose');

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String }, 
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Group members
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Group', groupSchema);