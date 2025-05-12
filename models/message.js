const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true, default: 'Unknown' },
  receiver: { type: String, required: true, default: 'Unknown' },
  groupId: { type: String, default: null }, // Optional for group
  content: { type: String, required: true, default: '[No Content]' },
  fileUrl: { type: String, default: '' },   // For attachments
  emojis: { type: [String], default: [] },  // For emoji reactions
  isGroup: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Message', messageSchema);
