const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true, default: 'Unknown' },
  receiver: { type: String, required: true, default: 'Unknown' },
  groupId: { type: String, default: null },
  content: { type: String, default: '[No Content]' },
  fileUrl: { type: String, default: '' },
  emojis: { type: [String], default: [] },
  isGroup: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
  visibleTo: [{ type: String }],
  readBy: { type: [String], default: [] },  // <-- ADD THIS
});

module.exports = mongoose.model('Message', messageSchema);
