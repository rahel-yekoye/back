require('dotenv').config({ path: './secret.env' });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Message = require('./models/message'); 
const User = require('./models/user'); 
const Group = require('./models/group'); 
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Joi = require('joi'); 
const { groupSchema } = require('./schemas'); 
const app = express();
const fs = require('fs'); 
const port = 4000;

const verificationCodes = new Map();
const callTimers = {};

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*', 
    methods: ['GET', 'POST']
  }
});
//middleware ..cors handles frontend requests and express the api framework
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log(' Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

app.get('/', (req, res) => {
  res.send(' Chat App Backend with Real-Time is Running!');
});

const registerSchema = Joi.object({
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().required(),
  password: Joi.string().min(6).required(),
});


app.post('/register', async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, email, phoneNumber, password } = req.body;

  console.log('Received registration data:', req.body);

  if (!username || !email || !phoneNumber || !password) {
    console.log('Missing required fields'); 
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log('Username already exists:', username); 
      return res.status(400).json({ error: 'Username already exists' });
    }

    const existingPhone = await User.findOne({ phoneNumber });
    if (existingPhone) {
      console.log('Phone number already exists:', phoneNumber); 
      return res.status(400).json({ error: 'Phone number already exists' });
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated verification code:', verificationCode); 

    verificationCodes.set(email, { username, phoneNumber, password, verificationCode });

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'tnegussie14@gmail.com', 
        pass: 'itve nhev cdcy sihv', 
      },
    });

    await transporter.sendMail({
      from: 'tnegussie14@gmail.com',
      to: email,
      subject: 'Email Verification Code',
      text: `Your verification code is: ${verificationCode}`,
    });

    res.status(201).json({ message: 'Verification code sent to your email' });
  } catch (error) {
    console.error('Error during registration:', error); 
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/verify', async (req, res) => {
  const { email, verificationCode } = req.body;

  if (!email || !verificationCode) {
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  try {
    const userData = verificationCodes.get(email);
    if (!userData || userData.verificationCode !== verificationCode) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const parsedPhoneNumber = parsePhoneNumberFromString(userData.phoneNumber, 'ET');
    const normalizedPhoneNumber = parsedPhoneNumber ? parsedPhoneNumber.number : userData.phoneNumber;

    const newUser = new User({
      username: userData.username,
      email,
      phoneNumber: normalizedPhoneNumber, // <-- always save normalized!
      password: hashedPassword,
    });
    await newUser.save();
    verificationCodes.delete(email);

    const token = jwt.sign({ id: newUser._id, email: newUser.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
      },
    });

  } catch (error) {
    console.error('Error during verification:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  console.log('Login request body:', req.body); // Debugging log

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  console.log('Authorization Header:', req.headers['authorization']);
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid or malformed token.' });
    }
    req.user = user; // Attach the user payload to the request
    next();
  });
}

console.log('MongoDB URI:', process.env.MONGO_URI);
console.log('JWT Secret:', process.env.JWT_SECRET);

// Rate limiter
const searchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests, please try again later.',
});

// Secured /search endpoint
app.get('/search', authenticateToken, async (req, res) => {
  console.log('Authenticated user:', req.user); 
  const { phoneNumber } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: 'Phone number is required' });
  }

  try {
    console.log('Received phone number:', phoneNumber); // Debug log

    const { parsePhoneNumberFromString } = require('libphonenumber-js');
    const parsedPhoneNumber = parsePhoneNumberFromString(phoneNumber, 'ET'); // Replace 'ET' with your default country code
    if (!parsedPhoneNumber || !parsedPhoneNumber.isValid()) {
      console.log('Invalid phone number format:', phoneNumber); // Debug log
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    const normalizedPhoneNumber = parsedPhoneNumber.number;
    console.log('Normalized phone number:', normalizedPhoneNumber); // Debug log

    const user = await User.findOne({ phoneNumber: normalizedPhoneNumber });
    if (!user) {
      console.log('User not found for phone number:', normalizedPhoneNumber); // Debug log
      return res.status(404).json({ error: 'User not found' });
    }

    console.log('User found:', user); // Debug log
    res.json({ success: true, user: { username: user.username, phoneNumber: user.phoneNumber } });
  } catch (error) {
    console.error('Error searching for user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Real-time Socket.IO connection
const userIdToSocketId = {};

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('register_user', (userId) => {
    userIdToSocketId[userId] = socket.id;
  socket.data.userId = userId;
    socket.join(userId);
    console.log(`[SOCKET] User ${userId} registered (socket.id: ${socket.id})`);
  });

  socket.on('disconnect', () => {
    for (const [userId, sId] of Object.entries(userIdToSocketId)) {
      if (sId === socket.id) {
        delete userIdToSocketId[userId];
        break;
      }
    }
  });

  // Register user to their own room for signaling
// Handle group message sending
socket.on('send_group_message', async (data) => {
  const { groupId, sender, content, clientId, fileUrl } = data;
  console.log('📥 Received send_group_message:', data);

  if (!groupId || !sender || (!content && !fileUrl)) {
    console.error('❌ Missing fields in send_group_message:', data);
    return;
  }

  try {
    const message = new Message({
      sender,
      groupId,
      content,
      isGroup: true,
      timestamp: new Date(),
      clientId: clientId || null,    // ✅ Save clientId
      fileUrl: fileUrl || '',        // ✅ Save fileUrl
    });

    await message.save();
    console.log('✅ Message saved to database:', message);

    io.to(groupId).emit('group_message', {
      _id: message._id.toString(),        // ✅ Optional but ideal for syncing
      clientId: message.clientId,
      groupId,
      sender,
      content: message.content,
      timestamp: message.timestamp,
      fileUrl: message.fileUrl,
    });

    console.log(`📤 Message emitted to group ${groupId}:`, {
      sender,
      content: message.content,
      timestamp: message.timestamp,
      clientId: message.clientId,
      fileUrl: message.fileUrl,
    });
  } catch (error) {
    console.error('❌ Error saving or emitting message:', error);
  }
});

// Handle joining groups
socket.on('join_group', (groupIds) => {
  console.log('📥 Received join_group payload:', groupIds);

  // Defensive check: accept string or array of strings
  if (typeof groupIds === 'string') {
    groupIds = [groupIds];
  }

  if (!Array.isArray(groupIds)) {
    console.warn('⚠️ join_group payload is neither string nor array:', groupIds);
    return;
  }

  groupIds.forEach((groupId, index) => {
    if (typeof groupId === 'string' && groupId.trim().length > 0) {
      socket.join(groupId);
      console.log(`Socket ${socket.id} joined room ${groupId}`);
console.log('Current clients in room:', io.sockets.adapter.rooms.get(groupId));

      socket.emit('joined_group', groupId); // Used by frontend to confirm
      console.log(`✅ User ${socket.id} joined group [${index}]: ${groupId}`);
    } else {
      console.warn(`⚠️ Empty or invalid groupId at index ${index}:`, groupId);
    }
  });
});

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    console.log(`User ${socket.id} joined room: ${roomId}`);
    // Print all sockets in the room
    const room = io.sockets.adapter.rooms.get(roomId);
    console.log(`Current sockets in room ${roomId}:`, room ? Array.from(room) : []);
  });

  function normalizeRoomId(user1, user2) {
    return user1 < user2 ? `${user1}_${user2}` : `${user2}_${user1}`;
  }

// Handle sending messages
socket.on('send_message', async (data) => {
  console.log('📨 Received send_message event:', data);

  // Destructure with clientId included
  const {
    roomId,
    sender,
    receiver,
    content,
    timestamp,
    fileUrl,
    clientId,
  } = data;

  const normalizedRoomId = normalizeRoomId(sender, receiver);

  // Validate required fields
  if (!roomId || !sender || !receiver || !timestamp) {
    console.error('❌ Missing required fields for send_message:', {
      roomId: !!roomId,
      sender: !!sender,
      receiver: !!receiver,
      content: !!content,
      timestamp: !!timestamp,
    });
    return;
  }

  try {
    // Construct message
    const message = new Message({
      sender,
      receiver,
      content,
      roomId,
      isGroup: false,
      timestamp: new Date(timestamp),
      fileUrl: fileUrl || '',
      visibleTo: [sender, receiver],
      readBy: [sender],
      direction: 'outgoing',
      clientId: clientId || null, // ✅ Save clientId if needed for tracking
    });

    await message.save();
    console.log('✅ Message saved to database:', message);

    // Emit to room: client can filter by clientId to avoid duplication
    io.to(normalizedRoomId).emit('receive_message', {
      _id: message._id,
      sender: message.sender,
      receiver: message.receiver,
      roomId: message.roomId,
      content: message.content,
      fileUrl: message.fileUrl,
      isGroup: message.isGroup,
      isFile: !!message.fileUrl,
      deleted: message.deleted,
      edited: message.edited,
      direction: 'incoming',
      duration: message.duration ?? null,
      timestamp: message.timestamp.toISOString(),
      readBy: message.readBy,
      visibleTo: message.visibleTo,
      emojis: message.emojis,
      clientId: message.clientId, // ✅ Echo back to allow deduplication
    });

    console.log(`📤 Message emitted to room ${normalizedRoomId}`);

    // Mark as read immediately if receiver is in the room
    const room = io.sockets.adapter.rooms.get(normalizedRoomId);
    const receiverSocketId = userIdToSocketId[receiver];

    if (room && receiverSocketId && room.has(receiverSocketId)) {
      await Message.updateOne(
        { _id: message._id },
        { $addToSet: { readBy: receiver } }
      );

      io.to(normalizedRoomId).emit('message_read', {
        messageId: message._id.toString(),
        reader: receiver,
      });

      console.log(`✅ Message marked as read by ${receiver}`);
    }

    // Emit conversation updates (inbox-style)
    const updateForReceiver = {
      otherUser: sender,
      message: message.content,
      timestamp: message.timestamp.toISOString(),
      isGroup: false,
    };

    const updateForSender = {
      otherUser: receiver,
      message: message.content,
      timestamp: message.timestamp.toISOString(),
      isGroup: false,
    };

    io.to(receiver).emit('conversation_update', updateForReceiver);
    io.to(sender).emit('conversation_update', updateForSender);

  } catch (error) {
    console.error('❌ Error saving or emitting message:', error);
  }
});

socket.on('mark_as_read', async ({ user, otherUser }) => {
  const roomId = [user, otherUser].sort().join('_');
  const messages = await Message.find({
    roomId,
    readBy: { $ne: user }, // unread by this user
    receiver: user,        // only mark ones received
  });

const messageIds = messages.map(msg => msg._id.toString());

  await Message.updateMany(
    { _id: { $in: messageIds } },
    { $addToSet: { readBy: user } }
  );

  io.to(roomId).emit('messages_read', {
    messageIds,
    reader: user,
  });
});



// PUT /messages/mark-read
// Request body: { user: 'username', otherUser: 'username' }

app.put('/messages/mark-read', async (req, res) => {
  const { user, otherUser } = req.body;

  if (!user || !otherUser) return res.status(400).json({ error: 'Missing parameters' });

  const roomId = normalizeRoomId(user, otherUser);

  try {
    const messagesToUpdate = await Message.find({
      roomId,
      visibleTo: user,
      readBy: { $ne: user },
    });

    const messageIds = messagesToUpdate.map(msg => msg._id);
    await Message.updateMany(
      { _id: { $in: messageIds } },
      { $addToSet: { readBy: user } }
    );

    const readMessageIds = messageIds.map(id => id.toString());

    // Notify the receiver (otherUser) if online
    const senderSocketId = userIdToSocketId[otherUser];
    if (senderSocketId) {
      io.to(senderSocketId).emit('messages_read', {
        reader: user,
        messageIds: readMessageIds,
      });
    }

    res.json({ success: true, updatedCount: readMessageIds.length });

  } catch (err) {
    console.error('Error marking messages as read:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


  // --- CALL SIGNALING EVENTS ---

  // When caller starts the call (ring the receiver)


  // When caller starts the call (ring the receiver)
  socket.on('call_initiate', (data) => {
    console.log(`[SOCKET] call_initiate: from=${data.from}, to=${data.to}, callerName=${data.callerName}`);
    io.to(data.to).emit('incoming_call', {
      from: data.from,
      voiceOnly: data.voiceOnly,
      callerName: data.callerName,
    });
    console.log(`[SOCKET] Emitting incoming_call to: ${data.to}`);

    // Start missed call timer
    const callKey = `${data.from}_${data.to}`;
    callTimers[callKey] = setTimeout(() => {
      // Call not answered in 30 seconds
      const missedCallMsg = {
        sender: data.from,
        receiver: data.to,
        content: 'Missed call',
        type: 'missed_call',
        timestamp: new Date().toISOString(),
        visibleTo: [data.to],
      };
      Message.create(missedCallMsg);
      io.to(data.to).emit('missed_call', missedCallMsg);
      delete callTimers[callKey];
    }, 30000); // 30 seconds
  });

  // When receiver accepts the call, send the offer to the callee
socket.on('call_offer', (data) => {
  // data: { to, from, offer, type, voiceOnly, callerName }
  console.log(`Call offer from ${data.from} to ${data.to}`);
  io.to(data.to).emit('call_offer', {
    offer: data.offer,
    type: data.type, // <-- ADD THIS LINE
    from: data.from,
    voiceOnly: data.voiceOnly,
    callerName: data.callerName,
  });
});
  // Receiver answers the call
  /*socket.on('answer_made', (data) => {
    console.log(`Answer from ${data.from} to ${data.to}`);
    io.to(data.to).emit('answer_made', {
            from: data.from,
            answer: data.answer,
    });
  });*/
socket.on('call_cancelled', (data) => {
  console.log(`[SOCKET] call_cancelled: from=${data.from}, to=${data.to}`);
  io.to(data.to).emit('call_cancelled', {
    from: data.from,
    to: data.to,
  });
  // Save missed call message to DB
  const missedCallMsg = {
    sender: data.from,
    receiver: data.to,
    content: 'Missed call',
    type: 'missed_call',
    timestamp: new Date().toISOString(),
    visibleTo: [data.to], // Only callee should see
  };
  // Save to DB (pseudo-code)
  Message.create(missedCallMsg);
  // Notify callee
  io.to(data.to).emit('missed_call', missedCallMsg);
  // Do NOT notify the caller

  // For the caller (cancelled call)
  const cancelledCallMsg = {
    sender: data.from,
    receiver: data.to,
    content: 'Cancelled call',
    type: 'cancelled_call',
    timestamp: new Date().toISOString(),
    visibleTo: [data.from], // Only caller should see
  };
  // Save to DB (optional)
  Message.create(cancelledCallMsg);
  // Notify ONLY the caller
  io.to(data.from).emit('cancelled_call', cancelledCallMsg);
});

  // ICE candidates exchange
  socket.on('ice_candidate', (data) => {
    io.to(data.to).emit('ice_candidate', {
      candidate: data.candidate,
      from: data.from,
    });
  });

  // When receiver declines the call
  socket.on('decline_call', (data) => {
    console.log(`Call declined by ${data.from} to ${data.to}`);
    io.to(data.to).emit('call_declined', {
      from: data.from,
    });
  });

  // Optional: call ended
  // Optional: call ended
socket.on('end_call', (data) => {
  console.log(`Call ended by ${data.from} for ${data.to}`);
  // Notify BOTH users
  io.to(data.to).emit('call_ended', { from: data.from, to: data.to });
  io.to(data.from).emit('call_ended', { from: data.from, to: data.to });
});

  socket.on('join_group', (groupId) => {
    socket.join(groupId);
    console.log(`Socket ${socket.id} joined room ${groupId}`);
console.log('Current clients in room:', io.sockets.adapter.rooms.get(groupId));

    console.log(`User ${socket.id} joined group: ${groupId}`);
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
  });

  socket.on('make_answer', (data) => {
    const targetSocketId = userIdToSocketId[data.to];
    if (targetSocketId) {
      io.to(targetSocketId).emit('answer_made', {
        answer: data.answer,
        from: data.from,
      });
      console.log(`[DEBUG] Sent answer_made to socket ${targetSocketId}`);
    } else {
      console.log(`[ERROR] No socket found for user ${data.to}`);
    }
  });

  // When a call ends after being answered
  function emitCallLog(callerId, calleeId, durationSeconds) {
    console.log('Emitting call log:', callerId, calleeId, durationSeconds);
    // For caller (outgoing)
    const outgoingLog = {
      sender: callerId,
      receiver: calleeId,
      type: 'call_log',
      direction: 'outgoing',
      duration: durationSeconds,
      timestamp: new Date().toISOString(),
      content: 'Outgoing call',
      visibleTo: [callerId]
    };
    // For callee (incoming)
    const incomingLog = {
      sender: calleeId,
      receiver: callerId,
      type: 'call_log',
      direction: 'incoming',
      duration: durationSeconds,
      timestamp: new Date().toISOString(),
      content: 'Incoming call',
      visibleTo: [calleeId]
    };
    io.to(callerId).emit('call_log', outgoingLog);
    io.to(calleeId).emit('call_log', incomingLog);
    Message.create(outgoingLog);
    Message.create(incomingLog);
  }

  socket.on('join', (userId) => {
    socket.join(userId);
  });
});



// API route to send message (for compatibility if needed)
app.post('/messages', async (req, res) => {
  try {
    console.log('New message received via API:', req.body);
    const { sender, receiver, content } = req.body;

    // Check if the message already exists in the database
    const existingMessage = await Message.findOne({ sender, receiver, content });

    if (!existingMessage) {
      console.log('No duplicate message found, saving message.');
    } else {
      console.log('Duplicate message detected:', existingMessage);
    }

    if (!existingMessage) {
      const message = new Message({ sender, receiver, content });
      await message.save();

      // Emit real-time message to sender and receiver rooms
      io.to(sender).emit('receive_message', message);
      io.to(receiver).emit('receive_message', message);

      res.json({ success: true, message: 'Message sent!', data: message });
    } else {
      console.log('Duplicate message detected, not saving.');
      res.json({ success: false, message: 'Duplicate message detected' });
    }
  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ success: false, message: 'Failed to send message', error });
  }
});

// API route to get chat history
app.get('/messages', async (req, res) => {
  const { user1, user2, currentUser } = req.query;

  console.log(`[API] GET /messages called with user1=${user1}, user2=${user2}, currentUser=${currentUser}`);

  if (!user1 || !user2 || !currentUser) {
    console.warn('[API] Missing required query parameters');
    return res.status(400).json({ error: 'user1, user2, and currentUser are required' });
  }

  try {
    const messages = await Message.find({
      $and: [
        {
          $or: [
            { sender: user1, receiver: user2 },
            { sender: user2, receiver: user1 },
          ]
        },
        {
          visibleTo: currentUser
        }
      ]
    }).sort({ timestamp: 1 });

    if (!messages.length) {
      console.log('[API] No messages found for the conversation');
    } else {
      console.log(`[API] Fetched ${messages.length} messages`);
    }

    res.json(messages);
  } catch (error) {
    console.error('[API] Error fetching messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Configure storage for uploaded files (images, audio, etc.)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads/');
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// File upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
const ip = req.headers.host; // e.g., "localhost:4000"
const fileUrl = `http://${ip}/uploads/${req.file.filename}`;
res.json({ fileUrl });
});

// API route to get all conversations for a user
app.get('/conversations', async (req, res) => {
  const { user } = req.query;

  if (!user) {
    return res.status(400).json({ error: 'User is required' });
  }

  try {
    const conversations = await Message.aggregate([
      {
        $match: {
          $and: [
            {
              $or: [
                { sender: user },
                { receiver: user },
              ],
            },
            { isGroup: { $ne: true } }
          ]
        },
      },
      { $sort: { timestamp: -1 } },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$sender', user] },
              '$receiver',
              '$sender',
            ],
          },
          latestMessage: { $first: '$$ROOT' },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id", // or "username" if you use usernames
          as: "userInfo"
        }
      },
      {
        $addFields: {
          otherUser: { $arrayElemAt: ["$userInfo.username", 0] }
        }
      }
    ]);

    res.json(conversations.map((conv) => ({
      otherUser: conv.otherUser || conv._id,
      message: conv.latestMessage.content || '[No Content]',
      timestamp: conv.latestMessage.timestamp || new Date().toISOString(),
    })));
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups', authenticateToken, async (req, res) => {
  const { name, description, members } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Group name is required' });
  }

  try {
    const group = new Group({
      name,
      description,
      members: [req.user.id, ...members], // Add creator as a member
      createdBy: req.user.id, // Optionally track who created the group
    });

    await group.save();
    res.status(201).json(group);
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups/:groupId/add', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { members } = req.body;

  try {
    const group = await Group.findById(groupId);

    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    group.members.push(...members);
    await group.save();

    // Notify the added members (real-time notification)
    members.forEach((memberId) => {
      io.to(memberId).emit('group_notification', {
        message: `You have been added to the group: ${group.name}`,
        groupId: group._id,
      });
    });

    res.json({ message: 'Members added successfully', group });
  } catch (error) {
    console.error('Error adding members to group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await Group.find({ members: req.user.id });
    console.log('Fetched groups:', groups); // Log the fetched groups

    // Return full group details
    res.json(groups);
  } catch (error) {
    console.error('Error fetching groups:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/groups/:groupId', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  try {
    const group = await Group.findById(groupId).lean();
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    res.json(group);
  } catch (error) {
    console.error('Error fetching group:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { content } = req.body;

if (!content && !fileUrl) {
    return res.status(400).json({ error: 'Message content is required' });
  }

  try {
    const group = await Group.findById(groupId);

    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    const message = new Message({
      sender: req.user.id,
      groupId,
      content,
      isGroup: true,
      timestamp: new Date(),
    });

    await message.save();

    // Emit the message to all group members
    io.to(groupId).emit('group_message', {
      sender: req.user.username,
      content: message.content,
      timestamp: message.timestamp,
    });
    console.log(`Message emitted to group ${groupId}:`, {
      sender: req.user.username,
      content: message.content,
      timestamp: message.timestamp,
    });

    res.json({ message: 'Message sent successfully', data: message });
  } catch (error) {
    console.error('Error sending group message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;

  try {
    const messages = await Message.find({ groupId }).sort({ timestamp: 1 }); // Sort by timestamp
    res.json(messages);
  } catch (error) {
    console.error('Error fetching group messages:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/groups/:groupId/last-message', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  try {
    const lastMessage = await Message.findOne({ groupId })
      .sort({ timestamp: -1 })
      .lean();
    if (!lastMessage) {
      return res.json(null);
    }
    res.json(lastMessage);
  } catch (error) {
    console.error('Error fetching last group message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
/// DELETE /messages/:id  (or POST /messages/delete-many for batch delete)
// Example using Express + MongoDB
// Add a test route to verify server is reachable
app.get('/health', (req, res) => {
  console.log('✅ Health check route hit');
  res.send('OK');
});

app.delete('/messages/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`🗑️ Attempting to delete message with ID: ${id}`);

  if (!mongoose.Types.ObjectId.isValid(id)) {
    console.warn(`⚠️ Invalid ObjectId format for ID: ${id}`);
    return res.status(400).json({ error: 'Invalid message ID format' });
  }

  try {
    const deleted = await Message.findByIdAndDelete(id);
    if (!deleted) {
      console.warn(`⚠️ Message with ID ${id} not found`);
      return res.status(404).json({ error: 'Message not found' });
    }

    console.log('✅ Deleted message:', {
      id: deleted._id,
      content: deleted.content,
      fileUrl: deleted.fileUrl,
    });

    res.status(200).json({ message: 'Deleted successfully' });
  } catch (err) {
    console.error(`❌ Error deleting message ID ${id}:`, err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.post('/messages/delete-many', async (req, res) => {
  const { ids } = req.body;

  if (!Array.isArray(ids) || ids.length === 0) {
    console.warn('⚠️ No valid IDs provided for delete-many');
    return res.status(400).json({ error: 'No valid IDs provided' });
  }

  // Validate all IDs are valid ObjectIds
  const invalidIds = ids.filter(id => !mongoose.Types.ObjectId.isValid(id));
  if (invalidIds.length > 0) {
    console.warn(`⚠️ Invalid ObjectId(s) detected: ${invalidIds.join(', ')}`);
    return res.status(400).json({ error: 'One or more invalid IDs' });
  }

  try {
    console.log('🗑️ Request to delete messages:', ids);

    const result = await Message.deleteMany({ _id: { $in: ids } });
    console.log(`✅ Deleted ${result.deletedCount} message(s) from DB.`);

    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    console.error('❌ Delete many error:', error);
    res.status(500).json({ error: 'Failed to delete messages' });
  }
});

app.put('/messages/:id', async (req, res) => {
  const messageId = req.params.id;
  const { content } = req.body;

  try {
    const updatedMessage = await Message.findByIdAndUpdate(
      messageId,
      { content, edited: true },
      { new: true }
    );

    if (!updatedMessage) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json(updatedMessage);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/users', authenticateToken, async (req, res) => {
  try {
    // Fetch all users except the current user
    const users = await User.find(
      { _id: { $ne: req.user.id } }, // Exclude the current user
      '_id username email' // <-- include _id
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req, res, next) => {
  console.log(`❓ Incoming request: ${req.method} ${req.url}`);
  next();
});

// Start server with socket.io attached
server.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});

