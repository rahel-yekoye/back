require('dotenv').config({ path: './secret.env' });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs'); // Replace bcrypt with bcryptjs
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Message = require('./models/message'); // Import Message model
const User = require('./models/user'); // Import User model
const Group = require('./models/group'); // Adjust the path if necessary
const { parsePhoneNumberFromString } = require('libphonenumber-js');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const Joi = require('joi'); // Import Joi for validation
const { groupSchema } = require('./schemas'); // Import groupSchema
const app = express();
const fs = require('fs'); // for file handling (e.g., audio uploads in future)
const port = 4000;

// Temporary storage for verification codes
const verificationCodes = new Map();

// Create HTTP server to attach Socket.IO
const server = http.createServer(app);

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: '*', // Allow requests from any origin (adjust this for production)
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => console.error('❌ MongoDB connection error:', err));

// Test route
app.get('/', (req, res) => {
  res.send('🚀 Chat App Backend with Real-Time is Running!');
});

const registerSchema = Joi.object({
  username: Joi.string().required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().required(),
  password: Joi.string().min(6).required(),
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { error } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  const { username, email, phoneNumber, password } = req.body;

  console.log('Received registration data:', req.body); // Debug log

  if (!username || !email || !phoneNumber || !password) {
    console.log('Missing required fields'); // Debug log
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      console.log('Username already exists:', username); // Debug log
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Check if the phone number already exists
    const existingPhone = await User.findOne({ phoneNumber });
    if (existingPhone) {
      console.log('Phone number already exists:', phoneNumber); // Debug log
      return res.status(400).json({ error: 'Phone number already exists' });
    }

    // Generate a random verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    console.log('Generated verification code:', verificationCode); // Debug log

    // Save the code and user details temporarily
    verificationCodes.set(email, { username, phoneNumber, password, verificationCode });

    // Send the verification code via email
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: 'tnegussie14@gmail.com', // Replace with your Gmail address
        pass: 'itve nhev cdcy sihv', // Replace with the generated App Password
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
    console.error('Error during registration:', error); // Log the error
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verification endpoint
app.post('/verify', async (req, res) => {
  const { email, verificationCode } = req.body;

  console.log('Received verification data:', req.body); // Debug log

  if (!email || !verificationCode) {
    console.log('Missing required fields'); // Debug log
    return res.status(400).json({ error: 'Email and verification code are required' });
  }

  try {
    // Check if the verification code matches
    const userData = verificationCodes.get(email);
    if (!userData || userData.verificationCode !== verificationCode) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Save the user to the database
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const newUser = new User({
      username: userData.username,
      email,
      phoneNumber: userData.phoneNumber,
      password: hashedPassword,
    });
    await newUser.save();

    // Remove the verification code from temporary storage
    verificationCodes.delete(email);

    console.log('User registered successfully:', newUser); // Debug log
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during verification:', error); // Debug log
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
  const token = authHeader && authHeader.split(' ')[1]; // Properly extract token

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
  console.log('Authenticated user:', req.user); // Debug log
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
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Handle group message sending
  socket.on('send_group_message', async (data) => {
    console.log('Received send_group_message event:', data);

    const { groupId, sender, content } = data;

    if (!groupId || !sender || !content) {
      console.error('Missing required fields for send_group_message');
      return;
    }

    try {
      // Save the message to the database
      const message = new Message({
        sender,
        groupId,
        content,
        isGroup: true,
        timestamp: new Date(),
      });

      await message.save();
      console.log('Message saved to database:', message);

      // Emit the message to all members of the group
      io.to(groupId).emit('group_message', {
        sender,
        content: message.content,
        timestamp: message.timestamp,
      });

      console.log(`Message emitted to group ${groupId}:`, {
        sender,
        content: message.content,
        timestamp: message.timestamp,
      });
    } catch (error) {
      console.error('Error saving or emitting message:', error);
    }
  });

  // Handle joining groups
  socket.on('join_groups', (groupIds) => {
    console.log('Received groupIds:', groupIds);

    if (!Array.isArray(groupIds)) {
      console.warn('groupIds is not an array. Wrapping it in an array.');
      groupIds = [groupIds];
    }

    groupIds.forEach((groupId) => {
      socket.join(groupId);
      console.log(`User ${socket.id} joined group: ${groupId}`);
    });
  });

  socket.on('join_room', (roomId) => {
    socket.join(roomId);
    console.log(`User ${socket.id} joined room: ${roomId}`);
  });

  // Handle sending messages
  socket.on('send_message', async (data) => {
    console.log('Received send_message event:', data);

    const { roomId, sender, receiver, content, timestamp } = data;

    // Validate required fields
    if (!roomId || !sender || !receiver || !content || !timestamp) {
      console.error('Missing required fields for send_message:', {
        roomId: !!roomId,
        sender: !!sender,
        receiver: !!receiver,
        content: !!content,
        timestamp: !!timestamp,
      });
      return;
    }

    try {
      // Save the message to the database
      const message = new Message({
        sender,
        receiver,
        content,
        roomId,
        isGroup: false,
        timestamp: new Date(timestamp),
      });

      await message.save();
      console.log('Message saved to database:', message);

      // Emit the message to the sender and receiver
      io.to(roomId).emit('receive_message', {
        sender,
        receiver,
        content: message.content,
        timestamp: message.timestamp,
      });

      console.log(`Message emitted to room ${roomId}:`, {
        sender,
        receiver,
        content: message.content,
        timestamp: message.timestamp,
      });
    } catch (error) {
      console.error('Error saving or emitting message:', error);
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
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
  const { user1, user2 } = req.query;

  if (!user1 || !user2) {
    return res.status(400).json({ error: 'Both user1 and user2 are required' });
  }

  try {
    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 },
      ],
    }).sort({ timestamp: 1 });

    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
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
  res.status(200).json({
    message: 'File uploaded successfully',
    fileUrl: `http://localhost:${port}/uploads/${req.file.filename}`,
  });
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
          $or: [
            { sender: user },
            { receiver: user },
          ],
        },
      },
      {
        $sort: { timestamp: -1 },
      },
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
    ]);

    res.json(conversations.map((conv) => ({
      otherUser: conv._id,
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
      members: [req.user.id, ...members], // Add the creator as the first member
      createdBy: req.user.id,
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

    if (group.admin.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Only the group admin can add members' });
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

app.post('/groups/:groupId/messages', authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const { content } = req.body;

  if (!content) {
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

app.get('/users', authenticateToken, async (req, res) => {
  try {
    // Fetch all users except the current user
    const users = await User.find(
      { _id: { $ne: req.user.id } }, // Exclude the current user
      'username email' // Only return username and email
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server with socket.io attached
server.listen(port, () => {
  console.log(`🚀 Server is running with real-time on http://localhost:${port}`);
});
