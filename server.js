const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const dataManager = require('./utils/dataManager');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// JWT Secret - should be in environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'studysync_default_secret_change_in_production';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "ws:"],
    },
  },
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: { error: 'Too many messages, please slow down.' },
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks and static files
    return req.path === '/health' || req.path.startsWith('/favicon') || req.path.startsWith('/robots');
  },
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.round(15 * 60) // 15 minutes in seconds
    });
  }
});

// Trust proxy for rate limiting (if behind reverse proxy)
app.set('trust proxy', 1);

// Basic middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', generalLimiter);

// Storage - now using dataManager for persistence
let accounts = new Map();
let users = new Map();
let connectedUsers = new Map();
let emergencyShutdown = false;

// Initialize data storage
let messages = new Map();
let friendships = new Map();
let friendRequests = new Map();
let groups = new Map();
let privateChats = new Map();
let notifications = new Map();
let reports = new Map();
let userBlocks = new Map();

// Socket.io rate limiting storage
let socketRateLimits = new Map(); // Map of socketId -> { messageCount, lastReset }

// Socket.io rate limiting function
function checkSocketRateLimit(socketId, limit = 30, windowMs = 60000) {
  const now = Date.now();
  const userLimit = socketRateLimits.get(socketId);
  
  if (!userLimit) {
    socketRateLimits.set(socketId, { messageCount: 1, lastReset: now });
    return true;
  }
  
  // Reset counter if window has passed
  if (now - userLimit.lastReset > windowMs) {
    socketRateLimits.set(socketId, { messageCount: 1, lastReset: now });
    return true;
  }
  
  // Check if limit exceeded
  if (userLimit.messageCount >= limit) {
    return false;
  }
  
  // Increment counter
  userLimit.messageCount++;
  socketRateLimits.set(socketId, userLimit);
  return true;
}

// Clean up old rate limit entries
setInterval(() => {
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  
  for (const [socketId, limit] of socketRateLimits.entries()) {
    if (now - limit.lastReset > windowMs * 2) { // Keep for 2 windows
      socketRateLimits.delete(socketId);
    }
  }
}, 300000); // Clean up every 5 minutes

// Utility functions
function generateId() {
  return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return validator.escape(input.trim());
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_-]{1,20}$/.test(username);
}

function isValidEmail(email) {
  return validator.isEmail(email);
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'studysync_salt').digest('hex');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

function generateJWT(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

function getChatKey(chatType, chatId) {
  return `${chatType}_${chatId}`;
}

function getPrivateChatId(userId1, userId2) {
  return userId1 < userId2 ? `${userId1}_${userId2}` : `${userId2}_${userId1}`;
}

function getUserFriends(userId) {
  try {
    const userFriends = friendships.get(userId) || new Set();
    return Array.from(userFriends).map(friendId => {
      const account = accounts.get(friendId);
      if (!account) {
        console.warn(`Friend account not found: ${friendId}`);
        return null;
      }
      return {
        id: account.id,
        username: account.username,
        status: isUserOnline(friendId) ? 'online' : 'offline',
        joinedDate: account.createdAt.toISOString().split('T')[0],
        lastLogin: account.lastLogin ? account.lastLogin.toISOString().split('T')[0] : 'Never'
      };
    }).filter(friend => friend !== null);
  } catch (error) {
    console.error('Error getting user friends:', error);
    return [];
  }
}

function isUserOnline(userId) {
  return Array.from(connectedUsers.values()).some(user => user.id === userId);
}

function canUserAccessChat(userId, chatType, chatId) {
  switch (chatType) {
    case 'public':
      return true;
    case 'private':
      // Fix: Properly check for private chat access
      const participants = Array.from(privateChats.values())
        .find(chat => chat.includes(userId) && chat.includes(chatId.split('_').find(id => id !== userId)));
      return !!participants;
    case 'group':
      const group = groups.get(chatId);
      return group && group.members.includes(userId);
    default:
      return false;
  }
}
app.post('/api/leave-group/:groupId', authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    
    // Check if group exists
    const group = groups.get(groupId);
    if (!group) {
      return res.status(404).json({ error: 'Study group not found' });
    }

    // Check if user is a member of the group
    if (!group.members.includes(req.userId)) {
      return res.status(400).json({ error: 'You are not a member of this group' });
    }

    // Remove user from group members
    group.members = group.members.filter(memberId => memberId !== req.userId);
    
    // If no members left, delete the group entirely
    if (group.members.length === 0) {
      groups.delete(groupId);
      
      // Also delete the group's messages
      const groupChatKey = `group_${groupId}`;
      messages.delete(groupChatKey);
      
      console.log(`[${new Date().toISOString()}] Group ${group.name} deleted - no members remaining`);
    } else {
      // Update the group
      groups.set(groupId, group);
      
      // If the leaving user was the creator and there are still members, 
      // assign creator role to the first remaining member
      if (group.createdBy === req.userId && group.members.length > 0) {
        group.createdBy = group.members[0];
        groups.set(groupId, group);
      }
      
      console.log(`[${new Date().toISOString()}] User ${req.user.username} left group ${group.name}`);
    }

    // Remove user from the group's socket room
    const groupRoom = `group_${groupId}`;
    const userSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.id === req.userId);
    if (userSocket && io.sockets.sockets.get(userSocket[0])) {
      io.sockets.sockets.get(userSocket[0]).leave(groupRoom);
    }

    // Notify remaining group members that user left
    if (group.members && group.members.length > 0) {
      io.to(groupRoom).emit('user_left_group', {
        groupId: groupId,
        groupName: group.name,
        username: req.user.username,
        userId: req.userId,
        timestamp: new Date()
      });

      // Add system message to group chat
      const systemMessage = {
        id: generateId(),
        username: 'System',
        text: `${req.user.username} left the study group`,
        timestamp: new Date(),
        userId: 'system',
        chatType: 'group',
        chatId: groupId,
        messageType: 'system'
      };

      const groupChatKey = `group_${groupId}`;
      const groupMessages = messages.get(groupChatKey) || [];
      groupMessages.push(systemMessage);
      messages.set(groupChatKey, groupMessages);

      // Broadcast system message to group
      io.to(groupRoom).emit('new_message', systemMessage);
    }

    res.json({ 
      success: true, 
      message: 'Successfully left the study group',
      groupId: groupId
    });
  } catch (error) {
    console.error('Error leaving group:', error);
    res.status(500).json({ error: 'Failed to leave group. Please try again.' });
  }
});
function addNotification(userId, notification) {
  try {
    if (!userId || !notification) {
      console.error('addNotification: Missing userId or notification');
      return;
    }

    if (!notifications.has(userId)) {
      notifications.set(userId, []);
    }
    
    // Ensure notification has required fields
    if (!notification.id) {
      notification.id = generateId();
    }
    if (!notification.timestamp) {
      notification.timestamp = new Date();
    }
    if (notification.unread === undefined) {
      notification.unread = true;
    }
    
    const userNotifications = notifications.get(userId);
    userNotifications.unshift(notification);
    
    // Keep only last 100 notifications per user
    if (userNotifications.length > 100) {
      userNotifications.splice(100);
    }
    
    notifications.set(userId, userNotifications);
    
    console.log(`[${new Date().toISOString()}] Notification added for user ${userId}: ${notification.type}`);
  } catch (error) {
    console.error('Error adding notification:', error);
  }
}

function findMessageOwner(messageId) {
  for (const [chatKey, chatMessages] of messages.entries()) {
    const message = chatMessages.find(msg => msg.id === messageId);
    if (message) {
      return {
        message,
        chatKey,
        chatType: chatKey.split('_')[0],
        chatId: chatKey.substring(chatKey.indexOf('_') + 1)
      };
    }
  }
  return null;
}

function validateMessage(text) {
  if (!text || typeof text !== 'string') {
    return { valid: false, error: 'Message must be text' };
  }
  
  const cleaned = text.trim();
  
  if (cleaned.length === 0) {
    return { valid: false, error: 'Message cannot be empty' };
  }
  
  if (cleaned.length > 500) {
    return { valid: false, error: 'Message too long (max 500 characters)' };
  }
  
  const inappropriatePatterns = [
    /(.)\1{10,}/, // spam
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/, // IP addresses
    /\b\d{3}-\d{3}-\d{4}\b/, // phone numbers
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/, // email addresses
    /\b(?:instagram|snapchat|tiktok|discord|telegram)\b/i, // social media
  ];
  
  for (const pattern of inappropriatePatterns) {
    if (pattern.test(cleaned)) {
      return { 
        valid: false, 
        error: 'Message contains content that violates our community guidelines',
        flagged: true,
        pattern: pattern.toString()
      };
    }
  }
  
  return { valid: true, text: sanitizeInput(cleaned) };
}

function checkUsageTime() {
  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay();
  
  if (day >= 1 && day <= 5 && hour >= 8 && hour < 15) {
    return {
      isSchoolHours: true,
      warning: ""
    };
  }
  
  return { isSchoolHours: false };
}
app.post('/api/friend-request', authenticateToken, async (req, res) => {
  try {
    const { toUserId } = req.body;
    
    // Validation
    if (!toUserId) {
      return res.status(400).json({ error: 'Target user ID is required' });
    }

    if (toUserId === req.userId) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    const targetAccount = accounts.get(toUserId);
    if (!targetAccount) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (targetAccount.suspended) {
      return res.status(400).json({ error: 'Cannot send friend request to suspended user' });
    }

    // Check if already friends
    const userFriends = friendships.get(req.userId) || new Set();
    if (userFriends.has(toUserId)) {
      return res.status(400).json({ error: 'Already friends with this user' });
    }

    // Check if request already exists (either direction)
    const existingRequest = Array.from(friendRequests.values()).find(request => 
      request.status === 'pending' && (
        (request.fromUserId === req.userId && request.toUserId === toUserId) ||
        (request.fromUserId === toUserId && request.toUserId === req.userId)
      )
    );

    if (existingRequest) {
      if (existingRequest.fromUserId === req.userId) {
        return res.status(400).json({ error: 'Friend request already sent to this user' });
      } else {
        return res.status(400).json({ error: 'This user has already sent you a friend request. Check your notifications!' });
      }
    }

    // Create new friend request
    const requestId = generateId();
    const request = {
      id: requestId,
      fromUserId: req.userId,
      toUserId: toUserId,
      timestamp: new Date(),
      status: 'pending'
    };

    friendRequests.set(requestId, request);

    // Add notification for target user
    addNotification(toUserId, {
      id: requestId,
      type: 'friend_request',
      title: 'Friend Request',
      message: `${req.user.username} wants to be study partners`,
      username: req.user.username,
      fromUserId: req.userId,
      timestamp: new Date(),
      unread: true
    });

    // Notify target user via socket if online
    const targetSocket = Array.from(connectedUsers.entries())
      .find(([_, user]) => user.id === toUserId);
    if (targetSocket) {
      io.to(targetSocket[0]).emit('friend_request_received', {
        requestId: requestId,
        from: {
          id: req.userId,
          username: req.user.username
        },
        timestamp: new Date()
      });
    }

    console.log(`[${new Date().toISOString()}] Friend request sent: ${req.user.username} -> ${targetAccount.username}`);
    
    res.json({ 
      success: true, 
      message: `Friend request sent to ${targetAccount.username}`,
      requestId: requestId
    });
  } catch (error) {
    console.error('Error sending friend request:', error);
    res.status(500).json({ error: 'Failed to send friend request. Please try again.' });
  }
});
app.post('/api/create-group', authenticateToken, async (req, res) => {
  try {
    const { name, description, members } = req.body;
    
    // Validation
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Group name is required' });
    }

    if (name.length > 50) {
      return res.status(400).json({ error: 'Group name must be 50 characters or less' });
    }

    const cleanName = sanitizeInput(name);
    const cleanDescription = description ? sanitizeInput(description) : '';

    // Validate members array
    if (!Array.isArray(members)) {
      return res.status(400).json({ error: 'Members must be an array' });
    }

    // Check if all members are valid friends of the creator
    const userFriends = friendships.get(req.userId) || new Set();
const invalidMembers = members.filter(memberId => !userFriends.has(memberId));
    
    if (members.length > 0 && invalidMembers.length > 0) {
    return res.status(400).json({ error: 'Can only add friends to study groups' });
}

    // Verify all member accounts exist and are not suspended
    const validMembers = [];
    for (const memberId of members) {
      const account = accounts.get(memberId);
      if (account && !account.suspended) {
        validMembers.push(memberId);
      }
    }

    // Create the group
    const groupId = generateId();
    const group = {
      id: groupId,
      name: cleanName,
      description: cleanDescription,
      members: [req.userId, ...validMembers], // Creator is automatically a member
      createdBy: req.userId,
      createdAt: new Date(),
      isActive: true
    };

    groups.set(groupId, group);

    // Create group chat messages container
    const groupChatKey = `group_${groupId}`;
    messages.set(groupChatKey, []);

    // Add system message to group
    const systemMessage = {
      id: generateId(),
      username: 'System',
      text: `Study group "${cleanName}" created by ${req.user.username}`,
      timestamp: new Date(),
      userId: 'system',
      chatType: 'group',
      chatId: groupId,
      messageType: 'system'
    };

    const groupMessages = messages.get(groupChatKey) || [];
    groupMessages.push(systemMessage);
    messages.set(groupChatKey, groupMessages);

    // Join all members to the group socket room
    const groupRoom = `group_${groupId}`;
    group.members.forEach(memberId => {
      const memberSocket = Array.from(connectedUsers.entries())
        .find(([_, user]) => user.id === memberId);
      if (memberSocket && io.sockets.sockets.get(memberSocket[0])) {
        io.sockets.sockets.get(memberSocket[0]).join(groupRoom);
      }
    });

    // Notify all members about the new group
    group.members.forEach(memberId => {
      if (memberId !== req.userId) {
        addNotification(memberId, {
          id: generateId(),
          type: 'group_invite',
          title: 'Added to Study Group',
          message: `${req.user.username} added you to "${cleanName}"`,
          username: req.user.username,
          fromUserId: req.userId,
          groupId: groupId,
          groupName: cleanName,
          timestamp: new Date(),
          unread: true
        });

        // Notify via socket if online
        const memberSocket = Array.from(connectedUsers.entries())
          .find(([_, user]) => user.id === memberId);
        if (memberSocket) {
          io.to(memberSocket[0]).emit('added_to_group', {
            group: {
              id: groupId,
              name: cleanName,
              description: cleanDescription,
              members: group.members.length
            },
            addedBy: {
              id: req.userId,
              username: req.user.username
            },
            timestamp: new Date()
          });
        }
      }
    });

    // Broadcast system message to all group members
    io.to(groupRoom).emit('new_message', systemMessage);

    console.log(`[${new Date().toISOString()}] Study group created: "${cleanName}" by ${req.user.username} with ${group.members.length} members`);
    
    res.json({ 
      success: true, 
      message: 'Study group created successfully',
      group: {
        id: groupId,
        name: cleanName,
        description: cleanDescription,
        members: group.members.length,
        createdAt: group.createdAt
      }
    });
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ error: 'Failed to create study group. Please try again.' });
  }
});
app.post('/api/friend-request/:requestId/respond', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { accept } = req.body;

    // Validate accept parameter
    if (typeof accept !== 'boolean') {
      return res.status(400).json({ error: 'Accept parameter must be true or false' });
    }

    const request = friendRequests.get(requestId);
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.toUserId !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to respond to this request' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Friend request has already been handled' });
    }

    // Get the sender's account
    const fromAccount = accounts.get(request.fromUserId);
    if (!fromAccount) {
      return res.status(404).json({ error: 'Requester account not found' });
    }

    let responseData = {
      success: true,
      message: accept ? 'Friend request accepted' : 'Friend request declined'
    };

    if (accept) {
      // Add to friendships
      if (!friendships.has(req.userId)) {
        friendships.set(req.userId, new Set());
      }
      if (!friendships.has(request.fromUserId)) {
        friendships.set(request.fromUserId, new Set());
      }

      friendships.get(req.userId).add(request.fromUserId);
      friendships.get(request.fromUserId).add(req.userId);

      // Create private chat if doesn't exist
      const chatId = getPrivateChatId(req.userId, request.fromUserId);
      const chatKey = `private_${chatId}`;
      if (!privateChats.has(chatKey)) {
        privateChats.set(chatKey, [req.userId, request.fromUserId]);
        messages.set(chatKey, []);
      }

      // Add friend info to response
      responseData.friend = {
        id: fromAccount.id,
        username: fromAccount.username,
        status: isUserOnline(fromAccount.id) ? 'online' : 'offline'
      };

      // Notify the sender that their request was accepted
      const senderSocket = Array.from(connectedUsers.entries())
        .find(([_, user]) => user.id === request.fromUserId);
      if (senderSocket) {
        io.to(senderSocket[0]).emit('friend_request_accepted', {
          friend: {
            id: req.userId,
            username: req.user.username,
            status: 'online'
          }
        });
      }

      // Add notification for sender
      addNotification(request.fromUserId, {
        id: generateId(),
        type: 'friend_request_accepted',
        title: 'Friend Request Accepted',
        message: `${req.user.username} accepted your friend request`,
        username: req.user.username,
        fromUserId: req.userId,
        timestamp: new Date(),
        unread: true
      });

      console.log(`[${new Date().toISOString()}] Friend request ACCEPTED: ${fromAccount.username} -> ${req.user.username}`);
    } else {
      // Add notification for sender about decline
      addNotification(request.fromUserId, {
        id: generateId(),
        type: 'friend_request_declined',
        title: 'Friend Request Declined',
        message: `${req.user.username} declined your friend request`,
        username: req.user.username,
        fromUserId: req.userId,
        timestamp: new Date(),
        unread: true
      });

      console.log(`[${new Date().toISOString()}] Friend request DECLINED: ${fromAccount.username} -> ${req.user.username}`);
    }

    // Update request status
    request.status = accept ? 'accepted' : 'declined';
    request.respondedAt = new Date();
    friendRequests.set(requestId, request);

    res.json(responseData);
  } catch (error) {
    console.error('Error responding to friend request:', error);
    res.status(500).json({ error: 'Failed to respond to friend request. Please try again.' });
  }
});
// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  const account = accounts.get(decoded.userId);
  if (!account) {
    return res.status(403).json({ error: 'Account not found' });
  }

  if (account.suspended) {
    return res.status(403).json({ 
      error: 'Account suspended',
      contactEmail: process.env.SUPPORT_EMAIL || 'support@studysync.app'
    });
  }

  req.userId = decoded.userId;
  req.user = account;
  next();
}

// Emergency shutdown middleware
app.use((req, res, next) => {
  if (emergencyShutdown && !req.path.includes('/health') && !req.path.includes('/emergency')) {
    return res.status(503).json({ 
      error: 'Platform temporarily unavailable',
      message: 'Please try again later'
    });
  }
  next();
});

// Legal pages (same as before)
app.get('/terms', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Terms of Service - StudySync</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
            h1, h2 { color: #333; }
            .highlight { background: #fff3cd; padding: 1rem; border-radius: 6px; border-left: 4px solid #ffc107; margin: 1rem 0; }
        </style>
    </head>
    <body>
        <h1>📚 StudySync Terms of Service</h1>
        <p><strong>Last Updated:</strong> ${new Date().toLocaleDateString()}</p>
        
        <div class="highlight">
            <strong>⚠️ Important:</strong> By using StudySync, you acknowledge that you are responsible for following your school's technology policies and using this platform appropriately.
        </div>
        
        <h2>1. Acceptable Use</h2>
        <p>StudySync is intended for appropriate communication between students. Users must:</p>
        <ul>
            <li>Be 13 years of age or older</li>
            <li>Follow all applicable school policies regarding technology use</li>
            <li>Use respectful and appropriate language</li>
            <li>Report violations of community guidelines</li>
            <li>Take full responsibility for their actions on the platform</li>
            <li>Use the platform during appropriate times (breaks, lunch, after school)</li>
        </ul>
        
        <h2>2. Prohibited Activities</h2>
        <ul>
            <li>Sharing personal information (phone numbers, addresses, social media)</li>
            <li>Harassment, bullying, or threatening behavior</li>
            <li>Spam or disruptive messaging</li>
            <li>Attempts to circumvent safety features</li>
            <li>Violating school technology policies</li>
            <li>Using inappropriate language or sharing inappropriate content</li>
        </ul>
        
        <h2>3. Consequences</h2>
        <p>Violations may result in warnings, account suspension, or permanent termination. We may also notify school administrators or parents when necessary.</p>
        
        <h2>4. Contact Information</h2>
        <p>Questions: <a href="mailto:${process.env.SUPPORT_EMAIL || 'support@studysync.app'}">${process.env.SUPPORT_EMAIL || 'support@studysync.app'}</a></p>
        
        <p><a href="/">← Back to StudySync</a></p>
    </body>
    </html>
  `);
});
// Legal pages (same as before)
app.get('/admin', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Terms of Service - StudySync</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
            h1, h2 { color: #333; }
            .highlight { background: #fff3cd; padding: 1rem; border-radius: 6px; border-left: 4px solid #ffc107; margin: 1rem 0; }
        </style>
    </head>
    <body>
       <div class="app-container">
        <!-- Auth Screen -->
        <div class="auth-screen" id="authScreen">
            <div class="auth-card">
                <div class="auth-header">
                    <h1>💬 StudySync Admin</h1>
                    <p>Student Communication Platform for admins</p>
                </div>
                
                <div class="auth-tabs">
                    <button class="auth-tab active" data-tab="login">Sign In</button>
                    <button class="auth-tab" data-tab="register">Create Account</button>
                </div>

                <!-- Login Form -->
                <div class="auth-form" id="loginForm">
                    <div class="input-group">
                        <label class="input-label" for="loginUsername">Username</label>
                        <input type="text" id="loginUsername" class="auth-input" placeholder="Enter your username" maxlength="20">
                    </div>
                    <div class="input-group">
                        <label class="input-label" for="loginPassword">Password</label>
                        <input type="password" id="loginPassword" class="auth-input" placeholder="Enter your password">
                    </div>
                    <button id="loginBtn" class="auth-btn">Sign In</button>
                </div>

                <!-- Register Form -->
                <div class="auth-form" id="registerForm" style="display: none;">
                    <div class="input-group">
                        <label class="input-label" for="registerUsername">Choose Username</label>
                        <input type="text" id="registerUsername" class="auth-input" placeholder="Create a username" maxlength="20">
                    </div>
                    <div class="input-group">
                        <label class="input-label" for="registerEmail">Email (Optional)</label>
                        <input type="email" id="registerEmail" class="auth-input" placeholder="your.email@school.edu">
                    </div>
                    <div class="input-group">
                        <label class="input-label" for="registerPassword">Password</label>
                        <input type="password" id="registerPassword" class="auth-input" placeholder="Create a secure password">
                    </div>
                    <div class="input-group">
                        <label class="input-label" for="confirmPassword">Confirm Password</label>
                        <input type="password" id="confirmPassword" class="auth-input" placeholder="Confirm your password">
                    </div>
                    <button id="registerBtn" class="auth-btn">Create Account</button>
                </div>
            </div>
        </div>
    </body>
    </html>
  `);
});

app.get('/privacy', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Privacy Policy - StudySync</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; line-height: 1.6; }
            h1, h2 { color: #333; }
            .highlight { background: #d1ecf1; padding: 1rem; border-radius: 6px; border-left: 4px solid #17a2b8; margin: 1rem 0; }
        </style>
    </head>
    <body>
        <h1>🔒 StudySync Privacy Policy</h1>
        <p><strong>Last Updated:</strong> ${new Date().toLocaleDateString()}</p>
        
        <div class="highlight">
            <strong>🛡️ Your Privacy:</strong> We are committed to protecting student privacy and only collecting information necessary for platform safety and functionality.
        </div>
        
        <h2>1. Information We Collect</h2>
        <ul>
            <li><strong>Account Information:</strong> Username and optional email address</li>
            <li><strong>Communication Data:</strong> Messages and chat participation</li>
            <li><strong>Usage Information:</strong> Login times, features used, device information</li>
            <li><strong>Safety Information:</strong> Reports submitted and received</li>
        </ul>
        
        <h2>2. How We Use Information</h2>
        <ul>
            <li>Provide communication services between students</li>
            <li>Ensure platform safety and security</li>
            <li>Respond to support requests and reports</li>
            <li>Comply with legal obligations</li>
        </ul>
        
        <h2>3. Information Sharing</h2>
        <p>We may share information with school administrators when required by policy or for safety concerns, parents/guardians for users under 18 when necessary, and law enforcement when legally required.</p>
        
        <h2>4. Contact Information</h2>
        <p>Privacy questions: <a href="mailto:${process.env.SUPPORT_EMAIL || 'privacy@studysync.app'}">${process.env.SUPPORT_EMAIL || 'privacy@studysync.app'}</a></p>
        
        <p><a href="/">← Back to StudySync</a></p>
    </body>
    </html>
  `);
});

// Routes
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { username, email, password, ageConfirmation, policyAcceptance } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (!ageConfirmation) {
      return res.status(400).json({ 
        error: 'You must confirm you are 13 or older to use this platform' 
      });
    }

    if (!policyAcceptance) {
      return res.status(400).json({ 
        error: 'You must accept the Terms of Service and Privacy Policy' 
      });
    }

    const cleanUsername = sanitizeInput(username);
    const cleanEmail = email ? sanitizeInput(email) : '';
    
    if (!isValidUsername(cleanUsername)) {
      return res.status(400).json({ 
        error: 'Invalid username format. Use letters, numbers, - and _ only (1-20 characters).' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long.' 
      });
    }

    if (email && !isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Invalid email format.' 
      });
    }

    const existingAccount = Array.from(accounts.values()).find(account => 
      account.username.toLowerCase() === cleanUsername.toLowerCase()
    );
    
    if (existingAccount) {
      return res.status(400).json({ 
        error: 'Username already taken. Please choose another.' 
      });
    }

    if (email) {
      const existingEmailAccount = Array.from(accounts.values()).find(account => 
        account.email && account.email.toLowerCase() === cleanEmail.toLowerCase()
      );
      
      if (existingEmailAccount) {
        return res.status(400).json({ 
          error: 'Email already registered. Please use another email.' 
        });
      }
    }

    const userId = generateId();
    const account = {
      id: userId,
      username: cleanUsername,
      email: cleanEmail,
      passwordHash: hashPassword(password),
      createdAt: new Date(),
      lastLogin: null,
      agreedToTerms: true,
      ageVerified: true,
      suspended: false
    };

    accounts.set(userId, account);
    await dataManager.setAccount(userId, account);
    
    // Initialize user data structures
    friendships.set(userId, new Set());
    notifications.set(userId, []);
    userBlocks.set(userId, new Set());
    
    console.log(`[${new Date().toISOString()}] New account created: ${cleanUsername}`);
    
    res.json({
      success: true,
      message: 'Account created successfully'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const cleanUsername = sanitizeInput(username);
    
    const account = Array.from(accounts.values()).find(acc => 
      acc.username.toLowerCase() === cleanUsername.toLowerCase()
    );
    
    if (!account) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (account.suspended) {
      return res.status(403).json({ 
        error: 'Account suspended. Contact support for assistance.',
        contactEmail: process.env.SUPPORT_EMAIL || 'support@studysync.app'
      });
    }

    if (!verifyPassword(password, account.passwordHash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    account.lastLogin = new Date();
    await dataManager.setAccount(account.id, account);

    const token = generateJWT(account.id);
    
    console.log(`[${new Date().toISOString()}] User logged in: ${account.username}`);
    
    res.json({
      success: true,
      user: {
        id: account.id,
        username: account.username,
        email: account.email
      },
      token: token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.post('/api/verify-token', (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ valid: false });
  }

  const decoded = verifyJWT(token);
  if (!decoded) {
    return res.status(401).json({ valid: false });
  }

  const account = accounts.get(decoded.userId);
  if (!account) {
    return res.status(401).json({ valid: false });
  }
  
  if (account.suspended) {
    return res.status(403).json({ 
      valid: false, 
      suspended: true,
      contactEmail: process.env.SUPPORT_EMAIL || 'support@studysync.app'
    });
  }
  
  res.json({
    valid: true,
    user: {
      id: account.id,
      username: account.username,
      email: account.email
    }
  });
});

// Protected routes using middleware
app.get('/api/messages/:chatType/:chatId', authenticateToken, (req, res) => {
  try {
    const { chatType, chatId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    
    const timeCheck = checkUsageTime();

    // Fix: For private chats, convert userId_userId format to proper chatId
    let normalizedChatId = chatId;
    if (chatType === 'private') {
      const [user1, user2] = chatId.split('_').sort();
      normalizedChatId = `${user1}_${user2}`;
    }
    
    if (!canUserAccessChat(req.userId, chatType, normalizedChatId)) {
      return res.status(403).json({ error: 'Access denied to this chat' });
    }
    
    const chatKey = getChatKey(chatType, normalizedChatId);
    let chatMessages = messages.get(chatKey) || [];
    
    const blockedUsers = userBlocks.get(req.userId) || new Set();
    chatMessages = chatMessages.filter(msg => !blockedUsers.has(msg.userId));
    
    // Pagination
    const totalMessages = chatMessages.length;
    const startIndex = Math.max(0, totalMessages - (page * limit));
    const endIndex = totalMessages - ((page - 1) * limit);
    const paginatedMessages = chatMessages.slice(startIndex, endIndex);
    
    res.json({ 
      messages: paginatedMessages,
      pagination: {
        page,
        limit,
        totalMessages,
        hasMore: startIndex > 0
      },
      chatInfo: {
        type: chatType,
        id: chatId,
        totalMessages
      },
      usageWarning: timeCheck.isSchoolHours ? timeCheck.warning : null
    });
  } catch (error) {
    console.error('Error loading messages:', error);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});

app.delete('/api/delete-message/:messageId', authenticateToken, (req, res) => {
  try {
    const { messageId } = req.params;
    
    const messageData = findMessageOwner(messageId);
    if (!messageData) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const { message, chatKey, chatType, chatId } = messageData;
    
    if (message.userId !== req.userId) {
      return res.status(403).json({ error: 'Can only delete your own messages' });
    }

    const chatMessages = messages.get(chatKey) || [];
    const messageIndex = chatMessages.findIndex(msg => msg.id === messageId);
    
    if (messageIndex !== -1) {
      chatMessages.splice(messageIndex, 1);
      messages.set(chatKey, chatMessages);
      
      const room = chatKey;
      io.to(room).emit('message_deleted', {
        messageId,
        chatType,
        chatId,
        deletedBy: req.userId
      });
      
      console.log(`[${new Date().toISOString()}] Message deleted by ${message.username}: ${messageId}`);
      
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Message not found' });
    }
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

app.post('/api/block-user', authenticateToken, (req, res) => {
  try {
    const { blockedUserId } = req.body;
    
    if (!accounts.has(blockedUserId)) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!userBlocks.has(req.userId)) {
      userBlocks.set(req.userId, new Set());
    }

    userBlocks.get(req.userId).add(blockedUserId);
    
    console.log(`[${new Date().toISOString()}] User ${req.userId} blocked user ${blockedUserId}`);
    
    res.json({ success: true, message: 'User blocked successfully' });
  } catch (error) {
    console.error('Error blocking user:', error);
    res.status(500).json({ error: 'Failed to block user' });
  }
});

app.post('/api/report', authenticateToken, (req, res) => {
  try {
    const { reportedUserId, reportedMessageId, reason, description, severity } = req.body;
    
    if (!accounts.has(reportedUserId)) {
      return res.status(404).json({ error: 'Reported user not found' });
    }

    const reportId = generateId();
    const report = {
      id: reportId,
      reporterId: req.userId,
      reportedUserId,
      reportedMessageId,
      reason: sanitizeInput(reason),
      description: sanitizeInput(description || ''),
      severity: severity || 'medium',
      timestamp: new Date(),
      status: 'pending'
    };
    
    reports.set(reportId, report);
    
    if (severity === 'critical') {
      const reportedAccount = accounts.get(reportedUserId);
      if (reportedAccount) {
        reportedAccount.suspended = true;
        dataManager.setAccount(reportedUserId, reportedAccount);
        
        const userSocket = Array.from(connectedUsers.entries())
          .find(([socketId, user]) => user.id === reportedUserId);
        if (userSocket) {
          io.to(userSocket[0]).emit('account_suspended', {
            reason: 'Account temporarily suspended pending review',
            contactEmail: process.env.SUPPORT_EMAIL || 'support@studysync.app'
          });
          io.sockets.sockets.get(userSocket[0])?.disconnect();
        }
      }
      
      console.log(`🚨 CRITICAL REPORT: User ${reportedUserId} reported for ${reason}`);
    }
    
    console.log(`[${new Date().toISOString()}] Report submitted: ${reportId} - ${reason}`);
    
    res.json({ success: true, reportId });
  } catch (error) {
    console.error('Error submitting report:', error);
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

// Additional protected routes...
app.get('/api/friends', authenticateToken, (req, res) => {
  try {
    const userFriends = getUserFriends(req.userId);
    
    // Get pending friend requests TO this user
    const incomingRequests = Array.from(friendRequests.values()).filter(request => 
      request.toUserId === req.userId && request.status === 'pending'
    ).map(request => {
      const fromAccount = accounts.get(request.fromUserId);
      return {
        id: request.id,
        username: fromAccount?.username || 'Unknown',
        fromUserId: request.fromUserId,
        timestamp: request.timestamp
      };
    });

    // Get pending friend requests FROM this user
    const outgoingRequests = Array.from(friendRequests.values()).filter(request => 
      request.fromUserId === req.userId && request.status === 'pending'
    ).map(request => {
      const toAccount = accounts.get(request.toUserId);
      return {
        id: request.id,
        username: toAccount?.username || 'Unknown',
        toUserId: request.toUserId,
        timestamp: request.timestamp
      };
    });
    
    res.json({ 
      friends: userFriends,
      incomingRequests: incomingRequests,
      outgoingRequests: outgoingRequests,
      stats: {
        totalFriends: userFriends.length,
        pendingIncoming: incomingRequests.length,
        pendingOutgoing: outgoingRequests.length
      }
    });
  } catch (error) {
    console.error('Error loading friends:', error);
    res.status(500).json({ error: 'Failed to load friends' });
  }
});

app.get('/api/notifications', authenticateToken, (req, res) => {
  try {
    const userNotifications = notifications.get(req.userId) || [];
    
    res.json({ 
      notifications: userNotifications
    });
  } catch (error) {
    console.error('Error loading notifications:', error);
    res.status(500).json({ error: 'Failed to load notifications' });
  }
});

app.get('/api/chats', authenticateToken, (req, res) => {
  try {
    const userPrivateChats = [];
    privateChats.forEach((participants, chatKey) => {
      if (participants.includes(req.userId)) {
        const [chatType, chatId] = chatKey.split('_', 2);
        const otherUserId = participants.find(id => id !== req.userId);
        const otherAccount = accounts.get(otherUserId);
        
        if (otherAccount) {
          userPrivateChats.push({
            type: 'private',
            id: chatId,
            name: otherAccount.username,
            description: 'Private study session'
          });
        }
      }
    });

    const userGroups = Array.from(groups.values()).filter(group => 
      group.members.includes(req.userId)
    ).map(group => ({
      type: 'group',
      id: group.id,
      name: group.name,
      description: group.description,
      members: group.members.length
    }));
    
    res.json({
      privateChats: userPrivateChats,
      groups: userGroups
    });
  } catch (error) {
    console.error('Error loading chats:', error);
    res.status(500).json({ error: 'Failed to load chats' });
  }
});
app.delete('/api/unfriend/:friendId', authenticateToken, async (req, res) => {
  try {
    const { friendId } = req.params;
    
    if (!accounts.has(friendId)) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userFriends = friendships.get(req.userId) || new Set();
    if (!userFriends.has(friendId)) {
      return res.status(400).json({ error: 'Not friends with this user' });
    }

    // Remove friendship
    userFriends.delete(friendId);
    friendships.set(req.userId, userFriends);
    
    const friendFriends = friendships.get(friendId) || new Set();
    friendFriends.delete(req.userId);
    friendships.set(friendId, friendFriends);

    // Get private chat info before removing
    const privateChatId = getPrivateChatId(req.userId, friendId);
    const chatKey = `private_${privateChatId}`;
    
    // Remove private chat
    privateChats.delete(chatKey);
    messages.delete(chatKey);

    const friendAccount = accounts.get(friendId);
    
    console.log(`[${new Date().toISOString()}] Unfriended: ${req.user.username} removed ${friendAccount?.username || friendId}`);
    
    res.json({ 
      success: true, 
      message: 'Friend removed successfully',
      chatId: privateChatId
    });
  } catch (error) {
    console.error('Error unfriending:', error);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});
app.delete('/api/friend-request/:requestId/cancel', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    
    const request = friendRequests.get(requestId);
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.fromUserId !== req.userId) {
      return res.status(403).json({ error: 'Can only cancel your own friend requests' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Can only cancel pending requests' });
    }

    // Update request status
    request.status = 'cancelled';
    request.cancelledAt = new Date();
    friendRequests.set(requestId, request);

    // Remove notification from target user
    const targetNotifications = notifications.get(request.toUserId) || [];
    const filteredNotifications = targetNotifications.filter(notif => notif.id !== requestId);
    notifications.set(request.toUserId, filteredNotifications);

    const targetAccount = accounts.get(request.toUserId);
    console.log(`[${new Date().toISOString()}] Friend request cancelled: ${req.user.username} -> ${targetAccount?.username || request.toUserId}`);
    
    res.json({ 
      success: true,
      message: 'Friend request cancelled'
    });
  } catch (error) {
    console.error('Error cancelling friend request:', error);
    res.status(500).json({ error: 'Failed to cancel friend request' });
  }
});
app.get('/api/friend-request-status/:userId', authenticateToken, (req, res) => {
  try {
    const { userId } = req.params;
    
    if (!accounts.has(userId)) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if already friends
    const userFriends = friendships.get(req.userId) || new Set();
    if (userFriends.has(userId)) {
      return res.json({ status: 'friends' });
    }

    // Check for pending request
    const pendingRequest = Array.from(friendRequests.values()).find(request => 
      request.status === 'pending' && (
        (request.fromUserId === req.userId && request.toUserId === userId) ||
        (request.fromUserId === userId && request.toUserId === req.userId)
      )
    );

    if (pendingRequest) {
      if (pendingRequest.fromUserId === req.userId) {
        return res.json({ 
          status: 'request_sent',
          requestId: pendingRequest.id,
          timestamp: pendingRequest.timestamp
        });
      } else {
        return res.json({ 
          status: 'request_received',
          requestId: pendingRequest.id,
          timestamp: pendingRequest.timestamp
        });
      }
    }

    res.json({ status: 'none' });
  } catch (error) {
    console.error('Error getting friend request status:', error);
    res.status(500).json({ error: 'Failed to get friend request status' });
  }
});
app.get('/api/search-users', authenticateToken, (req, res) => {
  try {
    const query = req.query.q?.toLowerCase() || '';
    
    if (query.length < 2) {
      return res.json({ users: [] });
    }

    if (query.length > 50) {
      return res.status(400).json({ error: 'Search query too long' });
    }

    const userFriends = friendships.get(req.userId) || new Set();
    const userBlocked = userBlocks.get(req.userId) || new Set();
    
    // Get pending requests to avoid showing users we already sent requests to
    const pendingRequests = new Set();
    friendRequests.forEach(request => {
      if (request.fromUserId === req.userId && request.status === 'pending') {
        pendingRequests.add(request.toUserId);
      }
    });
    
    const searchResults = Array.from(accounts.values())
      .filter(account => {
        // Exclude self, suspended accounts, friends, blocked users, and users with pending requests
        return account.id !== req.userId &&
               !account.suspended &&
               !userFriends.has(account.id) &&
               !userBlocked.has(account.id) &&
               !pendingRequests.has(account.id) &&
               account.username.toLowerCase().includes(query);
      })
      .slice(0, 10) // Limit to 10 results
      .map(account => ({
        id: account.id,
        username: account.username,
        status: isUserOnline(account.id) ? 'online' : 'offline',
        joinedDate: account.createdAt.toISOString().split('T')[0] // Just the date part
      }))
      .sort((a, b) => {
        // Sort by online status first, then alphabetically
        if (a.status === 'online' && b.status === 'offline') return -1;
        if (a.status === 'offline' && b.status === 'online') return 1;
        return a.username.localeCompare(b.username);
      });
    
    res.json({ 
      users: searchResults,
      query: query,
      totalFound: searchResults.length
    });
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});

// Connection rate limiting by IP
let connectionRateLimits = new Map(); // Map of IP -> { connections, lastReset }

function checkConnectionRateLimit(ip, limit = 10, windowMs = 300000) { // 10 connections per 5 minutes
  const now = Date.now();
  const ipLimit = connectionRateLimits.get(ip);
  
  if (!ipLimit) {
    connectionRateLimits.set(ip, { connections: 1, lastReset: now });
    return true;
  }
  
  // Reset counter if window has passed
  if (now - ipLimit.lastReset > windowMs) {
    connectionRateLimits.set(ip, { connections: 1, lastReset: now });
    return true;
  }
  
  // Check if limit exceeded
  if (ipLimit.connections >= limit) {
    return false;
  }
  
  // Increment counter
  ipLimit.connections++;
  connectionRateLimits.set(ip, ipLimit);
  return true;
}

// Clean up old connection rate limit entries
setInterval(() => {
  const now = Date.now();
  const windowMs = 300000; // 5 minutes
  
  for (const [ip, limit] of connectionRateLimits.entries()) {
    if (now - limit.lastReset > windowMs * 2) { // Keep for 2 windows
      connectionRateLimits.delete(ip);
    }
  }
}, 600000); // Clean up every 10 minutes

// Socket.io connection handling with improved authentication
io.on('connection', (socket) => {
  const clientIP = socket.handshake.address || socket.conn.remoteAddress || 'unknown';
  
  // Check connection rate limit
  if (!checkConnectionRateLimit(clientIP, 15, 300000)) { // 15 connections per 5 minutes per IP
    console.log(`[${new Date().toISOString()}] Connection rate limit exceeded for IP: ${clientIP}`);
    socket.emit('rate_limit_exceeded', 'Too many connections from your IP address. Please try again later.');
    socket.disconnect(true);
    return;
  }
  
  console.log(`[${new Date().toISOString()}] Socket connected: ${socket.id} from ${clientIP}`);

  socket.on('authenticate', (token) => {
    const decoded = verifyJWT(token);
    if (!decoded) {
      socket.emit('auth_error', 'Invalid authentication token');
      socket.disconnect();
      return;
    }

    const account = accounts.get(decoded.userId);
    if (!account || account.suspended) {
      socket.emit('auth_error', account?.suspended ? 'Account suspended' : 'Account not found');
      socket.disconnect();
      return;
    }

    socket.userId = account.id;
    socket.username = account.username;
    socket.joinTime = new Date();
    
    const user = {
      id: account.id,
      username: account.username,
      email: account.email,
      joinedAt: new Date(),
      lastActive: new Date(),
      role: 'student'
    };
    users.set(account.id, user);
    
    connectedUsers.set(socket.id, {
      id: account.id,
      username: account.username,
      socketId: socket.id,
      joinTime: socket.joinTime
    });

    // Join default room
    socket.join('public_general');

    // Join private chat rooms
    privateChats.forEach((participants, chatKey) => {
      if (participants.includes(account.id)) {
        socket.join(chatKey);
      }
    });

    // Join group rooms
    groups.forEach((group, groupId) => {
      if (group.members.includes(account.id)) {
        socket.join(`group_${groupId}`);
      }
    });

    console.log(`[${new Date().toISOString()}] ${account.username} authenticated successfully`);
    
    const timeCheck = checkUsageTime();
    if (timeCheck.isSchoolHours) {
      socket.emit('usage_warning', { message: timeCheck.warning });
    }
    
    socket.emit('authenticated');
  });

  socket.on('send_message', async (data) => {
    if (!socket.userId) {
      socket.emit('error', 'Not authenticated');
      return;
    }

    // Apply Socket.io specific rate limiting
    if (!checkSocketRateLimit(socket.id, 30, 60000)) { // 30 messages per minute
      socket.emit('message_error', 'Too many messages, please slow down.');
      console.log(`[${new Date().toISOString()}] Rate limit exceeded for ${socket.username}`);
      return;
    }

    try {
      const { text, chatType, chatId } = data;

      const validation = validateMessage(text);
      if (!validation.valid) {
        socket.emit('message_error', validation.error);
        
        if (validation.flagged) {
          console.log(`⚠️ FLAGGED MESSAGE from ${socket.username}: ${text} (Pattern: ${validation.pattern})`);
        }
        return;
      }

      if (!canUserAccessChat(socket.userId, chatType, chatId)) {
        socket.emit('error', 'Access denied to this chat');
        return;
      }

      const user = users.get(socket.userId);
      if (!user) {
        socket.emit('error', 'User not found');
        return;
      }

      const message = {
        id: generateId(),
        username: user.username,
        text: validation.text,
        timestamp: new Date(),
        userId: user.id,
        chatType,
        chatId,
        messageType: 'text'
      };

      const chatKey = getChatKey(chatType, chatId);
      const chatMessages = messages.get(chatKey) || [];
      chatMessages.push(message);
      
      // Keep only last 1000 messages per chat
      if (chatMessages.length > 1000) {
        chatMessages.splice(0, chatMessages.length - 1000);
      }
      
      messages.set(chatKey, chatMessages);
      user.lastActive = new Date();

      const room = chatKey;
      const sockets = await io.in(room).fetchSockets();
      
      sockets.forEach(targetSocket => {
        if (targetSocket.userId) {
          const blockedUsers = userBlocks.get(targetSocket.userId) || new Set();
          if (!blockedUsers.has(message.userId)) {
            targetSocket.emit('new_message', message);
          }
        }
      });
      
      console.log(`[${new Date().toISOString()}] Message in ${chatType}/${chatId} from ${user.username}: ${message.text.substring(0, 50)}${message.text.length > 50 ? '...' : ''}`);
    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', 'Failed to send message');
    }
  });

  socket.on('typing', (data) => {
    if (!socket.userId) return;
    
    // Light rate limiting for typing events (60 per minute)
    if (!checkSocketRateLimit(socket.id + '_typing', 60, 60000)) {
      return; // Silently ignore excessive typing events
    }
    
    try {
      const { isTyping, chatType, chatId } = data;
      const room = getChatKey(chatType, chatId);
      
      socket.to(room).emit('user_typing', {
        username: socket.username,
        isTyping,
        chatType,
        chatId
      });
    } catch (error) {
      console.error('Error handling typing:', error);
    }
  });

  socket.on('join_chat', (data) => {
    if (!socket.userId) return;
    
    // Rate limit chat joins (30 per minute)
    if (!checkSocketRateLimit(socket.id + '_join', 30, 60000)) {
      socket.emit('error', 'Too many chat join requests');
      return;
    }
    
    try {
      const { chatType, chatId } = data;
      
      if (canUserAccessChat(socket.userId, chatType, chatId)) {
        const room = getChatKey(chatType, chatId);
        socket.join(room);
        console.log(`[${new Date().toISOString()}] ${socket.username} joined ${room}`);
      } else {
        socket.emit('error', 'Access denied to chat');
      }
    } catch (error) {
      console.error('Error joining chat:', error);
    }
  });

  socket.on('leave_chat', (data) => {
    if (!socket.userId) return;
    
    try {
      const { chatType, chatId } = data;
      const room = getChatKey(chatType, chatId);
      socket.leave(room);
      console.log(`[${new Date().toISOString()}] ${socket.username} left ${room}`);
    } catch (error) {
      console.error('Error leaving chat:', error);
    }
  });

  socket.on('ping', () => {
    if (socket.userId) {
      const user = users.get(socket.userId);
      if (user) {
        user.lastActive = new Date();
      }
      socket.emit('pong');
    }
  });

  socket.on('disconnect', (reason) => {
    if (socket.username) {
      connectedUsers.delete(socket.id);
      
      // Clean up rate limiting data
      socketRateLimits.delete(socket.id);
      
      const sessionDuration = socket.joinTime ? 
        Math.round((new Date() - socket.joinTime) / 1000) : 0;
      
      console.log(`[${new Date().toISOString()}] ${socket.username} disconnected (${reason}) - Session duration: ${sessionDuration}s`);
    }
  });

  socket.on('error', (error) => {
    console.error(`[${new Date().toISOString()}] Socket error for ${socket.username || 'unknown'}:`, error);
  });
});

// Cleanup and maintenance
setInterval(() => {
  const now = new Date();
  const thirtyMinutesAgo = new Date(now.getTime() - 30 * 60 * 1000);
  
  // Clean up inactive users
  for (const [userId, user] of users.entries()) {
    if (user.lastActive < thirtyMinutesAgo) {
      const isConnected = Array.from(connectedUsers.values()).some(cu => cu.id === userId);
      if (!isConnected) {
        users.delete(userId);
        console.log(`[${new Date().toISOString()}] Cleaned up inactive user session: ${user.username}`);
      }
    }
  }
  
  // Clean up old notifications (keep only last 30 days)
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  for (const [userId, userNotifications] of notifications.entries()) {
    const filtered = userNotifications.filter(notif => new Date(notif.timestamp) > thirtyDaysAgo);
    if (filtered.length !== userNotifications.length) {
      notifications.set(userId, filtered);
    }
  }
}, 30 * 60 * 1000); // Run every 30 minutes

// Data persistence interval
setInterval(async () => {
  try {
    await dataManager.backupData({
      messages: Object.fromEntries(messages),
      friendships: Object.fromEntries(Array.from(friendships.entries()).map(([k, v]) => [k, Array.from(v)])),
      groups: Object.fromEntries(groups),
      privateChats: Object.fromEntries(privateChats),
      notifications: Object.fromEntries(notifications),
      reports: Object.fromEntries(reports),
      userBlocks: Object.fromEntries(Array.from(userBlocks.entries()).map(([k, v]) => [k, Array.from(v)]))
    });
    console.log(`[${new Date().toISOString()}] Data backup completed`);
  } catch (error) {
    console.error('Error during data backup:', error);
  }
}, 5 * 60 * 1000); // Backup every 5 minutes

// Health check
app.get('/health', (req, res) => {
  const memUsage = process.memoryUsage();
  res.json({
    status: emergencyShutdown ? 'maintenance' : 'healthy',
    timestamp: new Date().toISOString(),
    activeConnections: connectedUsers.size,
    totalAccounts: accounts.size,
    activeSessions: users.size,
    totalMessages: Array.from(messages.values()).reduce((sum, msgs) => sum + msgs.length, 0),
    totalReports: reports.size,
    pendingReports: Array.from(reports.values()).filter(r => r.status === 'pending').length,
    totalGroups: groups.size,
    totalFriendships: Array.from(friendships.values()).reduce((sum, friends) => sum + friends.size, 0) / 2,
    uptime: process.uptime(),
    memory: {
      used: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
    }
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Server error:`, {
    error: err.message,
    stack: err.stack,
    user: req.userId,
    ip: req.ip,
    url: req.url
  });
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        await dataManager.init();
        accounts = dataManager.accounts;
        
        // Load additional data if exists
        const additionalData = await dataManager.loadAdditionalData();
        if (additionalData) {
          if (additionalData.messages) {
            messages = new Map(Object.entries(additionalData.messages));
          }
          if (additionalData.friendships) {
            friendships = new Map(Object.entries(additionalData.friendships).map(([k, v]) => [k, new Set(v)]));
          }
          if (additionalData.groups) {
            groups = new Map(Object.entries(additionalData.groups));
          }
          if (additionalData.privateChats) {
            privateChats = new Map(Object.entries(additionalData.privateChats));
          }
          if (additionalData.notifications) {
            notifications = new Map(Object.entries(additionalData.notifications));
          }
          if (additionalData.reports) {
            reports = new Map(Object.entries(additionalData.reports));
          }
          if (additionalData.userBlocks) {
            userBlocks = new Map(Object.entries(additionalData.userBlocks).map(([k, v]) => [k, new Set(v)]));
          }
        }

        server.listen(PORT, () => {
            console.log(`[${new Date().toISOString()}] StudySync Platform running on port ${PORT}`);
            console.log(`[${new Date().toISOString()}] Access the platform at http://localhost:${PORT}`);
            console.log(`[${new Date().toISOString()}] Health check available at http://localhost:${PORT}/health`);
            console.log(`[${new Date().toISOString()}] Terms of Service at http://localhost:${PORT}/terms`);
            console.log(`[${new Date().toISOString()}] Privacy Policy at http://localhost:${PORT}/privacy`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();

// Process error handlers
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  
  // Try to save data before exiting
  dataManager.saveAccounts().catch(console.error);
  
  setTimeout(() => {
    process.exit(1);
  }, 5000);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit on unhandled rejections, just log them
});

process.on('SIGINT', async () => {
    console.log('\n[SHUTDOWN] Received SIGINT. Closing server gracefully...');
    
    try {
      // Save all data
      await dataManager.saveAccounts();
      await dataManager.backupData({
        messages: Object.fromEntries(messages),
        friendships: Object.fromEntries(Array.from(friendships.entries()).map(([k, v]) => [k, Array.from(v)])),
        groups: Object.fromEntries(groups),
        privateChats: Object.fromEntries(privateChats),
        notifications: Object.fromEntries(notifications),
        reports: Object.fromEntries(reports),
        userBlocks: Object.fromEntries(Array.from(userBlocks.entries()).map(([k, v]) => [k, Array.from(v)]))
      });
      
      console.log('[SHUTDOWN] Data saved successfully');
    } catch (error) {
      console.error('[SHUTDOWN] Error saving data:', error);
    }
    
    io.emit('system_shutdown', {
      message: 'Server shutting down for maintenance...',
      reason: 'Scheduled maintenance',
      timestamp: new Date()
    });
    
    server.close(() => {
        console.log('[SHUTDOWN] Server closed successfully');
        process.exit(0);
    });
});

process.on('SIGTERM', async () => {
    console.log('\n[SHUTDOWN] Received SIGTERM. Closing server gracefully...');
    
    try {
      await dataManager.saveAccounts();
      console.log('[SHUTDOWN] Data saved successfully');
    } catch (error) {
      console.error('[SHUTDOWN] Error saving data:', error);
    }
    
    server.close(() => {
        console.log('[SHUTDOWN] Server closed successfully');
        process.exit(0);
    });
});

module.exports = { app, server, io };