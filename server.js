require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const https = require('https');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
const allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'null'
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Cloudinary Configuration
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET
});

// Multer Configuration
const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'image/jpeg', 'image/png', 'image/gif',
        'application/pdf',
        'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only images, PDFs, PPT allowed (DOCX not allowed).'), false);
    }
};
const upload = multer({ storage, fileFilter });

// MongoDB Connection
const mongoURI = process.env.MONGO_URI || 'mongodb+srv://nandha_user:balasanjeevswathi@nandhanotes.8aqd2bz.mongodb.net/nandha_notes?retryWrites=true&w=majority';
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err.message));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    credits: { type: Number, default: 0 },
    uploadCount: { type: Number, default: 0 }
});
const User = mongoose.model('User', userSchema);

// Note Schema
const noteSchema = new mongoose.Schema({
    regulation: String,
    year: String,
    topic: String,
    subject: String,
    subjectCode: String,
    description: String,
    public_id: String,
    url: String,
    originalName: String,
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    uploadDate: { type: Date, default: Date.now },
    channelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel' }
});
const Note = mongoose.model('Note', noteSchema);

// Channel Schema
const channelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    code: { type: String, required: true, unique: true, length: 10 },
    admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model('Channel', channelSchema);

// Verify Token Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        console.error('No token provided in request', { headers: req.headers });
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
        req.user = decoded;
        console.log('Token verified:', { userId: decoded.userId, email: decoded.email });
        next();
    } catch (err) {
        console.error('Token verification error:', err.message);
        return res.status(401).json({ error: 'Invalid or expired token', details: err.message });
    }
};

// Generate unique 10-digit code
const generateChannelCode = () => crypto.randomBytes(5).toString('hex');

// Routes
app.get('/', (req, res) => {
    if (req.headers.accept?.includes('application/json')) {
        return res.status(404).json({ error: 'Not found' });
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Sign-up Endpoint
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;
    console.log('Signup request:', { username, email });
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (!/^[a-zA-Z0-9._%+-]+@nandhaengg\.org$/.test(email)) {
        return res.status(400).json({ error: 'Email must be a valid @nandhaengg.org address' });
    }
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword, credits: 0, uploadCount: 0 });
        await user.save();
        const token = jwt.sign({ email, userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret_key', { expiresIn: '1h' });
        res.json({ token, message: 'Sign-up successful' });
    } catch (err) {
        console.error('Signup error:', err.message);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log('Login request:', { email });
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        const token = jwt.sign({ email, userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret_key', { expiresIn: '1h' });
        res.json({ token, message: 'Login successful', email: user.email });
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    console.log('Reset password request:', { email });
    if (!email || !newPassword) {
        return res.status(400).json({ error: 'Email and new password are required' });
    }
    if (!/^[a-zA-Z0-9._%+-]+@nandhaengg\.org$/.test(email)) {
        return res.status(400).json({ error: 'Email must be a valid @nandhaengg.org address' });
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        console.log('Password reset successful for:', { email });
        res.json({ message: 'Password reset successful' });
    } catch (err) {
        console.error('Reset password error:', err.message);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Profile Endpoint
app.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.user.email }, 'username email credits uploadCount');
        console.log('Profile request for:', req.user.email);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ username: user.username, email: user.email, credits: user.credits, uploadCount: user.uploadCount });
    } catch (err) {
        console.error('Profile error:', err.message);
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Upload File
app.post('/api/upload', verifyToken, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file selected' });
    }
    try {
        let resourceType = "raw";
        if (req.file.mimetype.startsWith("image/")) {
            resourceType = "image";
        }
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: "nandha-notes",
                resource_type: resourceType,
                use_filename: true,
                unique_filename: false
            },
            async (error, result) => {
                if (error) {
                    console.error("Cloudinary upload error:", error);
                    if (!res.headersSent) {
                        return res.status(500).json({ error: "Upload failed", details: error.message });
                    }
                    return;
                }
                try {
                    const note = new Note({
                        regulation: req.body.regulation,
                        year: req.body.year,
                        topic: req.body.topic,
                        subject: req.body.subject,
                        subjectCode: req.body.subjectCode,
                        description: req.body.description,
                        public_id: result.public_id,
                        url: result.secure_url,
                        originalName: req.file.originalname,
                        uploadedBy: req.user.userId,
                        channelId: req.body.channelId || null
                    });
                    await note.save();
                    const user = await User.findById(req.user.userId);
                    user.uploadCount = (user.uploadCount || 0) + 1;
                    user.credits = user.uploadCount * 10;
                    await user.save();
                    if (!res.headersSent) {
                        res.json({
                            message: "Upload successful",
                            url: result.secure_url,
                            uploadCount: user.uploadCount,
                            credits: user.credits
                        });
                    }
                } catch (err) {
                    console.error("MongoDB save error:", err);
                    if (!res.headersSent) {
                        res.status(500).json({ error: "Failed to save note metadata", details: err.message });
                    }
                }
            }
        );
        uploadStream.end(req.file.buffer);
    } catch (err) {
        console.error("Upload error:", err);
        if (!res.headersSent) {
            res.status(500).json({ error: "Upload failed", details: err.message });
        }
    }
});

// Create Channel
app.post('/api/channels/create', verifyToken, async (req, res) => {
    try {
        const { name } = req.body;
        const userId = req.user.userId;
        if (!name) return res.status(400).json({ error: 'Channel name is required' });
        let code, isUnique = false;
        while (!isUnique) {
            code = generateChannelCode();
            const existingChannel = await Channel.findOne({ code });
            if (!existingChannel) isUnique = true;
        }
        const channel = new Channel({ name, code, admin: userId, users: [userId] });
        await channel.save();
        res.status(201).json({ message: 'Channel created', channel: { _id: channel._id, name, code } });
    } catch (error) {
        res.status(500).json({ error: 'Error creating channel', details: error.message });
    }
});

// Join Channel
app.post('/api/channels/join', verifyToken, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.user.userId;
        const channel = await Channel.findOne({ code });
        if (!channel) return res.status(404).json({ error: 'Invalid channel code' });
        if (channel.users.some(id => id.toString() === userId)) {
            return res.status(400).json({ error: 'User already in channel' });
        }
        channel.users.push(userId);
        await channel.save();
        res.status(200).json({ message: 'Joined channel', channel: { _id: channel._id, name: channel.name, code: channel.code } });
    } catch (error) {
        res.status(500).json({ error: 'Error joining channel', details: error.message });
    }
});

// Share Channel Code
app.get('/api/channels/:id/share', verifyToken, async (req, res) => {
    try {
        const channel = await Channel.findById(req.params.id);
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        if (!channel.users.some(id => id.toString() === req.user.userId)) {
            return res.status(403).json({ error: 'User not in channel' });
        }
        res.status(200).json({ code: channel.code });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching channel code', details: error.message });
    }
});

// Add User to Channel
app.post('/api/channels/:id/add-user', verifyToken, async (req, res) => {
    try {
        const { email } = req.body;
        const channelId = req.params.id;
        const channel = await Channel.findById(channelId);
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        if (channel.admin.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Only admin can add users' });
        }
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found in database' });
        if (channel.users.includes(user._id)) {
            return res.status(400).json({ error: 'User already in channel' });
        }
        channel.users.push(user._id);
        await channel.save();
        res.status(200).json({ message: 'User added to channel', user: { username: user.username, email: user.email } });
    } catch (error) {
        res.status(500).json({ error: 'Error adding user', details: error.message });
    }
});

// View Channel Users
app.get('/api/channels/:id/users', verifyToken, async (req, res) => {
    try {
        const channelId = req.params.id;
        const userId = req.user.userId;
        const channel = await Channel.findById(channelId).populate('users', 'username email credits');
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        if (!channel.users.some(user => user._id.toString() === userId)) {
            return res.status(403).json({ error: 'User not in channel' });
        }
        const users = channel.users.map(user => ({
            _id: user._id.toString(),
            username: user.username || 'Unknown',
            email: user.email || 'No email',
            credits: user.credits || 0,
            isAdmin: channel.admin.toString() === user._id.toString()
        }));
        res.status(200).json({ users });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching users', details: error.message });
    }
});

// View User Profile
app.get('/api/users/:id/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id, 'username email credits uploadCount');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.status(200).json({ username: user.username, email: user.email, credits: user.credits, uploadCount: user.uploadCount });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching profile', details: error.message });
    }
});

// Kick User
app.post('/api/channels/:id/kick-user', verifyToken, async (req, res) => {
    try {
        const { userId } = req.body;
        const channel = await Channel.findById(req.params.id);
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        if (channel.admin.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Only admin can kick users' });
        }
        if (channel.admin.toString() === userId) {
            return res.status(400).json({ error: 'Cannot kick the admin' });
        }
        channel.users = channel.users.filter(id => id.toString() !== userId);
        await channel.save();
        res.status(200).json({ message: 'User kicked from channel' });
    } catch (error) {
        res.status(500).json({ error: 'Error kicking user', details: error.message });
    }
});

// Get User's Channels
app.get('/api/channels', verifyToken, async (req, res) => {
    try {
        const channels = await Channel.find({ users: req.user.userId }, 'name code');
        res.status(200).json({ channels });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching channels', details: error.message });
    }
});

// Get Channel Documents
app.get('/api/channels/:id/documents', verifyToken, async (req, res) => {
    try {
        const channelId = req.params.id;
        const userId = req.user.userId;
        const channel = await Channel.findById(channelId);
        if (!channel) return res.status(404).json({ error: 'Channel not found' });
        if (!channel.users.some(id => id.toString() === userId)) {
            return res.status(403).json({ error: 'User not in channel' });
        }
        const documents = await Note.find({ channelId })
            .populate('uploadedBy', 'username _id') // Include _id in populate
            .select('topic subject subjectCode regulation url uploadDate originalName');
        res.status(200).json({
            documents: documents.map(doc => ({
                _id: doc._id,
                topic: doc.topic,
                subject: doc.subject,
                subjectCode: doc.subjectCode,
                regulation: doc.regulation,
                fileUrl: doc.url,
                username: doc.uploadedBy?.username || 'Unknown',
                userId: doc.uploadedBy?._id?.toString() || null, // Include userId
                uploadDate: doc.uploadDate,
                originalName: doc.originalName
            }))
        });
    } catch (error) {
        console.error('Error fetching documents:', error.message);
        res.status(500).json({ error: 'Error fetching documents', details: error.message });
    }
});

// Get Global Notes (channelId: null)
app.get('/api/notes', verifyToken, async (req, res) => {
    try {
        const notes = await Note.find({ channelId: null })
            .populate('uploadedBy', 'username _id') // Include _id in populate
            .select('topic subject subjectCode regulation url uploadDate originalName');
        res.status(200).json({
            documents: notes.map(doc => ({
                _id: doc._id,
                topic: doc.topic,
                subject: doc.subject,
                subjectCode: doc.subjectCode,
                regulation: doc.regulation,
                fileUrl: doc.url,
                username: doc.uploadedBy?.username || 'Unknown',
                userId: doc.uploadedBy?._id?.toString() || null, // Include userId
                uploadDate: doc.uploadDate,
                originalName: doc.originalName
            }))
        });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching notes', details: error.message });
    }
});

// Search Endpoint
app.get('/api/search', verifyToken, async (req, res) => {
    try {
        const { query, channelId } = req.query;
        if (!query) {
            return res.status(400).json({ error: 'Search query is required' });
        }
        const searchConditions = {
            $or: [
                { topic: { $regex: query, $options: 'i' } },
                { subject: { $regex: query, $options: 'i' } },
                { subjectCode: { $regex: query, $options: 'i' } },
                { description: { $regex: query, $options: 'i' } }
            ]
        };
        if (channelId) {
            searchConditions.channelId = channelId;
        } else {
            searchConditions.channelId = null;
        }
        const notes = await Note.find(searchConditions)
            .populate('uploadedBy', 'username _id') // Include _id in populate
            .select('topic subject subjectCode regulation url uploadDate originalName');
        res.status(200).json({
            documents: notes.map(doc => ({
                _id: doc._id,
                topic: doc.topic,
                subject: doc.subject,
                subjectCode: doc.subjectCode,
                regulation: doc.regulation,
                fileUrl: doc.url,
                username: doc.uploadedBy?.username || 'Unknown',
                userId: doc.uploadedBy?._id?.toString() || null, // Include userId
                uploadDate: doc.uploadDate,
                originalName: doc.originalName
            }))
        });
    } catch (error) {
        console.error('Search error:', error.message);
        res.status(500).json({ error: 'Error searching documents', details: error.message });
    }
});

// Proxy download/preview route
app.get("/api/file/:id", async (req, res) => {
    try {
        const note = await Note.findById(req.params.id);
        if (!note) return res.status(404).json({ error: "File not found" });

        const filename = note.originalName || "download.pdf";
        const ext = filename.split(".").pop().toLowerCase();

        let contentType = "application/octet-stream";
        if (ext === "pdf") contentType = "application/pdf";
        if (["jpg", "jpeg"].includes(ext)) contentType = "image/jpeg";
        if (ext === "png") contentType = "image/png";
        if (ext === "gif") contentType = "image/gif";
        if (ext === "ppt") contentType = "application/vnd.ms-powerpoint";
        if (ext === "pptx") contentType = "application/vnd.openxmlformats-officedocument.presentationml.presentation";

        res.setHeader("Content-Type", contentType);
        res.setHeader("Access-Control-Expose-Headers", "Content-Disposition");

        // Always set Content-Disposition to inline for preview to ensure viewing in browser
        res.setHeader("Content-Disposition", `inline; filename="${filename}"`);

        // Stream the file for all cases (preview or download)
        https.get(note.url, (fileRes) => {
            res.setHeader("Content-Length", fileRes.headers["content-length"]);
            fileRes.pipe(res);
        }).on("error", (err) => {
            console.error("File stream error:", err);
            res.status(500).json({ error: "Failed to stream file" });
        });
    } catch (err) {
        console.error("File fetch error:", err.message);
        res.status(500).json({ error: "Server error", details: err.message });
    }
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});