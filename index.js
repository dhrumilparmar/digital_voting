require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const nodemailer = require('nodemailer');
const PORT = process.env.PORT || 8080;
const app = express();

// Middleware
app.use(bodyParser.json());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log("Connected to MongoDB");
    }).catch(() => {
        console.log("Failed to connect to MongoDB");
    });

const RESULT_RELEASE_DATE = new Date(process.env.RESULT_RELEASE_DATE); 


// nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    }
});



// User Schema for signup
const signupSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
        unique: true
    },
    votedCandidates: { type: String },
    hasVoted: { type: Boolean, default: false },
    
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpiry: Date
});

const User = mongoose.model("User", signupSchema);

//  User Schema for audit logging
const auditSchema = new mongoose.Schema({
    action: {
        type: String,
        required: true,
        enum: ['LOGIN', 'SIGNUP', 'VOTE', 'PROFILE_UPDATE', 'VIEW_RESULTS']
    },
    username: String,
    details: mongoose.Schema.Types.Mixed,
    ipAddress: String,
    userAgent: String,
    timestamp: {
        type: Date,
        default: Date.now
    }
});

const Audit = mongoose.model('Audit', auditSchema);

// audit logging function
async function createAuditLog(action, username, details, req) {
    try {
        await Audit.create({
            action,
            username,
            details,
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
        });
    } catch (error) {
        console.error('Error creating audit log:', error);
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//signup route
app.post('/index', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const newUser = new User({ username, email, password });
        await newUser.save();
        
        //  audit log
        await createAuditLog('SIGNUP', username, { email }, req);
        
        res.status(201).json({ message: 'User created successfully!' });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }
        res.status(500).json({ message: 'Error creating user', error });
    }
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
    const { username, password, otp } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            await createAuditLog('LOGIN', username, { status: 'failed', error: 'User not found' }, req);
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.password !== password) {
            await createAuditLog('LOGIN', username, { status: 'failed', error: 'Invalid password' }, req);
            return res.status(401).json({ message: 'Invalid password' });
        }

        // If OTP is provided, verify it
        if (otp) {
            if (!user.otp || user.otp !== otp) {
                await createAuditLog('LOGIN', username, { status: 'failed', error: 'Invalid OTP' }, req);
                return res.status(401).json({ message: 'Invalid OTP' });
            }

            if (user.otpExpiry < new Date()) {
                await createAuditLog('LOGIN', username, { status: 'failed', error: 'OTP has expired' }, req);
                return res.status(401).json({ message: 'OTP has expired' });
            }

            // Clear OTP after successful verification
            user.otp = null;
            user.otpExpiry = null;
            await user.save();

            await createAuditLog('LOGIN', username, { status: 'success', usedOTP: true }, req);

            return res.status(200).json({
                message: 'Login successful',
                user: {
                    username: user.username,
                    hasVoted: user.hasVoted
                }
            });
        }

        // Generate and send OTP
        const newOTP = generateOTP();
        user.otp = newOTP;
        user.otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes expiry
        await user.save();

        await sendOTPEmail(user.email, newOTP);
        
        res.status(200).json({ 
            message: 'OTP sent to your email',
            requireOTP: true
        });

    } catch (error) {
        console.error('Error during login:', error);
        await createAuditLog('LOGIN', username, { status: 'failed', error: error.message }, req);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/voting', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'voting.html'));
});

app.get('/update', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'update.html'));
});

app.post('/update-profile', async (req, res) => {
    const { currentUsername, newUsername, newEmail, newPassword } = req.body;

    try {
        const user = await User.findOne({ username: currentUsername });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (currentUsername !== newUsername) {
            const existingUser = await User.findOne({ username: newUsername });
            if (existingUser) {
                return res.status(400).json({ message: 'New username is already taken' });
            }
        }

        user.username = newUsername;
        user.email = newEmail;
        user.password = newPassword;

        await user.save();
        await createAuditLog('PROFILE_UPDATE', currentUsername, { newUsername, newEmail }, req);
        res.status(200).json({ message: 'Profile updated successfully!' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Error updating profile' });
    }
});

app.post('/vote', async (req, res) => {
    const { username, candidateName } = req.body;

    try {
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(404).json({ status: false, message: 'User not found' });
        }

        if (user.hasVoted) {
            return res.status(400).json({ status: false, message: 'You have already voted' });
        }

        user.votedCandidates = candidateName;
        user.hasVoted = true;
        await user.save();
        await createAuditLog('VOTE', username, { candidateName, timestamp: new Date() }, req);

        res.status(200).json({ 
            status: true, 
            message: 'Vote cast successfully'
        });
    } catch (error) {
        console.error('Error updating vote:', error);
        res.status(500).json({ status: false, message: 'Error casting vote' });
    }
});

app.get('/result', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'result.html'));
});

app.get('/election-results', async (req, res) => {
    try {
        const currentDate = new Date();
        
        // Check if current date is before release date
        if (currentDate < RESULT_RELEASE_DATE) {
            return res.status(403).json({ 
                message: `Results will be declared on ${RESULT_RELEASE_DATE.toLocaleDateString()}`,
                isBeforeRelease: true
            });
        }

        // Continue with existing result calculation logic
        const totalVoters = await User.countDocuments();
        const results = await User.aggregate([
            { $match: { hasVoted: true }},
            { $group: { 
                _id: "$votedCandidates", 
                count: { $sum: 1 } 
            }},
            { $sort: { count: -1 }}
        ]);

        // Calculate total votes cast
        const totalVotes = results.reduce((sum, result) => sum + result.count, 0);

        // Determine winner
        const winner = results.length > 0 ? results[0]._id : 'No votes cast';
        const winningVotes = results.length > 0 ? results[0].count : 0;

        await createAuditLog('VIEW_RESULTS', null, { winner, totalVotes }, req);

        res.json({
            winner,
            totalVoters,
            totalVotes,
            winningVotes,
            results
        });
    } catch (error) {
        console.error('Error fetching results:', error);
        res.status(500).json({ message: 'Error fetching election results' });
    }
});
//  these routes for admin audit trail access
app.get('/admin/audit-logs', async (req, res) => {
    try {
        const logs = await Audit.find()
            .sort({ timestamp: -1 })
            .limit(100);
        
        res.json(logs);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching audit logs' });
    }
});

app.get('/admin/audit-logs/search', async (req, res) => {
    const { action, username, startDate, endDate } = req.query;
    
    const query = {};
    if (action) query.action = action;
    if (username) query.username = username;
    if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
    }

    try {
        const logs = await Audit.find(query)
            .sort({ timestamp: -1 })
            .limit(100);
        
        res.json(logs);
    } catch (error) {
        res.status(500).json({ message: 'Error searching audit logs' });
    }
});

// Function to generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to send OTP email
async function sendOTPEmail(email, otp) {
    const mailOptions = {
        from: 'keyar24650@decodewp.com',
        to: email,
        subject: 'Login OTP for Digital Voting System',
        html: `
            <h1>Your OTP for Digital Voting System</h1>
            <p>Your OTP is: <strong>${otp}</strong></p>
            <p>This OTP will expire in 5 minutes.</p>
        `
    };

    return transporter.sendMail(mailOptions);
}

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}`);
});