const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');
const flash = require('connect-flash');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Atlas Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));
app.use(flash());
app.use(helmet());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100 
});
app.use(limiter);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// User Schema & Model
const UserSchema = new mongoose.Schema({
    username: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, default: 'user' },
    resetToken: String,
    resetTokenExpiration: Date,
});
const User = mongoose.model('User', UserSchema);

// Password Reset Functionality
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { messages: req.flash('error') });
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        req.flash('error', 'No account found with that email');
        return res.redirect('/forgot-password');
    }
    
    const token = crypto.randomBytes(20).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 3600000; // 1 hour expiry
    await user.save();
    
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    
    const mailOptions = {
        to: user.email,
        from: process.env.EMAIL_USER,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: http://localhost:${PORT}/reset-password/${token}`,
    };
    
    await transporter.sendMail(mailOptions);
    req.flash('info', 'Password reset email sent');
    res.redirect('/login');
});

app.get('/reset-password/:token', async (req, res) => {
    const user = await User.findOne({
        resetToken: req.params.token,
        resetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
        req.flash('error', 'Invalid or expired token');
        return res.redirect('/forgot-password');
    }
    res.render('reset-password', { token: req.params.token });
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    const user = await User.findOne({
        resetToken: token,
        resetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
        req.flash('error', 'Invalid or expired token');
        return res.redirect('/forgot-password');
    }
    
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();
    
    req.flash('info', 'Password reset successfully. Please log in.');
    res.redirect('/login');
});

// Role-Based Access Control
app.get('/admin', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        req.flash('error', 'Access Denied');
        return res.redirect('/');
    }
    res.render('admin', { user: req.session.user });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
