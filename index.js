const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const cors = require('cors');
const app = express();
app.use(bodyParser.json());
app.use(cors());
// Simulate a database for users
let users = [];
let otpStore = {};

// Secret key for JWT
const JWT_SECRET = "your_jwt_secret_key"; // Replace with an environment variable for security

// Generate RSA keys for encrypting AES keys
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// Helper function to generate a random AES key
const generateAESKey = () => crypto.randomBytes(32);

// Encrypt data with AES
const encryptWithAES = (data, aesKey) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
    const encryptedData = cipher.update(data, "utf8", "hex") + cipher.final("hex");
    return { encryptedData, iv: iv.toString("hex") };
};

// Decrypt data with AES
const decryptWithAES = (encryptedData, aesKey, iv) => {
    const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, Buffer.from(iv, "hex"));
    const decryptedData = decipher.update(encryptedData, "hex", "utf8") + decipher.final("utf8");
    return decryptedData;
};

// Function to send OTP via email
const sendOTP = (email, otp) => {
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: 'ashraful.islam.asfu@gmail.com',
            pass: 'uqgimztflmqhuqrk', // Use environment variables to store this
        },
    });

    const mailOptions = {
        from: "your_email@gmail.com",
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP Code is: ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log("Error sending email:", error);
        } else {
            console.log("Email sent:", info.response);
        }
    });
};

// Registration endpoint
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (users.find((user) => user.email === email)) {
        return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, email, password: hashedPassword });
    res.status(201).json({ message: "User registered successfully" });
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = users.find((user) => user.email === email);
    if (!user) {
        return res.status(400).json({ error: "User not found" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ email: user.email, username: user.username }, JWT_SECRET, { expiresIn: "1h" });

    const otp = crypto.randomInt(100000, 999999).toString();
    const aesKey = generateAESKey();
    const { encryptedData, iv } = encryptWithAES(otp, aesKey);
    const encryptedAESKey = crypto.publicEncrypt(publicKey, aesKey);

    otpStore[email] = { encryptedOTP: encryptedData, aesKey: encryptedAESKey.toString("base64"), iv };

    sendOTP(email, otp);
    res.json({ email, token, message: "OTP sent to your email for verification." });
});

// OTP verification endpoint
app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    const storedOTPData = otpStore[email];
    if (!storedOTPData) {
        return res.status(400).json({ error: "No OTP generated for this email" });
    }

    try {
        
        const aesKey = crypto.privateDecrypt(privateKey, Buffer.from(storedOTPData.aesKey, "base64"));
        const decryptedOTP = decryptWithAES(storedOTPData.encryptedOTP, aesKey, storedOTPData.iv);

        if (decryptedOTP === otp) {
            res.json({ message: "OTP verified successfully!" });
            delete otpStore[email]; // Clear OTP after successful verification
        } else {
            res.status(400).json({ error: "Invalid OTP" });
        }
    } catch (error) {
        console.error("Decryption error:", error);
        res.status(500).json({ error: "An error occurred during OTP verification" });
    }
});

// Start the server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

