import bcrypt from "bcryptjs";
import cors from "cors";
import crypto from "crypto";
import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import nodemailer from "nodemailer";
dotenv.config();

const app = express();
const port = 7000;
app.use(cors());

app.use(express.json());

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

const User = mongoose.model("User", userSchema);

mongoose
  .connect(process.env.DB_URL, {})
  .then(() => {
    console.log("Connected to MongoDB Successfully");
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });

// Helper function to send email
const sendResetEmail = (email, token) => {
  const transporter = nodemailer.createTransport({
    service: "gmail", // Using Gmail for this example
    auth: {
      user: process.env.EMAIL_USER, // Your email
      pass: process.env.EMAIL_PASS, // Your email password
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset Request",
    text: `To reset your password, please click on the following link: \n\n${process.env.BASE_URL}/reset/${token}`,
  };

  return transporter.sendMail(mailOptions);
};

// Register Route
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ message: "User already exists" });
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashPassword });
    await newUser.save();

    return res.status(201).send({ message: "User registered successfully" });
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return res.status(400).send({ message: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(password, existingUser.password);
    if (passwordMatch) {
      return res.status(200).send({ message: "Logged in successfully" });
    } else {
      return res.status(400).send({ message: "Incorrect password" });
    }
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
});

// Forgot Password Route
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).send({ message: "User not found" });
    }

    // Generate reset token and expiration time (1 hour from now)
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenHash = bcrypt.hashSync(resetToken, 10);
    const resetPasswordExpires = Date.now() + 3600000; // 1 hour

    // Update the user's reset password token and expiration
    user.resetPasswordToken = resetTokenHash;
    user.resetPasswordExpires = resetPasswordExpires;
    await user.save();

    // Send the reset email
    await sendResetEmail(user.email, resetToken);

    return res.status(200).send({ message: "Password reset email sent" });
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
});

// Reset Password Route
app.post("/reset/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).send({ message: "Invalid or expired token" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password and clear the reset token fields
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.status(200).send({ message: "Password successfully reset" });
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
