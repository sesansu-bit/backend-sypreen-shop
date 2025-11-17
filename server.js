import express from "express";
import mongoose from "mongoose";
import {User} from "./models/User.js";
import {Otp} from "./models/User.js";
import {Payment} from "./models/User.js";
import {ResetToken} from "./models/User.js";
import dotenv from 'dotenv';
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cors from "cors";
import crypto from "crypto";
import nodemailer from "nodemailer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import morgan from "morgan";
import { OAuth2Client } from "google-auth-library";
import Razorpay from "razorpay";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { Product } from "./models/User.js";
 





dotenv.config();
const app =express();
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(express.json());
app.use(helmet());
app.use(morgan("dev"));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const filePath = path.join(__dirname, 'items.json')

app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://sypreen-shopping-web.vercel.app"
  ],
  credentials: true,
}));

mongoose.connect(process.env.MONGO_URI, { dbName: "userdata" })
  .then(() => console.log("MongoDB connected"))

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);





const createAccessToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

const createRefreshToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "30d" });

const accessCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 15 * 60 * 1000,
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 30 * 24 * 60 * 60 * 1000,
};




// ====================== SEED FUNCTION =======================

async function seedProducts() {
  try {
    console.log("⏳ Reading JSON file...");
    const data = await fs.readFile(filePath, "utf8");
    const items = JSON.parse(data);

    console.log("🧹 Cleaning product data...");
    const cleanedItems = items.map(cleanProduct);

    console.log("🗑️ Removing old products...");
    await Product.deleteMany();

    console.log("📥 Inserting new products...");
    await Product.insertMany(cleanedItems);

    console.log("🎉 Products seeded successfully!");
    return true;
  } catch (err) {
    console.error("❌ Seed Error:", err);
    return false;
  }
}

// ====================== SEED ROUTE =======================

app.get("/seed", async (req, res) => {
  const ok = await seedProducts();
  if (ok) {
    return res.json({ success: true, message: "Products seeded successfully!" });
  }
  res.status(500).json({ success: false, message: "Seeding failed" });
});





 



//  Send ALL categories grouped at once
app.get("/api/products/all", async (req, res) => {
  try {
    const items = await Product.find();

    const groupByCategory = (cat) => items.filter(item => (item.category || "").toLowerCase() === cat.toLowerCase());

    res.status(200).json({
      men: groupByCategory("men"),
      women: groupByCategory("women"),
      beauty: groupByCategory("beauty"),
      sports: groupByCategory("sports"),
      house: groupByCategory("house"),
      electronics: groupByCategory("electronics"),
      luggage: groupByCategory("luggage"),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server Error" });
  }
});







// Signup
app.post("/signup", async (req, res) => {
     try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: "All fields required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ success: false, message: "Email already registered" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);
    const user = await User.create({ name, email, password: hashed });

  
   const accessToken = createAccessToken({ id: user._id });
    const refreshToken = createRefreshToken({ id: user._id });
    user.refreshToken = refreshToken;
    await user.save();

    // set httpOnly cookies
    res.cookie("accessToken", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    // return user + access token (access in body so frontend can keep it in memory)
    res.status(201).json({
      success: true,
      message: "Signup successful🎉",
      user: { id: user._id, name: user.name, email: user.email },
      accessToken,
    });
  } catch (err) {
    console.error("signup error:", err);
    res.status(500).json({ success: false, message: "Server error during signup" });
  }
 
});



// LOGIN USER
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    // Check user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid email or password" });
    }

    // Check password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid email or password" });
    }

    // Generate tokens
    const accessToken = createAccessToken({ id: user._id });
    const refreshToken = createRefreshToken({ id: user._id });

    // Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    // Store tokens in cookies
    res.cookie("accessToken", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);

    // Send response
    res.json({
      success: true,
      message: "Login successful 🎉",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during login",
    });
  }
});




//refresh token
app.post("/refresh", async (req, res) => {
 try {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({ success: false, message: "Refresh token missing" });

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
      if (err) return res.status(403).json({ success: false, message: "Invalid refresh token" });

      // find user and ensure DB-stored refresh token matches (rotation / revocation)
      const user = await User.findById(decoded.id);
      if (!user || !user.refreshToken) return res.status(403).json({ success: false, message: "Not recognized" });

      if (user.refreshToken !== token) {
        // possible theft
        user.refreshToken = null;
        await user.save();
        return res.status(403).json({ success: false, message: "Refresh token mismatch" });
      }

      const newAccessToken = createAccessToken(user);
      const newRefreshToken = createRefreshToken(user);

      user.refreshToken = newRefreshToken;
      await user.save();

      // overwrite cookies
      res.cookie("accessToken", newAccessToken, accessCookieOptions);
      res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);

      // return new access token in body too
      return res.json({ success: true, message: "Tokens refreshed", accessToken: newAccessToken });
    });
  } catch (err) {
    console.error("refresh error:", err);
    res.status(500).json({ success: false, message: "Server error during token refresh" });
  }
});





//logout
app.post("/logout", async (req, res) => {
    try {
    const token = req.cookies?.refreshToken;
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decoded.id);
        if (user) {
          user.refreshToken = null;
          await user.save();
        }
      } catch (e) {
        // ignore
      }
    }
    // clear cookies
    res.clearCookie("accessToken", accessCookieOptions);
    res.clearCookie("refreshToken", refreshCookieOptions);
    res.json({ success: true, message: "Logged out" });
  } catch (err) {
    console.error("logout error:", err);
    res.status(500).json({ success: false, message: "Server error during logout" });
  }
});






//middleware
const verifyAccessToken = (req, res, next) => {
  try {
    const token = req.cookies?.accessToken || req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ success: false, message: "Access token required" });

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        if (err.name === "TokenExpiredError") {
          return res.status(401).json({ success: false, message: "Access token expired" });
        }
        return res.status(403).json({ success: false, message: "Invalid access token" });
      }
      req.user = decoded; // { id, email, iat, exp }
      next();
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};








//profile
app.get("/profile", verifyAccessToken,async (req, res) => {
 try {
    const user = await User.findById(req.user.id).select("-password -refreshToken");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, user });
  } catch (err) {
    console.error("getMe error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




app.get("/api/verify-token", verifyAccessToken, (req, res) => {
  res.json({ success: true, message: "Token valid", user: req.user });
});





let transporter;
try {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS, // Gmail app password or OAuth2
    },
  });

  await transporter.verify();
  console.log("Mail service ready");
} catch (err) {
  console.error("Mail service failed:", err.message);
}




const generateOtp = () =>
  Math.floor(100000 + Math.random() * 900000).toString();
const OTP_TTL_MS = 5 * 60 * 1000; // 5 min
const TOKEN_TTL_MS = 10 * 60 * 1000;

// -------------------- ✅ Rate Limiting --------------------
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  message: { ok: false, message: "Too many OTP requests, try later" },
});

// -------------------- 1️⃣ Send OTP --------------------
app.post(
  "/api/send-otp",
  otpLimiter,
  body("email").isEmail().withMessage("Valid email required"),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty())
        return res.status(400).json({ message: errors.array()[0].msg });

      const { email } = req.body;
      const otp = generateOtp();
      const otpHash = await bcrypt.hash(otp, 10);
      const expiresAt = new Date(Date.now() + OTP_TTL_MS);

      await Otp.deleteMany({ email });
      await Otp.create({ email, otpHash, expiresAt });

      await transporter.sendMail({
        from: process.env.FROM_EMAIL,
        to: email,
        subject: "OTP for Password Reset",
        text: `Your OTP is ${otp}. Valid for 5 minutes.`,
        html: `<p>Your OTP is <b>${otp}</b>. Valid for 5 minutes.</p>`,
      });

      res.json({ ok: true, message: "OTP sent successfully" });
    } catch (err) {
      console.error("Send OTP Error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// -------------------- 2️⃣ Verify OTP --------------------
app.post(
  "/api/verify-otp",
  body("email").isEmail(),
  body("otp").isLength({ min: 6, max: 6 }),
  async (req, res) => {
    try {
      const { email, otp } = req.body;
      const record = await Otp.findOne({ email });
      if (!record) return res.status(400).json({ message: "OTP not found" });

      if (record.expiresAt < new Date()) {
        await Otp.deleteOne({ email });
        return res.status(400).json({ message: "OTP expired" });
      }

      const isMatch = await bcrypt.compare(otp, record.otpHash);
      if (!isMatch) return res.status(400).json({ message: "Invalid OTP" });

      await Otp.deleteOne({ email });

      // ✅ Generate raw reset token (send once)
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = await bcrypt.hash(rawToken, 10);
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

      await ResetToken.deleteMany({ email });
      await ResetToken.create({ email, tokenHash, expiresAt });

      // ✅ Store token in secure cookie
      res.cookie("reset_token", rawToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: TOKEN_TTL_MS,
      });

      res.json({ ok: true, message: "OTP verified successfully" });
    } catch (err) {
      console.error("Verify OTP Error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// -------------------- 3️⃣ Reset Password --------------------
app.post(
  "/api/reset-password",
  body("email").isEmail(),
  body("newPassword").isLength({ min: 6 }),
  async (req, res) => {
    try {
      const { email, newPassword } = req.body;
      const rawToken = req.cookies.reset_token;

      if (!rawToken)
        return res.status(400).json({ message: "No reset token found" });

      const record = await ResetToken.findOne({ email });
      if (!record)
        return res.status(400).json({ message: "Reset token not found" });

      if (record.expiresAt < new Date()) {
        await ResetToken.deleteOne({ email });
        return res.status(400).json({ message: "Token expired" });
      }

      const isValid = await bcrypt.compare(rawToken, record.tokenHash);
      if (!isValid)
        return res.status(400).json({ message: "Invalid or tampered token" });

      const user = await User.findOne({ email });
      if (!user)
        return res.status(400).json({ message: "Email not registered" });

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      await user.save();

      await ResetToken.deleteOne({ email });
      res.clearCookie("reset_token");

      console.log("✅ Password updated for:", email);
      res.json({ ok: true, message: "Password reset successful" });
    } catch (err) {
      console.error("Reset Password Error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);








// ROUTE: Google login
app.post("/api/auth/google", async (req, res) => {
  const { tokenId } = req.body; // frontend se id_token
  try {
    const ticket = await client.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    let user = await User.findOne({ email });
    if (!user) {
    user = new User({ name, email, googleId });
      await user.save();
    }

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    // save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    // send tokens in httpOnly cookies
    res
      .cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 15 * 60 * 1000,
      })
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      })
      .status(200)
      .json({ message: "Google login successful🎉", user: { name, email } });
  } catch (err) {
    console.log(err);
    res.status(400).json({ message: "Google login failed" });
  }
});





const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});




app.get("/api/get-razorpay-key", (req, res) => {
  res.json({ key: process.env.RAZORPAY_KEY_ID });
});

// ✅ Create order
app.post("/api/create-order", async (req, res) => {
  try {
    const { amount } = req.body;

    if (!amount) return res.status(400).json({ success: false, message: "Amount required" });

    const options = {
      amount: Number(amount) * 100, // amount in paisa
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    if (!order) return res.status(500).json({ success: false, message: "Order creation failed" });

    res.json({ success: true, order });
  } catch (error) {
    console.error("Order Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// ✅ Verify payment
app.post("/api/verify-payment", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount } = req.body;

    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign)
      .digest("hex");

    if (razorpay_signature === expectedSign) {
      await Payment.create({
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        signature: razorpay_signature,
        amount,
        status: "success",
      });
      return res.json({ success: true, message: "Payment verified successfully" });
    } else {
      return res.status(400).json({ success: false, message: "Invalid signature" });
    }
  } catch (error) {
    console.error("Verify Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.get("/search", async (req, res) => {
  try {
    const query = req.query.q?.trim().toLowerCase();
    if (!query) return res.json({ suggestions: [] });

    const items = await Product.find({
      $or: [
        { item_name: { $regex: query, $options: "i" } },
        { category: { $regex: query, $options: "i" } }
      ]
    }).limit(10);

    const uniqueSuggestions = Array.from(new Set(items.map(p => JSON.stringify({ name: p.item_name, category: p.category }))))
      .map(p => JSON.parse(p));

    res.json({ suggestions: uniqueSuggestions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});





app.get("/cartfetch", verifyAccessToken, async (req, res) => {
  try {
    // Logged-in user ka data
    const user = await User.findById(req.user.id);

    if (!user.cart || user.cart.length === 0) {
      return res.json({ success: true, items: [] });
    }

    // Cart  product IDs 
    const productIds = user.cart;

    // IDs full product details fetch 
    const products = await Product.find({ id: { $in: productIds } });

    res.json({
      success: true,
      items: products
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});



app.post("/bagstore", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;

    if (!productId) {
      return res.status(400).json({ success: false, message: "Product ID is required" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

  if (user.wishlist.includes(productId)) {
          return res.status(400).json({
        success: false,
         isDuplicate: true,
        message: "Product exists in wishlist, cannot add to wishlist",
      });
    }
    
    // Duplicate check
    if (user.cart.includes(productId)) {
      return res.status(200).json({
        success: true,
        message: "Product already in cart",
        isDuplicate: true,
      });
    }
  if (!user.wishlist.includes(productId)) {
        user.cart.push(productId);
    await user.save();
    }

  
  

    // Get ONLY that product full info
    const product = await Product.findOne({ id: productId });

    res.json({
      success: true,
      message: "Product added to cart",
      item: product, 
        isDuplicate: false,
    });

  } catch (err) {
    console.error("Add to cart error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});






 
app.post("/bagremove", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) {
      return res.status(400).json({ success: false, message: "Product ID is required" });
    }

    // Find user using token
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Remove productId from cart
    user.cart = user.cart.filter(id => id !== productId);
    await user.save();

    res.json({
      success: true,
      message: "Product removed from cart",
    });
  } catch (err) {
    console.error("Remove from cart error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




// Fetch wishlist
app.get("/wishlistfetch", verifyAccessToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user.wishlist || user.wishlist.length === 0) {
      return res.json({ success: true, items: [] });
    }

    const products = await Product.find({ id: { $in: user.wishlist } });

    res.json({
      success: true,
      items: products
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




// Add to Wishlist

app.post("/wishliststore", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;

    if (!productId) {
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required" });
    }

    // Find user
    const user = await User.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
 // Check cart — do not add if already in cart
    if (user.cart.includes(productId)) {
      return res.status(400).json({
        success: false,
         isDuplicate: true,
        message: "Product exists in cart, cannot add to wishlist",
      });
    }
    
    // Duplicate check — if already in wishlist
    if (user.wishlist.includes(productId)) {
      const existingItem = await Product.findOne({ id: productId });
      return res.status(200).json({
        success: true,
        message: "Product already in wishlist",
        item: existingItem,
        isDuplicate: true,
      });
    }

   

    // Add to wishlist
    user.wishlist.push(productId);
    await user.save();

    // Fetch newly added product
    const newItem = await Product.findOne({ id: productId });

    return res.json({
      success: true,
      message: "Added to wishlist",
      item: newItem,
      isDuplicate: false,
    });
  } catch (err) {
    console.error("Add to wishlist error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




 app.post("/wishlistremove", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) {
      return res.status(400).json({ success: false, message: "Product ID is required" });
    }

    // Logged-in user
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    let addedToCartProduct = null;

    // 1️⃣ Add to cart if not already present
    if (!user.cart.includes(productId)) {
      user.cart.push(productId);
      // Fetch full info of newly added cart product
      addedToCartProduct = await Product.findOne({ id: productId });
    }

    // 2️⃣ Remove from wishlist
    user.wishlist = user.wishlist.filter(id => id !== productId);

    await user.save();

    res.json({
      success: true,
      message: "Wishlist updated and moved to cart if needed",
      addedToCart: addedToCartProduct // null if already in cart
    });

  } catch (err) {
    console.error("Wishlist remove error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});



const PORT=2000;
app.listen(PORT, () => console.log(`Server running `));