import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  refreshToken: String,
  googleId: String,

  cart: {
    type: [String],
    default: []
  },

  wishlist: {
    type: [String],
    default: []
  }
});



const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otpHash: String,
  expiresAt: Date,
});

const resetTokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  tokenHash: String,
  expiresAt: Date,
});

const paymentSchema = new mongoose.Schema({
  orderId: String,
  paymentId: String,
  signature: String,
  amount: Number,
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now },
});

const productSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  image: String,
  company: String,
  item_name: String,
  original_price: mongoose.Schema.Types.Mixed,   // could be number or string
  current_price: mongoose.Schema.Types.Mixed,    // could be number or string
  discount_percentage: mongoose.Schema.Types.Mixed, // "42%" or number
  return_period: mongoose.Schema.Types.Mixed,    // could be number or string
  delivery_date: String,
  category: String,
  rating: {
    stars:mongoose.Schema.Types.Mixed,        // 4.5 or "4.5"
    count: mongoose.Schema.Types.Mixed           // "57k" or number
  }
});



export const Product = mongoose.model("Product", productSchema);

export const Payment = mongoose.model("Payment", paymentSchema);

export const Otp = mongoose.model("Otp", otpSchema);
export const User =mongoose.model("user",userSchema);
export const ResetToken = mongoose.model("ResetToken", resetTokenSchema);
