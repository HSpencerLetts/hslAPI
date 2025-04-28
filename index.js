const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./authMiddleware");
require("dotenv").config();

const app = express();
app.use(express.json());

console.log("MONGO_URI:", process.env.MONGO_URI);

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// Schema & Models
const CallLog = mongoose.model(
  "CallLog",
  new mongoose.Schema({
    caller: String,
    ivrPath: String,
    callStart: Date,
    createdAt: { type: Date, default: Date.now },
  }),
);

const Item = mongoose.model(
  "Item",
  new mongoose.Schema({
    name: String,
    createdAt: { type: Date, default: Date.now },
  }),
);

const Customer = mongoose.model(
  "Customer",
  new mongoose.Schema({
    customerId: String,
    name: String,
    accountStatus: String,
  }),
);

// OAuth2-style token generation
app.post("/token", (req, res) => {
  // Check if credentials are in body or headers
  const { clientId, clientSecret } = req.body || req.headers;

  if (clientId && clientSecret) {
    if (
      clientId === process.env.OAUTH_CLIENT &&
      clientSecret === process.env.OAUTH_SECRET
    ) {
      const token = jwt.sign({ client: clientId }, process.env.OAUTH_SECRET, {
        expiresIn: "1h",
      });
      return res.json({ access_token: token });
    }
    return res.status(401).json({ error: "Invalid client credentials" });
  }

  return res.status(400).json({ error: "clientId and clientSecret required" });
});

// Protected route for retrieving customer data
app.get("/customer-data", authMiddleware, async (req, res) => {
  const { customerId } = req.query;

  if (customerId) {
    // Search for a specific customer
    const customer = await Customer.findOne({ customerId });

    if (!customer) {
      return res.status(404).json({ error: "Customer not found" });
    }

    return res.json({
      status: "success",
      accessedVia: req.authType,
      data: customer,
    });
  }

  // No customerId provided → return all customers
  const customers = await Customer.find();
  res.json({
    status: "success",
    accessedVia: req.authType,
    data: customers,
  });
});

// Add new customer (for seeding)
app.post("/customer-data", async (req, res) => {
  const { customerId, name, accountStatus } = req.body;
  const customer = new Customer({ customerId, name, accountStatus });
  await customer.save();
  res.status(201).json(customer);
});

// Log call
app.post("/log-call", async (req, res) => {
  const log = new CallLog(req.body);
  await log.save();
  res.status(201).json(log);
});

// Item routes
app.get("/items", async (req, res) => {
  const items = await Item.find();
  res.json(items);
});

app.post("/items", async (req, res) => {
  const item = new Item({ name: req.body.name });
  await item.save();
  res.status(201).json(item);
});

app.get("/", (req, res) => {
  res.send("🎉 Your API is live and working!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 API running on port ${PORT}`));
