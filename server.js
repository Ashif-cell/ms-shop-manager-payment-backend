const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("MS Shop Manager Payment Backend is running");
});

function getRazorpay() {
  if (!process.env.RAZORPAY_KEY_ID ||
      !process.env.RAZORPAY_KEY_SECRET) {
    throw new Error("Razorpay credentials are not configured");
  }

  return new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
}

app.post("/create-order", async (req, res) => {
  try {
    const amount = Number(req.body.amount);

    if (!Number.isInteger(amount) || amount < 100) {
      return res.status(400).json({
        error: "Invalid amount; minimum is ₹1"
      });
    }

    const order = await getRazorpay().orders.create({
      amount,
      currency: "INR",
      receipt: "ms_" + crypto.randomUUID()
    });

    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error("Order creation failed:", error.message);
    res.status(500).json({ error: "Could not create payment order" });
  }
});

app.post("/verify-payment", (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body;

    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({ verified: false });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(signature);

    if (a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ verified: false });
    }

    res.json({
      verified: true,
      orderId,
      paymentId
    });
  } catch (error) {
    res.status(500).json({ verified: false });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`Payment backend listening on ${port}`);
});
