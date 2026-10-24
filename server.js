const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const { google } = require("googleapis");
const admin = require("firebase-admin");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const PACKAGE_NAME = "com.aistudio.mobileclinic.vkrx";

const PRODUCTS = {
  pack_100: { coins: 100, price: 49 },
  pack_250: { coins: 250, price: 99 },
  pack_400: { coins: 400, price: 149 },
  pack_500: { coins: 500, price: 179 },
  pack_600: { coins: 600, price: 199 },
  pack_1500: { coins: 1500, price: 399 }
};

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

function initFirebase() {
  if (admin.apps.length) return admin.app();

  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("Google service account is not configured");

  const serviceAccount = JSON.parse(raw);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });

  return admin.app();
}

function getPublisher() {
  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("Google Play service account is not configured");

  const credentials = JSON.parse(raw);

  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ["https://www.googleapis.com/auth/androidpublisher"]
  });

  return auth.getClient().then(client =>
    google.androidpublisher({ version: "v3", auth: client })
  );
}

// Existing Razorpay order endpoint
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

// Existing Razorpay signature verification
app.post("/verify-payment", (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body;

    if (!orderId || !paymentId || !signature ||
        !process.env.RAZORPAY_KEY_SECRET) {
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

    res.json({ verified: true, orderId, paymentId });
  } catch (error) {
    res.status(500).json({ verified: false });
  }
});

// Verify a Google Play product purchase and credit coins exactly once.
// Client must send Firebase ID token in Authorization: Bearer <token>.
app.post("/verify-play-purchase", async (req, res) => {
  try {
    initFirebase();

    const authorization = req.headers.authorization || "";
    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        verified: false,
        error: "Firebase authentication required"
      });
    }

    const idToken = authorization.slice(7);
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    const { purchaseToken, productId } = req.body;
    if (!purchaseToken || !productId || !PRODUCTS[productId]) {
      return res.status(400).json({
        verified: false,
        error: "Invalid purchase details"
      });
    }

    const product = PRODUCTS[productId];
    const publisher = await getPublisher();

    const result = await publisher.purchases.products.get({
      packageName: PACKAGE_NAME,
      productId,
      token: purchaseToken
    });

    const purchase = result.data;

    if (purchase.purchaseState !== 0) {
      return res.status(400).json({
        verified: false,
        error: "Purchase is not completed"
      });
    }

    const db = admin.firestore();
    const tokenHash = crypto
      .createHash("sha256")
      .update(purchaseToken)
      .digest("hex");

    const transactionRef = db.collection("google_play_transactions")
      .doc(tokenHash);
    const userRef = db.collection("users").doc(uid);
    const coinTransactionRef = userRef.collection("coin_transactions")
      .doc(tokenHash);

    await db.runTransaction(async transaction => {
      const existing = await transaction.get(transactionRef);

      if (existing.exists) {
        if (existing.data().uid !== uid) {
          throw new Error("PURCHASE_ALREADY_USED");
        }
        throw new Error("PURCHASE_ALREADY_CREDITED");
      }

      const userSnapshot = await transaction.get(userRef);
      if (!userSnapshot.exists) {
        throw new Error("USER_NOT_FOUND");
      }

      const userData = userSnapshot.data();
      const currentCoins = Number(userData.coinBalance || 0);

      transaction.update(userRef, {
        coinBalance: currentCoins + product.coins
      });

      transaction.set(transactionRef, {
        uid,
        productId,
        coins: product.coins,
        packageName: PACKAGE_NAME,
        purchaseTime: purchase.purchaseTimeMillis || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

      transaction.set(coinTransactionRef, {
        type: "google_play_purchase",
        productId,
        coins: product.coins,
        purchaseTokenHash: tokenHash,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    // Consume only after successful server-side credit.
    await publisher.purchases.products.consume({
      packageName: PACKAGE_NAME,
      productId,
      token: purchaseToken
    });

    return res.json({
      verified: true,
      productId,
      coinsCredited: product.coins
    });
  } catch (error) {
    if (error.message === "PURCHASE_ALREADY_CREDITED") {
      return res.status(409).json({
        verified: false,
        error: "Purchase was already credited"
      });
    }

    if (error.message === "PURCHASE_ALREADY_USED") {
      return res.status(409).json({
        verified: false,
        error: "Purchase token already belongs to another account"
      });
    }

    if (error.message === "USER_NOT_FOUND") {
      return res.status(404).json({
        verified: false,
        error: "User account not found"
      });
    }

    console.error("Google Play verification failed:", error.message);
    return res.status(500).json({
      verified: false,
      error: "Purchase verification failed"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Payment backend listening on ${PORT}`);
});