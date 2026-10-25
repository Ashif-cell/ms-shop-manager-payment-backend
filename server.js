const express = require("express");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const PACKAGE_NAME = "com.aistudio.mobileclinic.vkrx";

// Authoritative Coin Packages Catalog matching MS Shop Manager Android app
const PRODUCTS = {
  pack_100: { id: "pack_100", name: "Starter Pack", coins: 100, price: 49, amountPaise: 4900 },
  pack_250: { id: "pack_250", name: "Value Pack", coins: 250, price: 99, amountPaise: 9900 },
  pack_400: { id: "pack_400", name: "Growth Pack", coins: 400, price: 149, amountPaise: 14900 },
  pack_500: { id: "pack_500", name: "Power Pack", coins: 500, price: 179, amountPaise: 17900 },
  pack_600: { id: "pack_600", name: "Pro Pack", coins: 600, price: 199, amountPaise: 19900 },
  pack_1500: { id: "pack_1500", name: "Mega Pack", coins: 1500, price: 399, amountPaise: 39900 }
};

app.get("/", (req, res) => {
  res.send("MS Shop Manager Payment Backend is running");
});

function getRazorpay() {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    throw new Error("Razorpay credentials are not configured (RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET missing)");
  }
  return new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
}

function initFirebase() {
  if (admin.apps.length) return admin.app();
  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON || process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("Google service account is not configured (GOOGLE_PLAY_SERVICE_ACCOUNT_JSON missing)");

  let serviceAccount = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (serviceAccount.private_key && serviceAccount.private_key.includes("\\n")) {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  return admin.app();
}

/**
 * 1. NATIVE NODE.JS RS256 JWT AUTHENTICATION FOR GOOGLE PLAY DEVELOPER API
 * Replaces the heavy 'googleapis' package with zero external dependencies.
 * Uses native 'crypto' to sign the RS256 JWT assertion and native 'fetch' for OAuth2 exchange.
 */
async function getGooglePlayAccessToken() {
  const raw = process.env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON;
  if (!raw) {
    throw new Error("Google Play service account is not configured (GOOGLE_PLAY_SERVICE_ACCOUNT_JSON missing)");
  }

  let credentials;
  try {
    credentials = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch (err) {
    throw new Error("Invalid GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: " + err.message);
  }

  const client_email = credentials.client_email;
  let private_key = credentials.private_key;

  if (!client_email || !private_key) {
    throw new Error("Invalid service account JSON: missing client_email or private_key");
  }

  if (private_key.includes("\\n")) {
    private_key = private_key.replace(/\\n/g, "\n");
  }

  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const claim = Buffer.from(JSON.stringify({
    iss: client_email,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  })).toString("base64url");

  const signature = crypto.createSign("RSA-SHA256")
    .update(`${header}.${claim}`)
    .sign(private_key, "base64url");

  const jwt = `${header}.${claim}.${signature}`;

  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  if (!tokenResp.ok) {
    const errText = await tokenResp.text();
    throw new Error(`Google OAuth2 token exchange failed HTTP ${tokenResp.status}: ${errText}`);
  }

  const tokenData = await tokenResp.json();
  return tokenData.access_token;
}

/**
 * Verifies purchase token directly against Google Play Developer API (Android Publisher v3).
 */
async function verifyGooglePlayPurchaseToken(packageName, productId, token) {
  const accessToken = await getGooglePlayAccessToken();
  const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${token}`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json"
    }
  });

  if (!resp.ok) {
    const errText = await resp.text();
    return {
      ok: false,
      status: resp.status,
      error: `Google Play API returned HTTP ${resp.status}: ${errText}`
    };
  }

  const data = await resp.json();
  return {
    ok: true,
    data: data
  };
}

/**
 * Consumes one-time product purchase on Google Play Developer API.
 */
async function consumeGooglePlayPurchaseToken(packageName, productId, token) {
  try {
    const accessToken = await getGooglePlayAccessToken();
    const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${token}:consume`;

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json"
      }
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.warn(`Google Play consume response HTTP ${resp.status}: ${errText}`);
      return false;
    }
    return true;
  } catch (err) {
    console.warn("Google Play consume error:", err.message);
    return false;
  }
}

/**
 * 2. RAZORPAY /create-order ENDPOINT
 * Accepts both 'amountPaise' (from Android client) and 'amount' (in paise),
 * with strict minimum ā‚¹1 (100 paise) integer validation.
 */
app.post(["/create-order", "/createRazorpayOrder"], async (req, res) => {
  try {
    const rawAmount = req.body.amountPaise !== undefined ? req.body.amountPaise : req.body.amount;
    const amount = Number(rawAmount);

    if (!Number.isInteger(amount) || amount < 100) {
      return res.status(400).json({
        error: "Invalid amount; minimum is ā‚¹1 (100 paise)"
      });
    }

    const order = await getRazorpay().orders.create({
      amount,
      currency: "INR",
      receipt: "ms_" + crypto.randomUUID()
    });

    // Provide both orderId and id, amount and amountPaise for 100% client compatibility
    return res.json({
      orderId: order.id,
      id: order.id,
      amount: order.amount,
      amountPaise: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error("Order creation failed:", error.message);
    return res.status(500).json({ error: "Could not create payment order" });
  }
});

/**
 * 3. RAZORPAY /verify-payment ENDPOINT
 * Cryptographic HMAC-SHA256 verification using constant-time comparison.
 */
app.post(["/verify-payment", "/verifyRazorpayPayment"], async (req, res) => {
  try {
    const orderId = req.body.orderId || req.body.razorpay_order_id;
    const paymentId = req.body.paymentId || req.body.razorpay_payment_id;
    const signature = req.body.signature || req.body.razorpay_signature;

    if (!orderId || !paymentId || !signature || !process.env.RAZORPAY_KEY_SECRET) {
      return res.status(400).json({ verified: false, error: "Missing required verification parameters" });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(signature);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ verified: false, error: "Invalid signature" });
    }

    return res.json({ verified: true, orderId, paymentId });
  } catch (error) {
    console.error("Payment verification failed:", error.message);
    return res.status(500).json({ verified: false, error: "Payment verification failed" });
  }
});

/**
 * 4. GOOGLE PLAY IN-APP PURCHASE VERIFICATION & ATOMIC COIN CREDITING
 * - Authenticates Firebase ID token (Bearer <token>).
 * - Verifies purchase against Google Play Developer API (Android Publisher v3).
 * - Enforces idempotency: Returns HTTP 200 with alreadyVerified: true and coinsCredited: 0.
 * - Handles missing Firestore user documents safely via merge-safe atomic transactions.
 * - Consumes the purchase on Google Play server-side.
 */
app.post(["/verify-play-purchase", "/verifyGooglePlayPurchase"], async (req, res) => {
  try {
    initFirebase();

    // Authenticate caller with Firebase ID token
    const authorization = req.headers.authorization || "";
    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        verified: false,
        error: "Firebase authentication required (Bearer token missing)"
      });
    }

    const idToken = authorization.slice(7);
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    const { purchaseToken, productId: reqProductId, packageId } = req.body;
    const productId = reqProductId || packageId;

    if (!purchaseToken || !productId || !PRODUCTS[productId]) {
      return res.status(400).json({
        verified: false,
        error: `Invalid purchase details or unsupported product ID: ${productId}`
      });
    }

    const product = PRODUCTS[productId];

    // Verify purchase token against Google Play Developer API
    const verifyResult = await verifyGooglePlayPurchaseToken(PACKAGE_NAME, productId, purchaseToken);
    if (!verifyResult.ok) {
      console.error(`Google Play verification rejected: ${verifyResult.error}`);
      return res.status(400).json({
        verified: false,
        error: verifyResult.error
      });
    }

    const purchase = verifyResult.data;
    if (purchase.purchaseState !== 0) {
      return res.status(400).json({
        verified: false,
        error: "Purchase is not completed (purchaseState != 0)"
      });
    }

    const db = admin.firestore();
    const tokenHash = crypto
      .createHash("sha256")
      .update(purchaseToken)
      .digest("hex");

    const transactionRef = db.collection("google_play_transactions").doc(tokenHash);
    const userRef = db.collection("users").doc(uid);
    const coinTransactionRef = userRef.collection("coin_transactions").doc(tokenHash);

    let alreadyVerified = false;
    let finalBalance = 0;

    // Atomic transaction for duplicate protection and merge-safe user doc handling
    await db.runTransaction(async transaction => {
      const existing = await transaction.get(transactionRef);
      if (existing.exists) {
        const existingData = existing.data();
        if (existingData.uid && existingData.uid !== uid) {
          throw new Error("PURCHASE_ALREADY_USED");
        }

        // Idempotent fulfillment: Token already credited for this user
        alreadyVerified = true;
        const userSnapshot = await transaction.get(userRef);
        finalBalance = userSnapshot.exists ? Number(userSnapshot.data().coinBalance || 0) : 0;
        return;
      }

      const userSnapshot = await transaction.get(userRef);
      const currentCoins = userSnapshot.exists ? Number(userSnapshot.data().coinBalance || 0) : 0;
      finalBalance = currentCoins + product.coins;

      // Merge-safe update: creates user document if missing without overwriting concurrent fields
      transaction.set(userRef, {
        coinBalance: finalBalance,
        lastWalletSync: Date.now()
      }, { merge: true });

      transaction.set(transactionRef, {
        uid,
        productId,
        coins: product.coins,
        packageName: PACKAGE_NAME,
        purchaseTime: purchase.purchaseTimeMillis || null,
        status: "verified",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

      transaction.set(coinTransactionRef, {
        id: tokenHash,
        uid,
        type: "google_play_purchase",
        amount: product.coins,
        coins: product.coins,
        productId,
        balanceAfter: finalBalance,
        purchaseTokenHash: tokenHash,
        status: "SUCCESS",
        timestamp: Date.now(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    // If purchase was previously verified, return HTTP 200 idempotently
    if (alreadyVerified) {
      return res.status(200).json({
        success: true,
        verified: true,
        alreadyVerified: true,
        productId,
        coinsCredited: 0,
        newBalance: finalBalance,
        message: "Purchase was already credited"
      });
    }

    // Consume product on Google Play server-side only after successful credit
    await consumeGooglePlayPurchaseToken(PACKAGE_NAME, productId, purchaseToken);

    return res.status(200).json({
      success: true,
      verified: true,
      alreadyVerified: false,
      productId,
      coinsCredited: product.coins,
      newBalance: finalBalance
    });
  } catch (error) {
    if (error.message === "PURCHASE_ALREADY_USED") {
      return res.status(409).json({
        verified: false,
        error: "Purchase token already belongs to another account"
      });
    }
    console.error("Google Play verification error:", error.message);
    return res.status(500).json({
      verified: false,
      error: error.message || "Purchase verification failed"
    });
  }
});

/**
 * 5. INDIA ALTERNATIVE BILLING REPORTING ENDPOINT
 */
app.post(["/report-external-transaction-start", "/reportExternalTransactionStart"], async (req, res) => {
  try {
    const { externalTransactionToken, packageId, coins, amountInr, uid } = req.body;
    if (!externalTransactionToken) {
      return res.status(400).json({ success: false, error: "externalTransactionToken is required" });
    }

    try {
      initFirebase();
      const db = admin.firestore();
      const tokenDocId = crypto.createHash("sha256").update(externalTransactionToken).digest("hex");
      await db.collection("google_play_external_transactions").doc(tokenDocId).set({
        tokenDocId,
        externalTransactionToken,
        packageId: packageId || "pack_100",
        coins: coins || 0,
        amountInr: amountInr || 0,
        uid: uid || "unknown",
        status: "INITIATED",
        initiatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } catch (dbErr) {
      console.warn("External transaction record notice:", dbErr.message);
    }

    return res.status(200).json({
      success: true,
      message: "External transaction initiation recorded"
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Payment backend listening on ${PORT}`);
});