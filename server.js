const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

/* =========================================================
   BASIC SERVER CONFIGURATION
   ========================================================= */

const PORT = Number(process.env.PORT || 3000);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

/* =========================================================
   ENVIRONMENT VARIABLES
   ========================================================= */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const CLICKPESA_BASE_URL =
  process.env.CLICKPESA_BASE_URL ||
  "https://api.clickpesa.com/third-parties";

const CLICKPESA_API_KEY = process.env.CLICKPESA_API_KEY;
const CLICKPESA_CLIENT_ID = process.env.CLICKPESA_CLIENT_ID;
const CLICKPESA_CHECKSUM_KEY =
  process.env.CLICKPESA_CHECKSUM_KEY;

/*
  IMPORTANT:
  Set ADMIN_API_KEY in Render. The Admin App must send:
  x-admin-api-key: YOUR_ADMIN_API_KEY

  This protects all /api/admin/* endpoints.
*/
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

const requiredEnvironmentVariables = [
  ["SUPABASE_URL", SUPABASE_URL],
  ["SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY],
  ["CLICKPESA_API_KEY", CLICKPESA_API_KEY],
  ["CLICKPESA_CLIENT_ID", CLICKPESA_CLIENT_ID],
  ["CLICKPESA_CHECKSUM_KEY", CLICKPESA_CHECKSUM_KEY],
  ["ADMIN_API_KEY", ADMIN_API_KEY],
];

const missingEnvironmentVariables =
  requiredEnvironmentVariables
    .filter(([, value]) => !value)
    .map(([name]) => name);

if (missingEnvironmentVariables.length > 0) {
  console.error(
    "Missing required environment variables:",
    missingEnvironmentVariables.join(", ")
  );
}

/* =========================================================
   SUPABASE
   ========================================================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  }
);

/* =========================================================
   CLICKPESA TOKEN CACHE
   ========================================================= */

let clickPesaToken = null;
let clickPesaTokenExpiresAt = 0;

/* =========================================================
   CLICKPESA AUTHENTICATION
   ========================================================= */

async function getClickPesaToken() {
  const now = Date.now();

  if (
    clickPesaToken &&
    now < clickPesaTokenExpiresAt
  ) {
    return clickPesaToken;
  }

  try {
    const response = await axios.post(
      `${CLICKPESA_BASE_URL}/generate-token`,
      {},
      {
        headers: {
          "api-key": CLICKPESA_API_KEY,
          "client-id": CLICKPESA_CLIENT_ID,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      }
    );

    if (
      !response.data ||
      !response.data.success ||
      !response.data.token
    ) {
      throw new Error(
        "ClickPesa did not return a valid authorization token."
      );
    }

    clickPesaToken = response.data.token;

    // Refresh before the one-hour JWT lifetime expires.
    clickPesaTokenExpiresAt =
      Date.now() + 55 * 60 * 1000;

    return clickPesaToken;
  } catch (error) {
    console.error(
      "ClickPesa token generation failed:",
      error.response?.data || error.message
    );

    throw new Error(
      "Unable to authenticate with ClickPesa."
    );
  }
}

/* =========================================================
   CLICKPESA REQUEST HELPER
   ========================================================= */

async function clickPesaRequest(
  method,
  endpoint,
  data = null
) {
  const token = await getClickPesaToken();

  try {
    const config = {
      method,
      url: `${CLICKPESA_BASE_URL}${endpoint}`,
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
      timeout: 30000,
    };

    if (data !== null) {
      config.data = data;
    }

    return await axios(config);
  } catch (error) {
    console.error(
      `ClickPesa request failed [${method} ${endpoint}]:`,
      error.response?.data || error.message
    );

    if (error.response?.status === 401) {
      clickPesaToken = null;
      clickPesaTokenExpiresAt = 0;
    }

    throw error;
  }
}

/* =========================================================
   CLICKPESA CHECKSUM
   ========================================================= */

function canonicalize(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }

  return Object.keys(value)
    .sort()
    .reduce((result, key) => {
      result[key] = canonicalize(value[key]);
      return result;
    }, {});
}

function createPayloadChecksum(checksumKey, payload) {
  const payloadWithoutChecksum = {
    ...payload,
  };

  delete payloadWithoutChecksum.checksum;
  delete payloadWithoutChecksum.checksumMethod;

  const canonicalPayload =
    canonicalize(payloadWithoutChecksum);

  const payloadString =
    JSON.stringify(canonicalPayload);

  return crypto
    .createHmac("sha256", checksumKey)
    .update(payloadString)
    .digest("hex");
}

function verifyChecksum(payload) {
  if (!payload?.checksum) {
    return true;
  }

  const received = String(payload.checksum);
  const calculated = createPayloadChecksum(
    CLICKPESA_CHECKSUM_KEY,
    payload
  );

  const receivedBuffer = Buffer.from(
    received,
    "utf8"
  );
  const calculatedBuffer = Buffer.from(
    calculated,
    "utf8"
  );

  if (
    receivedBuffer.length !==
    calculatedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    receivedBuffer,
    calculatedBuffer
  );
}

/* =========================================================
   PHONE NUMBER
   ========================================================= */

function cleanPhoneNumber(phone) {
  if (!phone) {
    return "";
  }

  let cleaned = String(phone)
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "");

  if (cleaned.startsWith("+")) {
    cleaned = cleaned.substring(1);
  }

  if (cleaned.startsWith("0")) {
    cleaned = "255" + cleaned.substring(1);
  }

  return cleaned;
}

/* =========================================================
   NUMBER / INPUT HELPERS
   ========================================================= */

function isPositiveNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0;
}

function isValidTransactionId(id) {
  return (
    typeof id === "string" &&
    id.trim().length > 0 &&
    id.length <= 100
  );
}

function roundMoney(value) {
  return Math.round(
    (Number(value) + Number.EPSILON) * 100
  ) / 100;
}

/* =========================================================
   FEE HELPER
   ========================================================= */

async function getFeePercentage(
  settingName,
  defaultValue
) {
  try {
    const { data, error } = await supabase
      .from("app_settings")
      .select("value")
      .eq("key", settingName)
      .maybeSingle();

    if (error) {
      console.error(
        `Could not read ${settingName}:`,
        error.message
      );
      return defaultValue;
    }

    if (!data || data.value === null) {
      return defaultValue;
    }

    const value = Number(data.value);

    if (!Number.isFinite(value)) {
      return defaultValue;
    }

    return value;
  } catch (error) {
    console.error(
      `Fee lookup failed for ${settingName}:`,
      error.message
    );

    return defaultValue;
  }
}

/* =========================================================
   ADMIN AUTHENTICATION
   ========================================================= */

function requireAdmin(req, res, next) {
  const suppliedKey =
    req.get("x-admin-api-key") ||
    req.get("authorization")?.replace(/^Bearer\s+/i, "");

  if (!ADMIN_API_KEY) {
    return res.status(503).json({
      success: false,
      message:
        "Admin API is not configured. Set ADMIN_API_KEY on the server.",
    });
  }

  if (
    !suppliedKey ||
    !crypto.timingSafeEqual(
      Buffer.from(String(suppliedKey)),
      Buffer.from(String(ADMIN_API_KEY))
    )
  ) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized.",
    });
  }

  next();
}

/* =========================================================
   STATUS HELPERS
   ========================================================= */

/*
  Deposit:
    pending
    fiat_received
    crypto_sent
    completed
    failed
    cancelled

  Withdrawal:
    pending
    crypto_address_provided
    crypto_received
    mobile_money_sent
    completed
    failed
    cancelled
*/

const SUCCESSFUL_CLICKPESA_STATUSES = [
  "SUCCESS",
  "SUCCESSFUL",
  "COMPLETED",
  "PAID",
];

const FAILED_CLICKPESA_STATUSES = [
  "FAILED",
  "CANCELLED",
  "CANCELED",
  "REJECTED",
  "DECLINED",
];

function mapClickPesaStatus(rawStatus) {
  const status = String(rawStatus || "").toUpperCase();

  if (
    SUCCESSFUL_CLICKPESA_STATUSES.includes(status)
  ) {
    return "fiat_received";
  }

  if (
    FAILED_CLICKPESA_STATUSES.includes(status)
  ) {
    return "failed";
  }

  return "pending";
}

/* =========================================================
   HEALTH CHECKS
   ========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "SwiftFX backend is running.",
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    message: "SwiftFX backend is running.",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "SwiftFX API is healthy.",
    timestamp: new Date().toISOString(),
  });
});

/* =========================================================
   DEPOSIT
   ========================================================= */

async function initiateDeposit(req, res) {
  try {
    const {
      user_id,
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number,
      amount,
      crypto_address,
    } = req.body || {};

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    if (!crypto_currency) {
      return res.status(400).json({
        success: false,
        message: "Crypto currency is required.",
      });
    }

    if (!crypto_network) {
      return res.status(400).json({
        success: false,
        message: "Crypto network is required.",
      });
    }

    if (!mobile_network) {
      return res.status(400).json({
        success: false,
        message: "Mobile network is required.",
      });
    }

    if (!phone_number) {
      return res.status(400).json({
        success: false,
        message: "Phone number is required.",
      });
    }

    if (!crypto_address) {
      return res.status(400).json({
        success: false,
        message: "Crypto wallet address is required.",
      });
    }

    if (!isPositiveNumber(amount)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid deposit amount.",
      });
    }

    const numericAmount = roundMoney(amount);

    const feePercentage =
      await getFeePercentage(
        "deposit_fee_percentage",
        2.5
      );

    const feeAmount = roundMoney(
      numericAmount * (feePercentage / 100)
    );

    const totalAmount = roundMoney(
      numericAmount + feeAmount
    );

    const cleanedPhone =
      cleanPhoneNumber(phone_number);

    if (!/^255\d{9}$/.test(cleanedPhone)) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid Tanzanian mobile number.",
      });
    }

    const transactionData = {
      user_id,
      type: "deposit",
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number: cleanedPhone,
      amount: numericAmount,
      fee_percentage: feePercentage,
      total_amount: totalAmount,
      crypto_address: String(crypto_address).trim(),
      status: "pending",
    };

    const {
      data: transaction,
      error: transactionError,
    } = await supabase
      .from("transactions")
      .insert(transactionData)
      .select()
      .single();

    if (transactionError) {
      console.error(
        "Transaction creation failed:",
        transactionError.message
      );

      return res.status(500).json({
        success: false,
        message: "Could not create the transaction.",
      });
    }

    const orderReference = transaction.id;

    /*
      ClickPesa collection.
      The mobile-money network is represented by the
      customer's phone number and ClickPesa's routing.
    */
    const previewPayload = {
      amount: String(Math.round(totalAmount)),
      currency: "TZS",
      orderReference,
      phoneNumber: cleanedPhone,
      fetchSenderDetails: false,
    };

    previewPayload.checksum =
      createPayloadChecksum(
        CLICKPESA_CHECKSUM_KEY,
        previewPayload
      );

    let previewResponse;

    try {
      previewResponse =
        await clickPesaRequest(
          "POST",
          "/payments/preview-ussd-push-request",
          previewPayload
        );
    } catch (error) {
      await supabase
        .from("transactions")
        .update({
          status: "failed",
          admin_notes:
            "ClickPesa preview request failed.",
          updated_at:
            new Date().toISOString(),
        })
        .eq("id", transaction.id);

      return res.status(502).json({
        success: false,
        message:
          "ClickPesa could not preview the mobile-money payment.",
        transactionId: transaction.id,
        error:
          error.response?.data ||
          error.message,
      });
    }

    const initiatePayload = {
      amount: String(Math.round(totalAmount)),
      currency: "TZS",
      orderReference,
      phoneNumber: cleanedPhone,
    };

    initiatePayload.checksum =
      createPayloadChecksum(
        CLICKPESA_CHECKSUM_KEY,
        initiatePayload
      );

    let clickPesaResponse;

    try {
      clickPesaResponse =
        await clickPesaRequest(
          "POST",
          "/payments/initiate-ussd-push-request",
          initiatePayload
        );
    } catch (error) {
      await supabase
        .from("transactions")
        .update({
          status: "failed",
          admin_notes:
            "ClickPesa USSD-PUSH initiation failed.",
          updated_at:
            new Date().toISOString(),
        })
        .eq("id", transaction.id);

      return res.status(502).json({
        success: false,
        message:
          "ClickPesa could not start the mobile-money payment.",
        transactionId: transaction.id,
        error:
          error.response?.data ||
          error.message,
      });
    }

    const clickPesaData =
      clickPesaResponse.data;

    const clickPesaReference =
      clickPesaData?.id ||
      clickPesaData?.paymentReference ||
      clickPesaData?.orderReference ||
      orderReference;

    const { error: updateError } =
      await supabase
        .from("transactions")
        .update({
          clickpesa_reference:
            clickPesaReference,
          status: "pending",
          updated_at:
            new Date().toISOString(),
        })
        .eq("id", transaction.id);

    if (updateError) {
      console.error(
        "Could not save ClickPesa reference:",
        updateError.message
      );
    }

    return res.status(200).json({
      success: true,
      message:
        "Payment request sent. Please enter your mobile-money PIN.",
      transactionId: transaction.id,
      orderReference,
      clickpesaReference,
      amount: numericAmount,
      feePercentage,
      feeAmount,
      totalAmount,
      phoneNumber: cleanedPhone,
      cryptoCurrency: crypto_currency,
      cryptoNetwork: crypto_network,
      mobileNetwork: mobile_network,
      cryptoAddress: crypto_address,
      stkPushSent: true,
      clickPesaPreview: previewResponse.data,
      clickPesaResponse: clickPesaData,
    });
  } catch (error) {
    console.error(
      "Deposit error:",
      error.response?.data ||
        error.message
    );

    return res.status(500).json({
      success: false,
      message:
        "An unexpected error occurred while starting the deposit.",
    });
  }
}

app.post(
  "/api/deposit/initiate",
  initiateDeposit
);

app.post(
  "/api/payments/deposit",
  initiateDeposit
);

/* =========================================================
   TEMP TEST — CREATE USER + SEND STK PUSH
   REMOVE THIS ENDPOINT AFTER TESTING
   ========================================================= */

app.post(
  "/api/test/create-user-and-stk",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        phone_number,
        amount,
        mobile_network = "Vodacom",
      } = req.body || {};

      if (!phone_number) {
        return res.status(400).json({
          success: false,
          message: "Phone number is required.",
        });
      }

      if (!amount || Number(amount) <= 0) {
        return res.status(400).json({
          success: false,
          message: "A valid amount is required.",
        });
      }

      /* -----------------------------------------------------
         1. CLEAN PHONE NUMBER
         ----------------------------------------------------- */

      const cleanedPhone = cleanPhoneNumber(phone_number);

      if (!cleanedPhone.startsWith("255")) {
        return res.status(400).json({
          success: false,
          message: "Invalid Tanzania phone number.",
        });
      }

      /* -----------------------------------------------------
         2. CREATE A SUPABASE AUTH USER
         ----------------------------------------------------- */

      const testEmail =
        `test_${Date.now()}@swiftfx.test`;

      const testPassword =
        `SwiftFXTest_${Date.now()}!`;

      const {
        data: authData,
        error: authError,
      } = await supabase.auth.admin.createUser({
        email: testEmail,
        password: testPassword,
        email_confirm: true,
      });

      if (authError) {
        console.error(
          "Test Supabase user creation failed:",
          authError.message
        );

        return res.status(500).json({
          success: false,
          message: "Could not create Supabase user.",
          error: authError.message,
        });
      }

      const userId = authData.user.id;

      /* -----------------------------------------------------
         3. GENERATE CLICKPESA-SAFE ORDER REFERENCE
         ----------------------------------------------------- */

      const orderReference =
  `SW${Date.now().toString().slice(-12)}`;

      /* -----------------------------------------------------
         4. CREATE CLICKPESA PREVIEW REQUEST
         ----------------------------------------------------- */

      const previewPayload = {
        amount: String(Math.round(Number(amount))),
        currency: "TZS",
        orderReference,
        phoneNumber: cleanedPhone,
        fetchSenderDetails: false,
      };

      previewPayload.checksum =
        createPayloadChecksum(
          CLICKPESA_CHECKSUM_KEY,
          previewPayload
        );

      let previewResponse;

      try {
        previewResponse =
          await clickPesaRequest(
            "POST",
            "/payments/preview-ussd-push-request",
            previewPayload
          );
      } catch (error) {
        console.error(
          "ClickPesa test preview failed:",
          error.response?.data || error.message
        );

        return res.status(502).json({
          success: false,
          message: "ClickPesa preview failed.",
          userId,
          testEmail,
          error:
            error.response?.data ||
            error.message,
        });
      }

      /* -----------------------------------------------------
         5. INITIATE STK PUSH
         ----------------------------------------------------- */

      const initiatePayload = {
        amount: String(Math.round(Number(amount))),
        currency: "TZS",
        orderReference,
        phoneNumber: cleanedPhone,
      };

      initiatePayload.checksum =
        createPayloadChecksum(
          CLICKPESA_CHECKSUM_KEY,
          initiatePayload
        );

      let clickPesaResponse;

      try {
        clickPesaResponse =
          await clickPesaRequest(
            "POST",
            "/payments/initiate-ussd-push-request",
            initiatePayload
          );
      } catch (error) {
        console.error(
          "ClickPesa test STK initiation failed:",
          error.response?.data || error.message
        );

        return res.status(502).json({
          success: false,
          message: "ClickPesa STK Push failed.",
          userId,
          testEmail,
          orderReference,
          error:
            error.response?.data ||
            error.message,
        });
      }

      /* -----------------------------------------------------
         6. RETURN EVERYTHING
         ----------------------------------------------------- */

      return res.status(200).json({
        success: true,
        message:
          "Supabase test user created and STK Push sent.",
        userId,
        testEmail,
        testPassword,
        phoneNumber: cleanedPhone,
        mobileNetwork,
        amount: Number(amount),
        orderReference,
        clickPesaPreview:
          previewResponse.data,
        clickPesaResponse:
          clickPesaResponse.data,
      });

    } catch (error) {
      console.error(
        "Create user + STK test error:",
        error.response?.data ||
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not create test user and send STK Push.",
        error:
          error.response?.data ||
          error.message,
      });
    }
  }
);

/* =========================================================
   CLICKPESA PAYMENT STATUS
   ========================================================= */

async function getPaymentStatus(req, res) {
  try {
    const { orderReference } = req.params;

    if (!orderReference) {
      return res.status(400).json({
        success: false,
        message: "Order reference is required.",
      });
    }

    const response =
      await clickPesaRequest(
        "GET",
        `/payments/${encodeURIComponent(
          orderReference
        )}`
      );

    const payments =
      Array.isArray(response.data)
        ? response.data
        : response.data?.data ||
          response.data?.payments ||
          [];

    const payment =
      payments.length > 0
        ? payments[0]
        : response.data;

    const localStatus =
      mapClickPesaStatus(
        payment?.status
      );

    /*
      Never downgrade a transaction that has already
      progressed beyond fiat_received.
    */
    const { data: existing } =
      await supabase
        .from("transactions")
        .select("id,status")
        .eq("id", orderReference)
        .maybeSingle();

    const advancedStatuses = [
      "crypto_sent",
      "crypto_received",
      "mobile_money_sent",
      "completed",
    ];

    if (
      existing &&
      advancedStatuses.includes(existing.status) &&
      localStatus !== "failed"
    ) {
      return res.json({
        success: true,
        orderReference,
        status: payment?.status || null,
        localStatus: existing.status,
        payment,
      });
    }

    const { error: updateError } =
      await supabase
        .from("transactions")
        .update({
          status: localStatus,
          updated_at:
            new Date().toISOString(),
        })
        .eq("id", orderReference);

    if (updateError) {
      console.error(
        "Local payment status update failed:",
        updateError.message
      );
    }

    return res.json({
      success: true,
      orderReference,
      status: payment?.status || null,
      localStatus,
      payment,
    });
  } catch (error) {
    console.error(
      "Payment status error:",
      error.response?.data ||
        error.message
    );

    return res.status(502).json({
      success: false,
      message:
        "Could not retrieve payment status from ClickPesa.",
      error:
        error.response?.data ||
        error.message,
    });
  }
}

app.get(
  "/api/payments/status/:orderReference",
  getPaymentStatus
);

/* =========================================================
   CLICKPESA WEBHOOK
   ========================================================= */

app.post(
  "/api/clickpesa/webhook",
  async (req, res) => {
    try {
      const payload = req.body || {};

      console.log(
        "ClickPesa webhook received:",
        payload
      );

      if (!verifyChecksum(payload)) {
        console.error(
          "Invalid ClickPesa webhook checksum."
        );

        return res.status(401).json({
          success: false,
          message: "Invalid webhook checksum.",
        });
      }

      const orderReference =
        payload?.orderReference ||
        payload?.reference ||
        payload?.order_reference;

      if (!orderReference) {
        return res.status(400).json({
          success: false,
          message: "Order reference missing.",
        });
      }

      const rawStatus =
        payload?.status ||
        payload?.transaction_status ||
        payload?.paymentStatus ||
        "";

      const localStatus =
        mapClickPesaStatus(rawStatus);

      /*
        First try our transaction UUID.
      */
      const { data: byId } =
        await supabase
          .from("transactions")
          .select("id,status,type")
          .eq("id", orderReference)
          .maybeSingle();

      let transaction = byId;

      /*
        If ClickPesa used its own reference, find the
        transaction using clickpesa_reference.
      */
      if (!transaction) {
        const { data: byReference } =
          await supabase
            .from("transactions")
            .select("id,status,type")
            .eq(
              "clickpesa_reference",
              orderReference
            )
            .maybeSingle();

        transaction = byReference;
      }

      if (!transaction) {
        console.error(
          "Webhook transaction not found:",
          orderReference
        );

        /*
          Return 200 so ClickPesa does not repeatedly
          resend a webhook for an unknown local record.
        */
        return res.status(200).json({
          success: false,
          message:
            "Webhook received, but transaction was not found.",
        });
      }

      /*
        A successful ClickPesa collection only proves
        that fiat was received. It must never directly
        mark a crypto transaction as completed.
      */
      const advancedStatuses = [
        "crypto_sent",
        "crypto_received",
        "mobile_money_sent",
        "completed",
      ];

      if (
        advancedStatuses.includes(
          transaction.status
        ) &&
        localStatus !== "failed"
      ) {
        return res.status(200).json({
          success: true,
          message:
            "Webhook received; transaction already progressed.",
        });
      }

      const updateData = {
        status: localStatus,
        updated_at:
          new Date().toISOString(),
      };

      if (localStatus === "fiat_received") {
        updateData.admin_notes =
          "Mobile-money payment confirmed by ClickPesa. Awaiting admin crypto settlement.";
      }

      const { error } =
        await supabase
          .from("transactions")
          .update(updateData)
          .eq("id", transaction.id);

      if (error) {
        console.error(
          "Webhook transaction update failed:",
          error.message
        );

        return res.status(500).json({
          success: false,
          message: "Could not update transaction.",
        });
      }

      return res.status(200).json({
        success: true,
        message:
          "Webhook processed successfully.",
      });
    } catch (error) {
      console.error(
        "Webhook error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Webhook processing failed.",
      });
    }
  }
);

/* =========================================================
   WITHDRAWAL
   ========================================================= */

async function initiateWithdrawal(req, res) {
  try {
    const {
      user_id,
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number,
      amount,
    } = req.body || {};

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    if (!crypto_currency) {
      return res.status(400).json({
        success: false,
        message: "Crypto currency is required.",
      });
    }

    if (!crypto_network) {
      return res.status(400).json({
        success: false,
        message: "Crypto network is required.",
      });
    }

    if (!mobile_network) {
      return res.status(400).json({
        success: false,
        message: "Mobile network is required.",
      });
    }

    if (!phone_number) {
      return res.status(400).json({
        success: false,
        message: "Phone number is required.",
      });
    }

    if (!isPositiveNumber(amount)) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid withdrawal amount.",
      });
    }

    const numericAmount = roundMoney(amount);

    const feePercentage =
      await getFeePercentage(
        "withdraw_fee_percentage",
        2
      );

    const feeAmount = roundMoney(
      numericAmount * (feePercentage / 100)
    );

    const amountAfterFee = roundMoney(
      numericAmount - feeAmount
    );

    if (amountAfterFee <= 0) {
      return res.status(400).json({
        success: false,
        message:
          "Withdrawal amount is too small after fees.",
      });
    }

    const cleanedPhone =
      cleanPhoneNumber(phone_number);

    if (!/^255\d{9}$/.test(cleanedPhone)) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid Tanzanian mobile number.",
      });
    }

    /*
      The crypto address is intentionally not created
      here. The admin will provide the address after
      reviewing the withdrawal request.
    */
    const transactionData = {
      user_id,
      type: "withdrawal",
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number: cleanedPhone,
      amount: numericAmount,
      fee_percentage: feePercentage,
      total_amount: amountAfterFee,
      crypto_address:
        "PENDING_ADMIN_ADDRESS",
      status: "pending",
      admin_notes:
        "Withdrawal received. Awaiting admin crypto deposit address.",
    };

    const {
      data: transaction,
      error,
    } = await supabase
      .from("transactions")
      .insert(transactionData)
      .select()
      .single();

    if (error) {
      console.error(
        "Withdrawal creation failed:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message: "Could not create withdrawal.",
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "Withdrawal request submitted successfully. Awaiting crypto deposit instructions.",
      transactionId: transaction.id,
      amount: numericAmount,
      feePercentage,
      feeAmount,
      amountAfterFee,
      phoneNumber: cleanedPhone,
      cryptoCurrency: crypto_currency,
      cryptoNetwork: crypto_network,
      mobileNetwork: mobile_network,
      status: "pending",
    });
  } catch (error) {
    console.error(
      "Withdrawal error:",
      error.message
    );

    return res.status(500).json({
      success: false,
      message:
        "An unexpected error occurred while creating the withdrawal.",
    });
  }
}

app.post(
  "/api/withdraw/initiate",
  initiateWithdrawal
);

app.post(
  "/api/payments/withdraw",
  initiateWithdrawal
);

/* =========================================================
   ADMIN — LIST TRANSACTIONS
   ========================================================= */

app.get(
  "/api/admin/transactions",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        status,
        type,
        limit = 100,
      } = req.query;

      const safeLimit = Math.min(
        Math.max(Number(limit) || 100, 1),
        500
      );

      let query = supabase
        .from("transactions")
        .select("*")
        .order("created_at", {
          ascending: false,
        })
        .limit(safeLimit);

      if (status) {
        query = query.eq("status", status);
      }

      if (type) {
        query = query.eq("type", type);
      }

      const { data, error } = await query;

      if (error) {
        console.error(
          "Admin transaction list failed:",
          error.message
        );

        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transactions.",
        });
      }

      return res.json({
        success: true,
        transactions: data || [],
      });
    } catch (error) {
      console.error(
        "Admin transaction list error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not retrieve transactions.",
      });
    }
  }
);

/* =========================================================
   ADMIN — GET ONE TRANSACTION
   ========================================================= */

app.get(
  "/api/admin/transactions/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!isValidTransactionId(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid transaction ID.",
        });
      }

      const { data, error } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      return res.json({
        success: true,
        transaction: data,
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message:
          "Could not retrieve transaction.",
      });
    }
  }
);

/* =========================================================
   ADMIN — DEPOSIT: MARK CRYPTO SENT
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/deposit/crypto-sent",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        crypto_tx_hash,
        admin_notes,
      } = req.body || {};

      if (!isValidTransactionId(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid transaction ID.",
        });
      }

      if (
        !crypto_tx_hash ||
        !String(crypto_tx_hash).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Crypto transaction hash is required.",
        });
      }

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "deposit") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a deposit.",
        });
      }

      if (
        ![
          "fiat_received",
          "crypto_sent",
        ].includes(transaction.status)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "The deposit must have confirmed mobile-money payment before crypto can be marked as sent.",
          currentStatus: transaction.status,
        });
      }

      const updateData = {
        crypto_tx_hash:
          String(crypto_tx_hash).trim(),
        crypto_sent_at:
          new Date().toISOString(),
        status: "crypto_sent",
        updated_at:
          new Date().toISOString(),
      };

      if (admin_notes) {
        updateData.admin_notes =
          String(admin_notes).trim();
      }

      const { data, error } =
        await supabase
          .from("transactions")
          .update(updateData)
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not update deposit.",
        });
      }

      return res.json({
        success: true,
        message:
          "Deposit marked as crypto sent.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin deposit crypto-sent error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not update deposit.",
      });
    }
  }
);

/* =========================================================
   ADMIN — DEPOSIT: COMPLETE
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/deposit/complete",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "deposit") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a deposit.",
        });
      }

      if (
        transaction.status !== "crypto_sent" ||
        !transaction.crypto_tx_hash
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Crypto must be marked as sent with a transaction hash before completing the deposit.",
          currentStatus: transaction.status,
        });
      }

      const now = new Date().toISOString();

      const { data, error } =
        await supabase
          .from("transactions")
          .update({
            status: "completed",
            completed_at: now,
            updated_at: now,
          })
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not complete deposit.",
        });
      }

      return res.json({
        success: true,
        message: "Deposit completed.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin deposit completion error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not complete deposit.",
      });
    }
  }
);

/* =========================================================
   ADMIN — WITHDRAWAL: PROVIDE CRYPTO ADDRESS
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/withdrawal/crypto-address",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        admin_crypto_address,
        admin_notes,
      } = req.body || {};

      if (
        !admin_crypto_address ||
        !String(admin_crypto_address).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Crypto deposit address is required.",
        });
      }

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "withdrawal") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a withdrawal.",
        });
      }

      if (
        ![
          "pending",
          "crypto_address_provided",
        ].includes(transaction.status)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "The crypto address can only be provided while the withdrawal is awaiting the customer's crypto payment.",
          currentStatus: transaction.status,
        });
      }

      const address =
        String(admin_crypto_address).trim();

      const updateData = {
        admin_crypto_address: address,
        crypto_address: address,
        status: "crypto_address_provided",
        updated_at:
          new Date().toISOString(),
      };

      if (admin_notes) {
        updateData.admin_notes =
          String(admin_notes).trim();
      }

      const { data, error } =
        await supabase
          .from("transactions")
          .update(updateData)
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not save crypto address.",
        });
      }

      return res.json({
        success: true,
        message:
          "Crypto deposit address provided to the withdrawal transaction.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin withdrawal address error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not provide crypto address.",
      });
    }
  }
);

/* =========================================================
   ADMIN — WITHDRAWAL: MARK CRYPTO RECEIVED
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/withdrawal/crypto-received",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        crypto_tx_hash,
        admin_notes,
      } = req.body || {};

      if (
        !crypto_tx_hash ||
        !String(crypto_tx_hash).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Crypto transaction hash is required.",
        });
      }

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "withdrawal") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a withdrawal.",
        });
      }

      if (
        ![
          "crypto_address_provided",
          "crypto_received",
        ].includes(transaction.status)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "The withdrawal must first have an admin crypto address.",
          currentStatus: transaction.status,
        });
      }

      const updateData = {
        crypto_tx_hash:
          String(crypto_tx_hash).trim(),
        crypto_received_at:
          new Date().toISOString(),
        status: "crypto_received",
        updated_at:
          new Date().toISOString(),
      };

      if (admin_notes) {
        updateData.admin_notes =
          String(admin_notes).trim();
      }

      const { data, error } =
        await supabase
          .from("transactions")
          .update(updateData)
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not mark crypto as received.",
        });
      }

      return res.json({
        success: true,
        message:
          "Crypto marked as received.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin withdrawal crypto-received error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not mark crypto as received.",
      });
    }
  }
);

/* =========================================================
   ADMIN — WITHDRAWAL: MARK MOBILE MONEY SENT
   ========================================================= */

/*
  We intentionally do NOT invent a ClickPesa payout API
  endpoint or payload here.

  The admin can make the payout through the ClickPesa
  dashboard/API workflow that is actually enabled for
  the merchant account, then use this endpoint to record
  the payout in SwiftFX.

  Once ClickPesa's exact payout API contract is supplied,
  this endpoint can be changed to trigger the payout
  automatically.
*/

app.post(
  "/api/admin/transactions/:id/withdrawal/mobile-money-sent",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        payout_reference,
        admin_notes,
      } = req.body || {};

      if (
        !payout_reference ||
        !String(payout_reference).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Mobile-money payout reference is required.",
        });
      }

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "withdrawal") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a withdrawal.",
        });
      }

      if (
        ![
          "crypto_received",
          "mobile_money_sent",
        ].includes(transaction.status)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Crypto must be received before mobile money can be marked as sent.",
          currentStatus: transaction.status,
        });
      }

      const now = new Date().toISOString();

      const updateData = {
        status: "mobile_money_sent",
        mobile_money_sent_at: now,
        updated_at: now,
        admin_notes:
          admin_notes
            ? String(admin_notes).trim()
            : `Mobile-money payout reference: ${String(
                payout_reference
              ).trim()}`,
      };

      /*
        We store the payout reference in admin_notes because
        the current Supabase schema does not contain a separate
        payout_reference column.
      */

      const { data, error } =
        await supabase
          .from("transactions")
          .update(updateData)
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not record mobile-money payout.",
        });
      }

      return res.json({
        success: true,
        message:
          "Mobile-money payout recorded as sent.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin mobile-money payout error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not record mobile-money payout.",
      });
    }
  }
);

/* =========================================================
   ADMIN — WITHDRAWAL: COMPLETE
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/withdrawal/complete",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.type !== "withdrawal") {
        return res.status(400).json({
          success: false,
          message:
            "This transaction is not a withdrawal.",
        });
      }

      if (
        transaction.status !==
        "mobile_money_sent"
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Mobile money must be marked as sent before completing the withdrawal.",
          currentStatus: transaction.status,
        });
      }

      const now = new Date().toISOString();

      const { data, error } =
        await supabase
          .from("transactions")
          .update({
            status: "completed",
            completed_at: now,
            updated_at: now,
          })
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not complete withdrawal.",
        });
      }

      return res.json({
        success: true,
        message: "Withdrawal completed.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin withdrawal completion error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not complete withdrawal.",
      });
    }
  }
);

/* =========================================================
   ADMIN — CANCEL TRANSACTION
   ========================================================= */

app.post(
  "/api/admin/transactions/:id/cancel",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { admin_notes } = req.body || {};

      const { data: transaction, error: findError } =
        await supabase
          .from("transactions")
          .select("*")
          .eq("id", id)
          .maybeSingle();

      if (findError) {
        return res.status(500).json({
          success: false,
          message:
            "Could not retrieve transaction.",
        });
      }

      if (!transaction) {
        return res.status(404).json({
          success: false,
          message: "Transaction not found.",
        });
      }

      if (transaction.status === "completed") {
        return res.status(400).json({
          success: false,
          message:
            "A completed transaction cannot be cancelled.",
        });
      }

      const notes =
        admin_notes
          ? String(admin_notes).trim()
          : "Transaction cancelled by admin.";

      const { data, error } =
        await supabase
          .from("transactions")
          .update({
            status: "cancelled",
            admin_notes: notes,
            updated_at:
              new Date().toISOString(),
          })
          .eq("id", id)
          .select()
          .single();

      if (error) {
        return res.status(500).json({
          success: false,
          message:
            "Could not cancel transaction.",
        });
      }

      return res.json({
        success: true,
        message: "Transaction cancelled.",
        transaction: data,
      });
    } catch (error) {
      console.error(
        "Admin cancellation error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not cancel transaction.",
      });
    }
  }
);

/* =========================================================
   ADMIN — CLICKPESA CONNECTION TEST
   ========================================================= */

app.get(
  "/api/admin/test-clickpesa-token",
  requireAdmin,
  async (req, res) => {
    try {
      const token = await getClickPesaToken();

      return res.json({
        ok: true,
        clickpesaConnected: true,
        tokenReceived: Boolean(token),
      });
    } catch (error) {
      console.error(
        "ClickPesa token test failed:",
        error.response?.data ||
          error.message
      );

      return res.status(500).json({
        ok: false,
        clickpesaConnected: false,
        error:
          error.response?.data ||
          error.message,
      });
    }
  }
);

/* =========================================================
   GLOBAL ERROR HANDLER
   ========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "Unhandled server error:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Internal server error.",
    });
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

if (missingEnvironmentVariables.length > 0) {
  console.error(
    "Server will not start until the required environment variables are configured."
  );
  process.exit(1);
}

app.listen(PORT, () => {
  console.log(
    `SwiftFX server running on port ${PORT}`
  );

  console.log(
    `ClickPesa API: ${CLICKPESA_BASE_URL}`
  );
});
