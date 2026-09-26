const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(cors());
app.use(express.json());

/* =========================================================
   ENVIRONMENT VARIABLES
   ========================================================= */

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const CLICKPESA_BASE_URL =
  process.env.CLICKPESA_BASE_URL ||
  "https://api.clickpesa.com/third-parties";

const CLICKPESA_API_KEY =
  process.env.CLICKPESA_API_KEY;

const CLICKPESA_CLIENT_ID =
  process.env.CLICKPESA_CLIENT_ID;

const CLICKPESA_CHECKSUM_KEY =
  process.env.CLICKPESA_CHECKSUM_KEY;


/* =========================================================
   BASIC CONFIGURATION CHECK
   ========================================================= */

const requiredEnvironmentVariables = [
  ["SUPABASE_URL", SUPABASE_URL],
  ["SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY],
  ["CLICKPESA_API_KEY", CLICKPESA_API_KEY],
  ["CLICKPESA_CLIENT_ID", CLICKPESA_CLIENT_ID],
  ["CLICKPESA_CHECKSUM_KEY", CLICKPESA_CHECKSUM_KEY],
];

const missingEnvironmentVariables =
  requiredEnvironmentVariables
    .filter(([, value]) => !value)
    .map(([name]) => name);

if (missingEnvironmentVariables.length > 0) {
  console.error(
    "Missing environment variables:",
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

  // Reuse existing token while it is still valid.
  // We refresh slightly early.
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

    // ClickPesa says the JWT is valid for 1 hour.
    // Keep it for 55 minutes.
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

    // If token expired unexpectedly, clear it so
    // the next request generates a fresh token.
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

/*
  ClickPesa checksum rules:

  1. Remove "checksum" and "checksumMethod".
  2. Recursively sort object keys alphabetically.
  3. Convert to compact JSON.
  4. HMAC-SHA256 using the checksum secret key.
  5. Return hexadecimal digest.
*/

function canonicalize(obj) {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(canonicalize);
  }

  return Object.keys(obj)
    .sort()
    .reduce((result, key) => {
      result[key] = canonicalize(obj[key]);
      return result;
    }, {});
}


function createPayloadChecksum(
  checksumKey,
  payload
) {
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
    .createHmac(
      "sha256",
      checksumKey
    )
    .update(payloadString)
    .digest("hex");
}


/* =========================================================
   PHONE NUMBER CLEANING
   ========================================================= */

function cleanPhoneNumber(phone) {
  if (!phone) {
    return "";
  }

  let cleaned = String(phone)
    .trim()
    .replace(/\s+/g, "")
    .replace(/-/g, "");

  // Convert Tanzania local format:
  // 0712345678 -> 255712345678
  if (cleaned.startsWith("0")) {
    cleaned = "255" + cleaned.substring(1);
  }

  // Convert +255712345678 -> 255712345678
  if (cleaned.startsWith("+")) {
    cleaned = cleaned.substring(1);
  }

  return cleaned;
}


/* =========================================================
   FEE HELPER
   ========================================================= */

async function getFeePercentage(settingName, defaultValue) {
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
   HEALTH CHECK
   ========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
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
    } = req.body;

    /* -----------------------------------------------
       VALIDATION
       ----------------------------------------------- */

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

    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      numericAmount <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid deposit amount.",
      });
    }

    /* -----------------------------------------------
       GET DEPOSIT FEE
       ----------------------------------------------- */

    const feePercentage =
      await getFeePercentage(
        "deposit_fee_percentage",
        2.5
      );

    const feeAmount =
      numericAmount * (feePercentage / 100);

    const totalAmount =
      numericAmount + feeAmount;

    /* -----------------------------------------------
       CLEAN PHONE
       ----------------------------------------------- */

    const cleanedPhone =
      cleanPhoneNumber(phone_number);

    if (
      !/^255\d{9}$/.test(cleanedPhone)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid Tanzanian mobile number.",
      });
    }

    /* -----------------------------------------------
       CREATE LOCAL TRANSACTION
       ----------------------------------------------- */

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
      crypto_address,
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
        message:
          "Could not create the transaction.",
      });
    }

    /* -----------------------------------------------
       CLICKPESA ORDER REFERENCE

       We use our transaction UUID as the
       ClickPesa orderReference.
       ----------------------------------------------- */

    const orderReference =
      transaction.id;

    /* -----------------------------------------------
       PREVIEW USSD PUSH
       ----------------------------------------------- */

    const previewPayload = {
      amount: String(
        Math.round(totalAmount)
      ),
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
        "ClickPesa preview failed."
      );

      await supabase
        .from("transactions")
        .update({
          status: "failed",
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

    /* -----------------------------------------------
       INITIATE USSD PUSH
       ----------------------------------------------- */

    const initiatePayload = {
      amount: String(
        Math.round(totalAmount)
      ),
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
        "ClickPesa USSD-PUSH initiation failed."
      );

      await supabase
        .from("transactions")
        .update({
          status: "failed",
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

    /* -----------------------------------------------
       GET CLICKPESA RESPONSE
       ----------------------------------------------- */

    const clickPesaData =
      clickPesaResponse.data;

    const clickPesaReference =
      clickPesaData?.id ||
      clickPesaData?.paymentReference ||
      clickPesaData?.orderReference ||
      orderReference;

    /* -----------------------------------------------
       SAVE CLICKPESA REFERENCE
       ----------------------------------------------- */

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

    /* -----------------------------------------------
       SUCCESS RESPONSE

       IMPORTANT:
       This means ClickPesa accepted the
       USSD-PUSH request.

       It does NOT mean the customer has
       successfully paid yet.

       The final payment status must come
       from ClickPesa.
       ----------------------------------------------- */

    return res.status(200).json({
      success: true,
      message:
        "Payment request sent. Please enter your mobile-money PIN.",
      transactionId: transaction.id,
      orderReference,
      clickpesaReference:
        clickPesaReference,
      amount: numericAmount,
      feePercentage,
      feeAmount,
      totalAmount,
      phoneNumber: cleanedPhone,
      cryptoCurrency:
        crypto_currency,
      cryptoNetwork:
        crypto_network,
      mobileNetwork:
        mobile_network,
      cryptoAddress:
        crypto_address,
      stkPushSent: true,
      clickPesaPreview:
        previewResponse.data,
      clickPesaResponse:
        clickPesaData,
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
   CHECK CLICKPESA PAYMENT STATUS
   ========================================================= */

async function getPaymentStatus(req, res) {
  try {
    const {
      orderReference,
    } = req.params;

    if (!orderReference) {
      return res.status(400).json({
        success: false,
        message:
          "Order reference is required.",
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

    let localStatus = "pending";

    const status = String(
      payment?.status || ""
    ).toUpperCase();

    if (
      [
        "SUCCESS",
        "SUCCESSFUL",
        "COMPLETED",
        "PAID",
      ].includes(status)
    ) {
      localStatus = "fiat_received";
    }

    if (
      [
        "FAILED",
        "CANCELLED",
        "CANCELED",
        "REJECTED",
        "DECLINED",
      ].includes(status)
    ) {
      localStatus = "failed";
    }

    /* -----------------------------------------------
       Update our local transaction
       ----------------------------------------------- */

    const { error: updateError } =
      await supabase
        .from("transactions")
        .update({
          status: localStatus,
          updated_at:
            new Date().toISOString(),
        })
        .eq(
          "id",
          orderReference
        );

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
      const payload = req.body;

      console.log(
        "ClickPesa webhook received:",
        payload
      );

      /*
        ClickPesa webhook payloads are signed using
        the same checksum method.

        We verify the checksum when ClickPesa
        provides one.
      */

      if (payload?.checksum) {
        const receivedChecksum =
          payload.checksum;

        const calculatedChecksum =
          createPayloadChecksum(
            CLICKPESA_CHECKSUM_KEY,
            payload
          );

        const checksumMatches =
          receivedChecksum.length ===
            calculatedChecksum.length &&
          crypto.timingSafeEqual(
            Buffer.from(
              receivedChecksum,
              "utf8"
            ),
            Buffer.from(
              calculatedChecksum,
              "utf8"
            )
          );

        if (!checksumMatches) {
          console.error(
            "Invalid ClickPesa webhook checksum."
          );

          return res.status(401).json({
            success: false,
            message:
              "Invalid webhook checksum.",
          });
        }
      }

      /* ---------------------------------------------
         Find order reference
         --------------------------------------------- */

      const orderReference =
        payload?.orderReference ||
        payload?.reference ||
        payload?.order_reference;

      if (!orderReference) {
        console.error(
          "Webhook did not contain an order reference."
        );

        return res.status(400).json({
          success: false,
          message:
            "Order reference missing.",
        });
      }

      /* ---------------------------------------------
         Determine payment status
         --------------------------------------------- */

      const rawStatus =
        payload?.status ||
        payload?.transaction_status ||
        payload?.paymentStatus ||
        "";

      const status =
        String(rawStatus).toUpperCase();

      let localStatus = "pending";

      if (
        [
          "SUCCESS",
          "SUCCESSFUL",
          "COMPLETED",
          "PAID",
        ].includes(status)
      ) {
        localStatus = "fiat_received";
      }

      if (
        [
          "FAILED",
          "CANCELLED",
          "CANCELED",
          "REJECTED",
          "DECLINED",
        ].includes(status)
      ) {
        localStatus = "failed";
      }

      /* ---------------------------------------------
         Update transaction
         --------------------------------------------- */

      const { data, error } =
        await supabase
          .from("transactions")
          .update({
            status: localStatus,
            updated_at:
              new Date().toISOString(),
          })
          .eq(
            "id",
            orderReference
          )
          .select();

      if (error) {
        console.error(
          "Webhook transaction update failed:",
          error.message
        );

        return res.status(500).json({
          success: false,
          message:
            "Could not update transaction.",
        });
      }

      /* ---------------------------------------------
         Also try clickpesa_reference

         This gives us a second way to locate the
         transaction if ClickPesa sends a reference
         different from our UUID.
         --------------------------------------------- */

      if (!data || data.length === 0) {
        const {
          error: referenceUpdateError,
        } = await supabase
          .from("transactions")
          .update({
            status: localStatus,
            updated_at:
              new Date().toISOString(),
          })
          .eq(
            "clickpesa_reference",
            orderReference
          );

        if (referenceUpdateError) {
          console.error(
            "Reference transaction update failed:",
            referenceUpdateError.message
          );
        }
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
    } = req.body;

    /* -----------------------------------------------
       VALIDATION
       ----------------------------------------------- */

    if (!user_id) {
      return res.status(400).json({
        success: false,
        message: "User ID is required.",
      });
    }

    if (!crypto_currency) {
      return res.status(400).json({
        success: false,
        message:
          "Crypto currency is required.",
      });
    }

    if (!crypto_network) {
      return res.status(400).json({
        success: false,
        message:
          "Crypto network is required.",
      });
    }

    if (!mobile_network) {
      return res.status(400).json({
        success: false,
        message:
          "Mobile network is required.",
      });
    }

    if (!phone_number) {
      return res.status(400).json({
        success: false,
        message:
          "Phone number is required.",
      });
    }

    const numericAmount = Number(amount);

    if (
      !Number.isFinite(numericAmount) ||
      numericAmount <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid withdrawal amount.",
      });
    }

    /* -----------------------------------------------
       GET WITHDRAWAL FEE
       ----------------------------------------------- */

    const feePercentage =
      await getFeePercentage(
        "withdraw_fee_percentage",
        2
      );

    const feeAmount =
      numericAmount *
      (feePercentage / 100);

    const amountAfterFee =
      numericAmount - feeAmount;

    if (amountAfterFee <= 0) {
      return res.status(400).json({
        success: false,
        message:
          "Withdrawal amount is too small after fees.",
      });
    }

    const cleanedPhone =
      cleanPhoneNumber(phone_number);

    if (
      !/^255\d{9}$/.test(cleanedPhone)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Enter a valid Tanzanian mobile number.",
      });
    }

    /* -----------------------------------------------
       CREATE WITHDRAWAL TRANSACTION
       ----------------------------------------------- */

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
        "PENDING_DEPOSIT",
      status: "pending",
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
        message:
          "Could not create withdrawal.",
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "Withdrawal request submitted successfully.",
      transactionId:
        transaction.id,
      amount: numericAmount,
      feePercentage,
      feeAmount,
      amountAfterFee,
      phoneNumber: cleanedPhone,
      cryptoCurrency:
        crypto_currency,
      cryptoNetwork:
        crypto_network,
      mobileNetwork:
        mobile_network,
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
      message:
        "Internal server error.",
    });
  }
);


/* =========================================================
   START SERVER
   ========================================================= */
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    message: "SwiftFX backend is running"
  });
});

app.listen(PORT, () => {
  console.log(
    `SwiftFX server running on port ${PORT}`
  );

  console.log(
    `ClickPesa API: ${CLICKPESA_BASE_URL}`
  );

  if (
    missingEnvironmentVariables.length > 0
  ) {
    console.error(
      "WARNING: Missing environment variables:",
      missingEnvironmentVariables.join(", ")
    );
  }
});
