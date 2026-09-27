require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const CLICKPESA_BASE_URL = (process.env.CLICKPESA_BASE_URL || 'https://api.clickpesa.com/third-parties').replace(/\/+$/, '');
const CLICKPESA_CLIENT_ID = process.env.CLICKPESA_CLIENT_ID;
const CLICKPESA_API_KEY = process.env.CLICKPESA_API_KEY;
const CLICKPESA_CHECKSUM_KEY = process.env.CLICKPESA_CHECKSUM_KEY;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false }
});

function normalizePhone(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('255')) return digits;
  if (digits.startsWith('0')) return '255' + digits.slice(1);
  return '255' + digits;
}

function generateOrderReference(customRef) {
  if (customRef) {
    const clean = String(customRef).replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    if (clean.length >= 6 && clean.length <= 20) return clean;
  }
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let suffix = '';
  for (let i = 0; i < 9; i++) {
    suffix += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return 'SFX' + suffix;
}

function canonicalizeObject(obj) {
  if (Array.isArray(obj)) {
    return obj.map(canonicalizeObject);
  } else if (obj !== null && typeof obj === 'object') {
    return Object.keys(obj)
      .sort()
      .reduce((acc, key) => {
        if (key !== 'checksum' && key !== 'checksumMethod' && obj[key] !== undefined) {
          acc[key] = canonicalizeObject(obj[key]);
        }
        return acc;
      }, {});
  }
  return obj;
}

function generateClickPesaChecksum(payload, secretKey) {
  if (!secretKey) return undefined;
  const canonical = canonicalizeObject(payload);
  const jsonString = JSON.stringify(canonical);
  return crypto.createHmac('sha256', secretKey).update(jsonString).digest('hex');
}

async function getClickPesaToken() {
  const response = await fetch(`${CLICKPESA_BASE_URL}/generate-token`, {
    method: 'POST',
    headers: {
      'client-id': CLICKPESA_CLIENT_ID,
      'api-key': CLICKPESA_API_KEY,
      'Accept': 'application/json'
    }
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.token) {
    throw new Error(data.message || data.error || `Failed to generate ClickPesa token (HTTP ${response.status})`);
  }
  return data.token.startsWith('Bearer ') ? data.token : `Bearer ${data.token}`;
}

async function getSettings() {
  const { data } = await supabase
    .from('app_settings')
    .select('*')
    .eq('id', 1)
    .single();

  return data || {
    id: 1,
    deposit_fee_percentage: 2.5,
    withdraw_fee_percentage: 2.0,
    usd_tzs_rate: 2580
  };
}

function requireAdminAuth(req, res, next) {
  const apiKey = req.headers['x-admin-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.admin_key;
  if (ADMIN_API_KEY && apiKey !== ADMIN_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid ADMIN_API_KEY' });
  }
  next();
}

// 1. HEALTH & SETTINGS
app.get(['/', '/health', '/api/health'], (req, res) => {
  res.json({ ok: true, success: true, service: 'SwiftFX Backend API' });
});

app.get('/api/settings', async (req, res) => {
  try {
    const settings = await getSettings();
    res.json({ success: true, settings });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/settings', requireAdminAuth, async (req, res) => {
  try {
    const { deposit_fee_percentage, withdraw_fee_percentage, usd_tzs_rate } = req.body;
    const updates = { id: 1, updated_at: new Date().toISOString() };
    if (deposit_fee_percentage !== undefined) updates.deposit_fee_percentage = Number(deposit_fee_percentage);
    if (withdraw_fee_percentage !== undefined) updates.withdraw_fee_percentage = Number(withdraw_fee_percentage);
    if (usd_tzs_rate !== undefined) updates.usd_tzs_rate = Number(usd_tzs_rate);

    const { data, error } = await supabase.from('app_settings').upsert(updates).select().single();
    if (error) throw error;
    res.json({ success: true, settings: data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. CLIENT ORDER TRACKING (Used by Client Frontend without needing Supabase keys)
app.get('/api/payments/track', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (!q) return res.status(400).json({ success: false, error: 'Query required' });

    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(q);
    let txn = null;

    if (isUUID) {
      const { data } = await supabase.from('transactions').select('*').eq('id', q).maybeSingle();
      txn = data;
    }

    if (!txn) {
      const { data } = await supabase
        .from('transactions')
        .select('*')
        .ilike('clickpesa_reference', q)
        .order('created_at', { ascending: false })
        .limit(1);
      if (data && data.length > 0) txn = data[0];
    }

    if (!txn) {
      const { data } = await supabase
        .from('transactions')
        .select('*')
        .eq('user_id', q)
        .order('created_at', { ascending: false })
        .limit(1);
      if (data && data.length > 0) txn = data[0];
    }

    if (!txn) return res.status(404).json({ success: false, error: 'Transaction not found' });
    return res.json({ success: true, transaction: txn });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/payments/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { data, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(15);

    if (error) throw error;
    return res.json({ success: true, transactions: data || [] });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 3. CLIENT DEPOSIT (Initiates ClickPesa USSD Push)
app.post('/api/payments/deposit', async (req, res) => {
  try {
    const {
      user_id,
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number,
      crypto_address,
      amount,
      orderReference
    } = req.body;

    if (!phone_number || !amount || !crypto_address) {
      return res.status(400).json({
        success: false,
        error: 'phone_number, amount, and crypto_address are required.'
      });
    }

    const settings = await getSettings();
    const feePercentage = Number(settings.deposit_fee_percentage || 2.5);
    const exchangeRate = Number(settings.usd_tzs_rate || 2580);

    const baseAmountUsd = Number(amount);
    const feeAmountUsd = Number((baseAmountUsd * (feePercentage / 100)).toFixed(4));
    const totalAmountUsd = Number((baseAmountUsd + feeAmountUsd).toFixed(4));
    const amountTzs = Math.max(1000, Math.round(totalAmountUsd * exchangeRate));

    const cleanPhone = normalizePhone(phone_number);
    const cleanRef = generateOrderReference(orderReference);
    const tempUserId = user_id || `guest_${crypto.randomUUID()}`;

    const bearerToken = await getClickPesaToken();

    const clickpesaPayload = {
      amount: String(amountTzs),
      currency: 'TZS',
      orderReference: cleanRef,
      phoneNumber: cleanPhone
    };

    if (CLICKPESA_CHECKSUM_KEY) {
      clickpesaPayload.checksum = generateClickPesaChecksum(clickpesaPayload, CLICKPESA_CHECKSUM_KEY);
    }

    const stkResponse = await fetch(`${CLICKPESA_BASE_URL}/payments/initiate-ussd-push-request`, {
      method: 'POST',
      headers: {
        'Authorization': bearerToken,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(clickpesaPayload)
    });

    const stkData = await stkResponse.json().catch(() => ({}));

    if (!stkResponse.ok) {
      return res.status(stkResponse.status).json({
        success: false,
        error: stkData.message || stkData.error || 'ClickPesa rejected the USSD push request.',
        details: stkData
      });
    }

    const now = new Date().toISOString();
    const { data: txn, error: dbError } = await supabase
      .from('transactions')
      .insert([{
        user_id: tempUserId,
        type: 'deposit',
        crypto_currency: crypto_currency || 'USDT',
        crypto_network: crypto_network || 'TRC20',
        mobile_network: mobile_network || 'Mobile Money',
        phone_number: cleanPhone,
        amount: baseAmountUsd,
        fee_percentage: feePercentage,
        fee_amount: feeAmountUsd,
        total_amount: totalAmountUsd,
        amount_tzs: amountTzs,
        crypto_address: crypto_address.trim(),
        status: 'pending_payment',
        clickpesa_reference: cleanRef,
        created_at: now,
        updated_at: now
      }])
      .select()
      .single();

    if (dbError) throw dbError;

    return res.json({
      success: true,
      stkPushSent: true,
      message: `USSD Push sent to +${cleanPhone} for ${amountTzs.toLocaleString()} TZS. Enter your PIN to confirm.`,
      transaction: txn
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || 'Internal server error during deposit initiation.'
    });
  }
});

// 4. CLICKPESA WEBHOOK (Detects Deposit & Alerts Admin App)
app.post(['/api/webhooks/clickpesa', '/webhooks/clickpesa', '/api/payments/webhook'], async (req, res) => {
  try {
    const body = req.body || {};
    const eventType = String(body.event || body.eventType || body.status || '').toUpperCase();
    const dataObj = body.data || body.transaction || body;
    const orderReference =
      dataObj.orderReference ||
      dataObj.order_reference ||
      dataObj.reference ||
      body.orderReference;

    const paymentStatus = String(dataObj.status || body.status || eventType).toUpperCase();

    if (!orderReference) {
      return res.status(200).json({ received: true });
    }

    const { data: txn } = await supabase
      .from('transactions')
      .select('*')
      .eq('clickpesa_reference', orderReference)
      .maybeSingle();

    if (!txn) {
      return res.status(200).json({ received: true });
    }

    const isSuccess =
      eventType.includes('RECEIVED') ||
      eventType.includes('SUCCESS') ||
      paymentStatus === 'SUCCESS' ||
      paymentStatus === 'SUCCESSFUL' ||
      paymentStatus === 'COMPLETED' ||
      paymentStatus === 'SETTLED';

    const isFailed =
      eventType.includes('FAILED') ||
      paymentStatus === 'FAILED' ||
      paymentStatus === 'REJECTED' ||
      paymentStatus === 'CANCELLED';

    if (isSuccess && txn.status !== 'completed') {
      const now = new Date().toISOString();
      const { data: updatedTxn } = await supabase
        .from('transactions')
        .update({ status: 'fiat_received', updated_at: now })
        .eq('id', txn.id)
        .select()
        .single();

      await supabase.from('admin_notifications').insert([{
        transaction_id: txn.id,
        type: 'deposit_webhook_confirmed',
        title: `New Confirmed Deposit: $${Number(txn.amount).toFixed(2)} ${txn.crypto_currency} (${txn.crypto_network})`,
        message: `ClickPesa confirmed payment of ${Number(txn.amount_tzs).toLocaleString()} TZS from +${txn.phone_number} (${txn.mobile_network}). Send $${Number(txn.amount).toFixed(2)} ${txn.crypto_currency} (${txn.crypto_network}) to wallet: ${txn.crypto_address}`,
        payload: {
          transaction_id: txn.id,
          user_id: txn.user_id,
          crypto_currency: txn.crypto_currency,
          crypto_network: txn.crypto_network,
          deposit_amount: txn.amount,
          total_paid_usd: txn.total_amount,
          amount_tzs: txn.amount_tzs,
          phone_number: txn.phone_number,
          mobile_network: txn.mobile_network,
          crypto_address: txn.crypto_address,
          clickpesa_reference: txn.clickpesa_reference
        }
      }]);

      return res.status(200).json({ success: true, transaction: updatedTxn });
    }

    if (isFailed && txn.status === 'pending_payment') {
      await supabase
        .from('transactions')
        .update({
          status: 'failed',
          admin_message: 'Mobile money USSD payment failed or was cancelled.',
          updated_at: new Date().toISOString()
        })
        .eq('id', txn.id);
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    return res.status(200).json({ received: true, error: err.message });
  }
});

// 5. CLIENT WITHDRAWAL
app.post('/api/payments/withdraw', async (req, res) => {
  try {
    const {
      user_id,
      crypto_currency,
      crypto_network,
      mobile_network,
      phone_number,
      amount
    } = req.body;

    if (!phone_number || !amount) {
      return res.status(400).json({
        success: false,
        error: 'phone_number and amount are required.'
      });
    }

    const settings = await getSettings();
    const feePercentage = Number(settings.withdraw_fee_percentage || 2.0);
    const exchangeRate = Number(settings.usd_tzs_rate || 2580);

    const baseAmountUsd = Number(amount);
    const feeAmountUsd = Number((baseAmountUsd * (feePercentage / 100)).toFixed(4));
    const netAmountUsd = Number(Math.max(0, baseAmountUsd - feeAmountUsd).toFixed(4));
    const payoutTzs = Math.round(netAmountUsd * exchangeRate);

    const cleanPhone = normalizePhone(phone_number);
    const cleanRef = generateOrderReference();
    const tempUserId = user_id || `guest_${crypto.randomUUID()}`;

    const now = new Date().toISOString();
    const { data: txn, error: dbError } = await supabase
      .from('transactions')
      .insert([{
        user_id: tempUserId,
        type: 'withdrawal',
        crypto_currency: crypto_currency || 'USDT',
        crypto_network: crypto_network || 'TRC20',
        mobile_network: mobile_network || 'Mobile Money',
        phone_number: cleanPhone,
        amount: baseAmountUsd,
        fee_percentage: feePercentage,
        fee_amount: feeAmountUsd,
        total_amount: netAmountUsd,
        amount_tzs: payoutTzs,
        crypto_address: '',
        status: 'awaiting_admin_wallet',
        clickpesa_reference: cleanRef,
        admin_message: `Withdrawal request received! Waiting for Admin to send our ${crypto_currency} (${crypto_network}) wallet address. Transaction fee: ${feePercentage}% ($${feeAmountUsd.toFixed(2)} USD).`,
        created_at: now,
        updated_at: now
      }])
      .select()
      .single();

    if (dbError) throw dbError;

    await supabase.from('admin_notifications').insert([{
      transaction_id: txn.id,
      type: 'withdrawal_requested',
      title: `New Withdrawal Request: $${baseAmountUsd.toFixed(2)} ${txn.crypto_currency} (${txn.crypto_network})`,
      message: `Client (${tempUserId}) wants to withdraw $${baseAmountUsd.toFixed(2)} ${txn.crypto_currency} on ${txn.crypto_network} to ${txn.mobile_network} (+${cleanPhone}). Fee: ${feePercentage}% ($${feeAmountUsd.toFixed(2)}). Net Payout: ${payoutTzs.toLocaleString()} TZS. Send your ${txn.crypto_currency} wallet address to client.`,
      payload: {
        transaction_id: txn.id,
        user_id: tempUserId,
        crypto_currency: txn.crypto_currency,
        crypto_network: txn.crypto_network,
        mobile_network: txn.mobile_network,
        phone_number: cleanPhone,
        withdraw_amount_usd: baseAmountUsd,
        fee_percentage: feePercentage,
        fee_amount_usd: feeAmountUsd,
        net_payout_tzs: payoutTzs
      }
    }]);

    return res.json({
      success: true,
      message: 'Withdrawal request sent to Admin.',
      transaction: txn
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || 'Internal server error during withdrawal creation.'
    });
  }
});

app.post('/api/payments/withdraw/:id/confirm-crypto', async (req, res) => {
  try {
    const { id } = req.params;
    const { tx_hash } = req.body || {};

    const { data: txn, error } = await supabase
      .from('transactions')
      .update({
        status: 'crypto_received',
        tx_hash: tx_hash || null,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await supabase.from('admin_notifications').insert([{
      transaction_id: txn.id,
      type: 'crypto_deposit_sent',
      title: `Client Sent Crypto: $${Number(txn.amount).toFixed(2)} ${txn.crypto_currency}`,
      message: `Client marked $${Number(txn.amount).toFixed(2)} ${txn.crypto_currency} (${txn.crypto_network}) as sent to ${txn.crypto_address}. Verify wallet balance, send ${Number(txn.amount_tzs).toLocaleString()} TZS to +${txn.phone_number} (${txn.mobile_network}), and click Approve.`,
      payload: {
        transaction_id: txn.id,
        tx_hash: tx_hash || null,
        phone_number: txn.phone_number,
        amount_tzs: txn.amount_tzs
      }
    }]);

    res.json({ success: true, transaction: txn });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 6. ADMIN APP ENDPOINTS
app.get('/api/admin/transactions', requireAdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('transactions')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json({ success: true, transactions: data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/notifications', requireAdminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('admin_notifications')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    if (error) throw error;
    res.json({ success: true, notifications: data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/transactions/:id/send-wallet', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { crypto_address, custom_note } = req.body;

    if (!crypto_address) {
      return res.status(400).json({ success: false, error: 'crypto_address is required' });
    }

    const { data: existing } = await supabase.from('transactions').select('*').eq('id', id).single();
    if (!existing) return res.status(404).json({ success: false, error: 'Transaction not found' });

    const feeUsd = (Number(existing.amount) * (Number(existing.fee_percentage) / 100)).toFixed(2);
    const adminMsg = custom_note ||
      `Please send exactly $${Number(existing.amount).toFixed(2)} ${existing.crypto_currency} on ${existing.crypto_network} to our wallet address: ${crypto_address.trim()}. Transaction fee: ${existing.fee_percentage}% ($${feeUsd} USD). Once received, we will send ${Number(existing.amount_tzs).toLocaleString()} TZS to +${existing.phone_number} (${existing.mobile_network}).`;

    const { data: updated, error } = await supabase
      .from('transactions')
      .update({
        crypto_address: crypto_address.trim(),
        status: 'awaiting_crypto_deposit',
        admin_message: adminMsg,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, transaction: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/transactions/:id/approve', requireAdminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { tx_hash, admin_message } = req.body || {};

    const { data: existing } = await supabase.from('transactions').select('*').eq('id', id).single();
    if (!existing) return res.status(404).json({ success: false, error: 'Transaction not found' });

    const feeUsd = (Number(existing.amount) * (Number(existing.fee_percentage) / 100)).toFixed(2);

    let defaultMessage = '';
    if (existing.type === 'deposit') {
      defaultMessage = `Deposit Approved! We have sent $${Number(existing.amount).toFixed(2)} ${existing.crypto_currency} (${existing.crypto_network}) to your wallet address: ${existing.crypto_address}. Total Paid: $${Number(existing.total_amount).toFixed(2)} USD (${Number(existing.amount_tzs).toLocaleString()} TZS including ${existing.fee_percentage}% fee). Reference: ${existing.clickpesa_reference}${tx_hash ? ' · TxHash: ' + tx_hash : ''}.`;
    } else {
      defaultMessage = `Withdrawal Approved & Sent! We have sent ${Number(existing.amount_tzs).toLocaleString()} TZS to your ${existing.mobile_network} number +${existing.phone_number}. Withdraw Amount: $${Number(existing.amount).toFixed(2)} ${existing.crypto_currency} · Transaction Fee (${existing.fee_percentage}%): -$${feeUsd} USD · Net Settled: $${Number(existing.total_amount).toFixed(2)} USD. Reference: ${existing.clickpesa_reference}.`;
    }

    const { data: updated, error } = await supabase
      .from('transactions')
      .update({
        status: 'completed',
        tx_hash: tx_hash || existing.tx_hash || null,
        admin_message: admin_message || defaultMessage,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, transaction: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`SwiftFX Backend running on port ${PORT}`);
});
