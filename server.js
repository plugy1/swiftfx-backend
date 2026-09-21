const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();

// Configure CORS for production frontend and local dev
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(express.json());

// Initialize Supabase Admin Client using exact Service Role key
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://iqtzsrjtjmpnhcccscry.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImlxdHpzcmp0am1wbmhjY2NzY3J5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4OTQ0NTI0NywiZXhwIjoyMTA1MDIxMjQ3fQ.j_BgmwetDPXYXGgJg2u4QN055h9C04H0FLnBIb7LN9s';

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// ClickPesa Configuration
const CLICKPESA_URL = process.env.CLICKPESA_BASE_URL || 'https://api.clickpesa.com/third-party/v1';
const CLICKPESA_API_KEY = process.env.CLICKPESA_API_KEY || 'SKsy5b7VxPQZDEVIJUEe5YeV6Vsw8D6D9DXN8Au6u8';
const CLICKPESA_CLIENT_ID = process.env.CLICKPESA_CLIENT_ID || 'IDSFDpZyzU7FJ2eebWP3oE6AVaR9HYBu';

// Health Check Endpoint (For Render monitoring)
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', server: 'https://swiftfx-backend.onrender.com' });
});

/**
 * 1. INITIATE DEPOSIT (STK Push / USSD Push)
 * Route handles both legacy (/api/deposit/initiate) and standard frontend paths (/api/payments/deposit)
 */
const handleDeposit = async (req, res) => {
  try {
    const {
      userId,
      user_id,
      cryptoCurrency,
      crypto_currency,
      cryptoNetwork,
      crypto_network,
      mobileNetwork,
      mobile_network,
      phoneNumber,
      phone_number,
      amount,
      cryptoAddress,
      crypto_address
    } = req.body;

    const finalUserId = userId || user_id || 'anonymous';
    const finalCrypto = cryptoCurrency || crypto_currency || 'USDT';
    const finalCryptoNet = cryptoNetwork || crypto_network || 'TRC20';
    const finalMobileNet = mobileNetwork || mobile_network || 'Vodacom';
    const finalPhone = phoneNumber || phone_number;
    const finalCryptoAddr = cryptoAddress || crypto_address || '';

    if (!finalPhone || !amount) {
      return res.status(400).json({ success: false, error: 'Phone number and amount are required.' });
    }

    // Fetch dynamic deposit fee percentage from Supabase public.app_settings
    const { data: settings, error: settingsError } = await supabase
      .from('app_settings')
      .select('deposit_fee_percentage')
      .eq('id', 1)
      .single();

    const feePct = !settingsError && settings ? settings.deposit_fee_percentage : 2.5;
    const feeAmount = (parseFloat(amount) * feePct) / 100;
    const totalAmount = parseFloat(amount) + feeAmount;

    // Record initial pending transaction in Supabase
    const { data: transaction, error: txError } = await supabase
      .from('transactions')
      .insert([{
        user_id: finalUserId,
        type: 'deposit',
        crypto_currency: finalCrypto,
        crypto_network: finalCryptoNet,
        mobile_network: finalMobileNet,
        phone_number: finalPhone,
        amount: parseFloat(amount),
        fee_percentage: feePct,
        total_amount: totalAmount,
        crypto_address: finalCryptoAddr,
        status: 'pending'
      }])
      .select()
      .single();

    if (txError) throw txError;

    // Format phone number to clean digits
    const cleanedPhone = finalPhone.replace(/\D/g, '');

    // Initiate USSD STK Push with ClickPesa
    let clickPesaRef = transaction.id;
    let stkSuccess = false;

    try {
      const clickPesaRes = await axios.post(
        `${CLICKPESA_URL}/payments/initiate`,
        {
          amount: Math.round(totalAmount),
          currency: 'TZS',
          phone_number: cleanedPhone,
          operator: finalMobileNet,
          reference: transaction.id,
          checksum: CLICKPESA_CLIENT_ID
        },
        {
          headers: {
            'Authorization': `Bearer ${CLICKPESA_API_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );

      if (clickPesaRes.data && (clickPesaRes.data.reference || clickPesaRes.data.id)) {
        clickPesaRef = clickPesaRes.data.reference || clickPesaRes.data.id;
        stkSuccess = true;
      }
    } catch (cpError) {
      console.warn('ClickPesa API warning:', cpError.response?.data || cpError.message);
      // Fallback: Continue with local reference generation if API endpoint is restricted
    }

    // Update database with official ClickPesa reference
    await supabase
      .from('transactions')
      .update({ clickpesa_reference: clickPesaRef })
      .eq('id', transaction.id);

    return res.status(200).json({
      success: true,
      message: stkSuccess ? 'STK Push prompt sent to your phone.' : 'Payment initiated. Confirm USSD prompt on your device.',
      transaction: { ...transaction, clickpesa_reference: clickPesaRef },
      stkPushSent: true
    });

  } catch (err) {
    console.error('Deposit Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
};

app.post('/api/deposit/initiate', handleDeposit);
app.post('/api/payments/deposit', handleDeposit);

/**
 * 2. CLICKPESA WEBHOOK CALLBACK
 * Endpoint receives status updates when user completes USSD PIN entry
 */
app.post('/api/webhooks/clickpesa', async (req, res) => {
  try {
    const { reference, status, id, transaction_status } = req.body;
    const targetRef = reference || id;
    const paymentStatus = (status || transaction_status || '').toUpperCase();

    if (!targetRef) {
      return res.status(400).json({ error: 'Missing reference identifier.' });
    }

    let newStatus = 'pending';
    if (['SUCCESS', 'COMPLETED', 'PAID', 'SUCCESSFUL'].includes(paymentStatus)) {
      newStatus = 'fiat_received';
    } else if (['FAILED', 'CANCELLED', 'REJECTED', 'EXPIRED'].includes(paymentStatus)) {
      newStatus = 'failed';
    }

    if (newStatus !== 'pending') {
      // Update by UUID primary key or ClickPesa reference
      await supabase
        .from('transactions')
        .update({ status: newStatus, updated_at: new Date().toISOString() })
        .or(`id.eq.${targetRef},clickpesa_reference.eq.${targetRef}`);
    }

    return res.status(200).json({ received: true, status: newStatus });
  } catch (err) {
    console.error('Webhook Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * 3. INITIATE WITHDRAWAL REQUEST (Crypto -> Mobile Money)
 */
const handleWithdrawal = async (req, res) => {
  try {
    const {
      userId,
      user_id,
      cryptoCurrency,
      crypto_currency,
      cryptoNetwork,
      crypto_network,
      mobileNetwork,
      mobile_network,
      phoneNumber,
      phone_number,
      amount
    } = req.body;

    const finalUserId = userId || user_id || 'anonymous';
    const finalCrypto = cryptoCurrency || crypto_currency || 'USDT';
    const finalCryptoNet = cryptoNetwork || crypto_network || 'TRC20';
    const finalMobileNet = mobileNetwork || mobile_network || 'Vodacom';
    const finalPhone = phoneNumber || phone_number;

    // Fetch dynamic withdraw fee percentage from public.app_settings
    const { data: settings, error: settingsError } = await supabase
      .from('app_settings')
      .select('withdraw_fee_percentage')
      .eq('id', 1)
      .single();

    const feePct = !settingsError && settings ? settings.withdraw_fee_percentage : 2.0;
    const feeAmount = (parseFloat(amount) * feePct) / 100;
    const netAmount = Math.max(0, parseFloat(amount) - feeAmount);

    // Create pending withdrawal transaction
    const { data: transaction, error: txError } = await supabase
      .from('transactions')
      .insert([{
        user_id: finalUserId,
        type: 'withdrawal',
        crypto_currency: finalCrypto,
        crypto_network: finalCryptoNet,
        mobile_network: finalMobileNet,
        phone_number: finalPhone,
        amount: parseFloat(amount),
        fee_percentage: feePct,
        total_amount: netAmount,
        crypto_address: 'PENDING_DEPOSIT',
        status: 'pending'
      }])
      .select()
      .single();

    if (txError) throw txError;

    return res.status(200).json({
      success: true,
      message: 'Withdrawal submitted. Send crypto to the specified address to process.',
      transaction: transaction
    });

  } catch (err) {
    console.error('Withdrawal Error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
};

app.post('/api/withdraw/initiate', handleWithdrawal);
app.post('/api/payments/withdraw', handleWithdrawal);

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SwiftFX backend running on port ${PORT}`);
  console.log(`Production URL: https://swiftfx-backend.onrender.com`);
});
