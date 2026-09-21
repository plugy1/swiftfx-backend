const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Supabase Admin Client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ClickPesa Configuration
const CLICKPESA_URL = process.env.CLICKPESA_BASE_URL || 'https://api.clickpesa.com/third-party/v1';
const CLICKPESA_API_KEY = process.env.CLICKPESA_API_KEY;

// 1. Initiate Deposit (STK Push)
app.post('/api/deposit/initiate', async (req, res) => {
  try {
    const { userId, cryptoCurrency, cryptoNetwork, mobileNetwork, phoneNumber, amount, cryptoAddress } = req.body;

    // Fetch dynamic transaction fee from Supabase
    const { data: settings, error: settingsError } = await supabase
      .from('app_settings')
      .select('deposit_fee_percentage')
      .eq('id', 1)
      .single();

    if (settingsError) throw settingsError;

    const feePct = settings.deposit_fee_percentage;
    const feeAmount = (amount * feePct) / 100;
    const totalAmount = parseFloat(amount) + feeAmount;

    // Create record in Supabase
    const { data: transaction, error: txError } = await supabase
      .from('transactions')
      .insert([{
        user_id: userId,
        type: 'deposit',
        crypto_currency: cryptoCurrency,
        crypto_network: cryptoNetwork,
        mobile_network: mobileNetwork,
        phone_number: phoneNumber,
        amount: amount,
        fee_percentage: feePct,
        total_amount: totalAmount,
        crypto_address: cryptoAddress,
        status: 'pending'
      }])
      .select()
      .single();

    if (txError) throw txError;

    // Trigger ClickPesa STK Push
    const clickPesaResponse = await axios.post(
      `${CLICKPESA_URL}/payments/initiate`,
      {
        amount: Math.round(totalAmount),
        currency: 'TZS',
        phone_number: phoneNumber,
        operator: mobileNetwork,
        reference: transaction.id
      },
      {
        headers: { 'Authorization': `Bearer ${CLICKPESA_API_KEY}` }
      }
    );

    // Update transaction reference
    await supabase
      .from('transactions')
      .update({ clickpesa_reference: clickPesaResponse.data.reference || transaction.id })
      .eq('id', transaction.id);

    return res.status(200).json({
      success: true,
      message: 'STK Push sent successfully. Check your phone for prompt.',
      transactionId: transaction.id
    });

  } catch (err) {
    console.error('Deposit initiation error:', err.response?.data || err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// 2. ClickPesa Webhook Callback
app.post('/api/webhooks/clickpesa', async (req, res) => {
  try {
    const { reference, status } = req.body;

    if (status === 'SUCCESS' || status === 'COMPLETED') {
      // Update transaction status to fiat_received
      await supabase
        .from('transactions')
        .update({ status: 'fiat_received', updated_at: new Date() })
        .eq('id', reference);
    } else if (status === 'FAILED') {
      await supabase
        .from('transactions')
        .update({ status: 'failed', updated_at: new Date() })
        .eq('id', reference);
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error('Webhook error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// 3. Initiate Withdrawal Request
app.post('/api/withdraw/initiate', async (req, res) => {
  try {
    const { userId, cryptoCurrency, cryptoNetwork, mobileNetwork, phoneNumber, amount } = req.body;

    // Fetch dynamic transaction fee from Supabase
    const { data: settings, error: settingsError } = await supabase
      .from('app_settings')
      .select('withdraw_fee_percentage')
      .eq('id', 1)
      .single();

    if (settingsError) throw settingsError;

    const feePct = settings.withdraw_fee_percentage;
    const feeAmount = (amount * feePct) / 100;
    const netAmount = parseFloat(amount) - feeAmount;

    // Create withdrawal request in Supabase
    const { data: transaction, error: txError } = await supabase
      .from('transactions')
      .insert([{
        user_id: userId,
        type: 'withdrawal',
        crypto_currency: cryptoCurrency,
        crypto_network: cryptoNetwork,
        mobile_network: mobileNetwork,
        phone_number: phoneNumber,
        amount: amount,
        fee_percentage: feePct,
        total_amount: netAmount,
        crypto_address: 'PENDING_ADMIN_ADDRESS',
        status: 'pending'
      }])
      .select()
      .single();

    if (txError) throw txError;

    return res.status(200).json({
      success: true,
      message: 'Withdrawal request submitted. Admin will issue crypto address.',
      transactionId: transaction.id
    });

  } catch (err) {
    console.error('Withdraw initiation error:', err.message);
    return res.status(500).json({ success: false, error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SwiftFX backend running on port ${PORT}`));
