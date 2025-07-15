// routes/plans.js
const express = require('express');
const router = express.Router();
const db = require('../db'); // Your MySQL connection

// Get available plans
router.get('/available-plans', (req, res) => {
  const plans = [
    {
      name: 'Starter',
      price: 0,
      user_limit: 5,
      permissions: {
        can_export_excel: false,
        can_export_pdf: false,
        can_download_image: true,
        can_view_leads: true,
        can_add_user: false
      }
    },
    {
      name: 'Pro',
      price: 999,
      user_limit: 20,
      permissions: {
        can_export_excel: true,
        can_export_pdf: true,
        can_download_image: true,
        can_view_leads: true,
        can_add_user: true
      }
    }
  ];

  res.json({ Status: 'success', Plans: plans });
});

// Update license on plan upgrade
router.post('/upgrade', (req, res) => {
  const { client_email, selectedPlan } = req.body;
  const { name, price, user_limit, permissions } = selectedPlan;

  const sql = `UPDATE licenses SET plan_name=?, plan_price=?, user_limit=?, permissions=? 
               WHERE client_email=?`;

  db.query(sql, [name, price, user_limit, JSON.stringify(permissions), client_email], (err, result) => {
    if (err) return res.json({ Status: 'error', Error: err });
    return res.json({ Status: 'success', Message: 'Plan upgraded successfully' });
  });
});

module.exports = router;
