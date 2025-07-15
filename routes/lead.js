import express from 'express';
import db from '../db.js';

const router = express.Router();

// 📥 Add New Lead
router.post('/add', (req, res) => {
  const { name, email, phone, source, status } = req.body;
  const q = 'INSERT INTO leads (name, email, phone, source, status) VALUES (?, ?, ?, ?, ?)';
  db.query(q, [name, email, phone, source, status], (err, result) => {
    if (err) return res.status(500).json(err);
    res.json({ success: true });
  });
});

// 📤 Get All Leads
router.get('/', (req, res) => {
  db.query('SELECT * FROM leads ORDER BY id DESC', (err, result) => {
    if (err) return res.status(500).json(err);
    res.json(result);
  });
});

// 🗑️ Delete a Lead
router.delete('/:id', (req, res) => {
  db.query('DELETE FROM leads WHERE id = ?', [req.params.id], (err, result) => {
    if (err) return res.status(500).json(err);
    res.json({ success: true });
  });
});

// ✏️ Update Lead
router.put('/:id', (req, res) => {
  const { name, email, phone, source, status } = req.body;
  const q = 'UPDATE leads SET name=?, email=?, phone=?, source=?, status=? WHERE id=?';
  db.query(q, [name, email, phone, source, status, req.params.id], (err, result) => {
    if (err) return res.status(500).json(err);
    res.json({ success: true });
  });
});

export default router;
