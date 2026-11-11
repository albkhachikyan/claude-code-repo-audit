const { Router } = require('express');

const router = Router();
const items = [];

router.get('/', (req, res) => res.json(items));
router.post('/', (req, res) => {
  const name = String(req.body && req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name required' });
  items.push({ id: items.length + 1, name });
  res.status(201).json(items[items.length - 1]);
});

module.exports = router;
