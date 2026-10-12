import { Router } from 'express';

const router = Router();
router.get('/api/v1/orders/:id', (req, res) => {
  // A route declaration alone cannot establish tenant authorization.
  res.json({ orderId: req.params.id, internalSecret: process.env.INTERNAL_SECRET });
});

export default router;
