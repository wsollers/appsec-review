import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import type { Express } from 'express';
import { buildTestApp, tokenFor, authHeader } from '../helpers/app.js';

let app: Express;
let token: string;

beforeAll(async () => {
  ({ app } = await buildTestApp());
  token = await tokenFor(app, 'admin');
});

describe('REST orders', () => {
  it('lists orders', async () => {
    const res = await request(app).get('/api/v1/orders?pageSize=25').set(authHeader(token));
    expect(res.status).toBe(200);
    expect(res.body.items.length).toBeGreaterThan(0);
  });

  it('returns an order with details', async () => {
    const res = await request(app).get('/api/v1/orders/10248').set(authHeader(token));
    expect(res.status).toBe(200);
    expect(res.body.order.orderId).toBe(10248);
    expect(res.body.details.length).toBeGreaterThan(0);
  });

  it('creates an order with line items', async () => {
    const res = await request(app)
      .post('/api/v1/orders')
      .set(authHeader(token))
      .send({
        customerId: 'ALFKI',
        employeeId: 1,
        orderDate: '2024-03-03',
        freight: 12.5,
        shipName: 'Alfreds',
        shipCity: 'Berlin',
        shipCountry: 'Germany',
        details: [{ productId: 1, unitPrice: 18, quantity: 3, discount: 0 }],
      });
    expect(res.status).toBe(201);
    expect(res.body.orderId).toBeTypeOf('number');
  });

  it('manages order details', async () => {
    const add = await request(app)
      .post('/api/v1/orders/10248/details')
      .set(authHeader(token))
      .send({ productId: 3, unitPrice: 10, quantity: 2, discount: 0 });
    expect(add.status).toBe(201);
    expect(add.body.productId).toBe(3);

    const listed = await request(app).get('/api/v1/orders/10248/details').set(authHeader(token));
    expect(listed.status).toBe(200);
    expect(listed.body.items.some((item: { productId: number }) => item.productId === 3)).toBe(
      true,
    );

    const updated = await request(app)
      .put('/api/v1/orders/10248/details/3')
      .set(authHeader(token))
      .send({ quantity: 4 });
    expect(updated.status).toBe(200);
    expect(updated.body.quantity).toBe(4);

    const removed = await request(app)
      .delete('/api/v1/orders/10248/details/3')
      .set(authHeader(token));
    expect(removed.status).toBe(204);
  });
});
