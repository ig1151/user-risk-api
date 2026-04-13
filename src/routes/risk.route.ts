import { Router, Request, Response, NextFunction } from 'express';
import { riskSchema } from '../utils/validation';
import { assessRisk } from '../services/risk.service';
import type { RiskRequest } from '../types/index';
export const riskRouter = Router();

riskRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { error, value } = riskSchema.validate(req.body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map((d) => d.message) } }); return; }
    const result = await assessRisk(value as RiskRequest);
    res.status(200).json(result);
  } catch (err) { next(err); }
});

riskRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const body: RiskRequest = {
      email: req.query.email as string | undefined,
      phone: req.query.phone as string | undefined,
      ip: req.query.ip as string | undefined,
      country_code: req.query.country_code as string | undefined,
    };
    const { error, value } = riskSchema.validate(body, { abortEarly: false });
    if (error) { res.status(422).json({ error: { code: 'VALIDATION_ERROR', message: 'Validation failed', details: error.details.map((d) => d.message) } }); return; }
    const result = await assessRisk(value as RiskRequest);
    res.status(200).json(result);
  } catch (err) { next(err); }
});
