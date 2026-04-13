#!/bin/bash
set -e

echo "🚀 Building User Risk API..."

cat > src/types/index.ts << 'HEREDOC'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type Recommendation = 'allow' | 'verify' | 'block';

export interface RiskRequest {
  email?: string;
  phone?: string;
  ip?: string;
  country_code?: string;
}

export interface EmailRisk {
  score: number;
  valid: boolean;
  disposable: boolean;
  free_provider: boolean;
  role_based: boolean;
  mx_found: boolean;
  did_you_mean?: string;
}

export interface PhoneRisk {
  score: number;
  valid: boolean;
  line_type: string;
  is_voip: boolean;
  is_likely_fake: boolean;
  country_code: string;
}

export interface IpRisk {
  score: number;
  country: string;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_hosting: boolean;
  threat_level: string;
}

export interface RiskSignal {
  signal: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: 'email' | 'phone' | 'ip';
}

export interface RiskResponse {
  id: string;
  combined_score: number;
  level: RiskLevel;
  recommendation: Recommendation;
  signals: RiskSignal[];
  email?: EmailRisk;
  phone?: PhoneRisk;
  ip?: IpRisk;
  checks_performed: string[];
  latency_ms: number;
  created_at: string;
}
HEREDOC

cat > src/utils/config.ts << 'HEREDOC'
import 'dotenv/config';
function optional(key: string, fallback: string): string { return process.env[key] ?? fallback; }
export const config = {
  server: { port: parseInt(optional('PORT', '3000'), 10), nodeEnv: optional('NODE_ENV', 'development'), apiVersion: optional('API_VERSION', 'v1') },
  rateLimit: { windowMs: parseInt(optional('RATE_LIMIT_WINDOW_MS', '60000'), 10), maxFree: parseInt(optional('RATE_LIMIT_MAX_FREE', '20'), 10), maxPro: parseInt(optional('RATE_LIMIT_MAX_PRO', '500'), 10) },
  logging: { level: optional('LOG_LEVEL', 'info') },
} as const;
HEREDOC

cat > src/utils/logger.ts << 'HEREDOC'
import pino from 'pino';
import { config } from './config';
export const logger = pino({
  level: config.logging.level,
  transport: config.server.nodeEnv === 'development' ? { target: 'pino-pretty', options: { colorize: true } } : undefined,
  base: { service: 'user-risk-api' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: ['req.headers.authorization'], censor: '[REDACTED]' },
});
HEREDOC

cat > src/utils/validation.ts << 'HEREDOC'
import Joi from 'joi';
export const riskSchema = Joi.object({
  email: Joi.string().optional(),
  phone: Joi.string().optional(),
  ip: Joi.string().optional(),
  country_code: Joi.string().length(2).uppercase().optional(),
}).or('email', 'phone', 'ip').messages({
  'object.missing': 'At least one of email, phone, or ip is required',
});
HEREDOC

cat > src/utils/email.utils.ts << 'HEREDOC'
import { promises as dnsPromises } from 'dns';

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

const DISPOSABLE = new Set(['mailinator.com','guerrillamail.com','tempmail.com','throwaway.email','yopmail.com','trashmail.com','maildrop.cc','10minutemail.com','tempinbox.com','fakeinbox.com','discard.email','spam4.me','spamgourmet.com','mailnull.com','emailondeck.com']);
const FREE = new Set(['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com','protonmail.com','mail.com','zoho.com','gmx.com','live.com','me.com','googlemail.com']);
const ROLE = new Set(['admin','info','support','help','contact','sales','billing','noreply','no-reply','webmaster','postmaster','abuse','security','marketing','newsletter']);
const TYPOS: Record<string,string> = { 'gmial.com':'gmail.com','gmai.com':'gmail.com','yahooo.com':'yahoo.com','hotmai.com':'hotmail.com','outlok.com':'outlook.com' };

export async function analyzeEmail(email: string) {
  const formatValid = EMAIL_REGEX.test(email);
  const [username, domain] = email.split('@');
  let mxFound = false;
  if (formatValid && domain) {
    try { const mx = await dnsPromises.resolveMx(domain); mxFound = mx.length > 0; } catch { mxFound = false; }
  }
  const disposable = DISPOSABLE.has(domain?.toLowerCase() ?? '');
  const freeProvider = FREE.has(domain?.toLowerCase() ?? '');
  const roleBased = ROLE.has((username ?? '').toLowerCase().split('+')[0]);
  const didYouMean = TYPOS[domain?.toLowerCase() ?? ''] ? `${username}@${TYPOS[domain.toLowerCase()]}` : undefined;

  let score = 0;
  if (!formatValid) score += 50;
  if (!mxFound) score += 30;
  if (disposable) score += 40;
  if (roleBased) score += 10;
  score = Math.min(100, score);

  return { score, valid: formatValid && mxFound, disposable, free_provider: freeProvider, role_based: roleBased, mx_found: mxFound, did_you_mean: didYouMean };
}
HEREDOC

cat > src/utils/phone.utils.ts << 'HEREDOC'
import { parsePhoneNumberFromString, getCountryCallingCode } from 'libphonenumber-js';

const DISPOSABLE_PREFIXES = ['1900','1976','1977','1978','1979'];

export function analyzePhone(phone: string, countryCode?: string) {
  try {
    const parsed = parsePhoneNumberFromString(phone, countryCode as never);
    if (!parsed) return { score: 80, valid: false, line_type: 'unknown', is_voip: false, is_likely_fake: true, country_code: '' };

    const type = parsed.getType();
    const lineType = type === 'MOBILE' ? 'mobile' : type === 'FIXED_LINE' ? 'landline' : type === 'VOIP' ? 'voip' : type === 'TOLL_FREE' ? 'toll_free' : type === 'FIXED_LINE_OR_MOBILE' ? 'mobile' : 'unknown';
    const isVoip = lineType === 'voip';
    const country = parsed.country ?? countryCode ?? '';

    const digits = phone.replace(/\D/g, '').replace(/^1/, '');
    const isLikelyFake = /^(\d)\1{6,}/.test(digits) || digits === '1234567890' || digits.length < 7;
    const isDisposable = DISPOSABLE_PREFIXES.some(p => digits.startsWith(p));

    let score = 0;
    if (!parsed.isValid()) score += 40;
    if (isVoip) score += 40;
    if (isLikelyFake) score += 60;
    if (isDisposable) score += 50;
    score = Math.min(100, score);

    return { score, valid: parsed.isValid(), line_type: lineType, is_voip: isVoip, is_likely_fake: isLikelyFake, country_code: country };
  } catch {
    return { score: 80, valid: false, line_type: 'unknown', is_voip: false, is_likely_fake: true, country_code: '' };
  }
}
HEREDOC

cat > src/utils/ip.utils.ts << 'HEREDOC'
import http from 'http';

const HOSTING_ASNS = new Set(['AS16509','AS14618','AS15169','AS396982','AS8075','AS13335','AS14061','AS16276','AS24940','AS20473']);
const VPN_ORGS = ['nordvpn','expressvpn','surfshark','cyberghost','protonvpn','ipvanish','mullvad','privateinternetaccess','pia vpn'];
const TOR_INDICATORS = ['tor','torproject','exit node'];

function httpGet(url: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid JSON')); } });
    }).on('error', reject);
  });
}

export async function analyzeIP(ip: string) {
  try {
    const data = await httpGet(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,isp,org,as,proxy,hosting,query`);
    if (data.status === 'fail') return { score: 0, country: '', is_vpn: false, is_proxy: false, is_tor: false, is_hosting: false, threat_level: 'unknown' };

    const asn = String(data.as ?? '');
    const org = String(data.org ?? '').toLowerCase();
    const isp = String(data.isp ?? '').toLowerCase();
    const combined = `${org} ${isp}`;

    const isVpn = VPN_ORGS.some(v => combined.includes(v)) || Boolean(data.proxy);
    const isTor = TOR_INDICATORS.some(t => combined.includes(t));
    const isHosting = HOSTING_ASNS.has(asn.split(' ')[0]) || Boolean(data.hosting);
    const isProxy = Boolean(data.proxy);

    let score = 0;
    if (isTor) score += 90;
    else if (isProxy) score += 70;
    else if (isVpn) score += 50;
    else if (isHosting) score += 30;
    score = Math.min(100, score);

    const threat_level = score >= 80 ? 'critical' : score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';

    return { score, country: String(data.countryCode ?? ''), is_vpn: isVpn, is_proxy: isProxy, is_tor: isTor, is_hosting: isHosting, threat_level };
  } catch {
    return { score: 0, country: '', is_vpn: false, is_proxy: false, is_tor: false, is_hosting: false, threat_level: 'unknown' };
  }
}
HEREDOC

cat > src/services/risk.service.ts << 'HEREDOC'
import { v4 as uuidv4 } from 'uuid';
import { analyzeEmail } from '../utils/email.utils';
import { analyzePhone } from '../utils/phone.utils';
import { analyzeIP } from '../utils/ip.utils';
import { logger } from '../utils/logger';
import type { RiskRequest, RiskResponse, RiskSignal, RiskLevel, Recommendation } from '../types/index';

function getRecommendation(score: number): Recommendation {
  if (score >= 70) return 'block';
  if (score >= 40) return 'verify';
  return 'allow';
}

function getLevel(score: number): RiskLevel {
  if (score >= 80) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

export async function assessRisk(req: RiskRequest): Promise<RiskResponse> {
  const id = `risk_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
  const t0 = Date.now();
  const signals: RiskSignal[] = [];
  const checksPerformed: string[] = [];

  logger.info({ id, hasEmail: !!req.email, hasPhone: !!req.phone, hasIp: !!req.ip }, 'Starting risk assessment');

  let emailRisk, phoneRisk, ipRisk;
  let emailScore = 0, phoneScore = 0, ipScore = 0;

  if (req.email) {
    checksPerformed.push('email');
    emailRisk = await analyzeEmail(req.email);
    emailScore = emailRisk.score;
    if (emailRisk.disposable) signals.push({ signal: 'Disposable email address detected', severity: 'high', source: 'email' });
    if (!emailRisk.mx_found) signals.push({ signal: 'Email domain has no MX records', severity: 'high', source: 'email' });
    if (!emailRisk.valid) signals.push({ signal: 'Email address is invalid', severity: 'critical', source: 'email' });
    if (emailRisk.role_based) signals.push({ signal: 'Role-based email address', severity: 'low', source: 'email' });
    if (emailRisk.did_you_mean) signals.push({ signal: `Possible typo — did you mean ${emailRisk.did_you_mean}?`, severity: 'medium', source: 'email' });
  }

  if (req.phone) {
    checksPerformed.push('phone');
    phoneRisk = analyzePhone(req.phone, req.country_code);
    phoneScore = phoneRisk.score;
    if (phoneRisk.is_voip) signals.push({ signal: 'VoIP phone number detected', severity: 'high', source: 'phone' });
    if (phoneRisk.is_likely_fake) signals.push({ signal: 'Phone number appears fake or sequential', severity: 'critical', source: 'phone' });
    if (!phoneRisk.valid) signals.push({ signal: 'Phone number is invalid', severity: 'high', source: 'phone' });
  }

  if (req.ip) {
    checksPerformed.push('ip');
    ipRisk = await analyzeIP(req.ip);
    ipScore = ipRisk.score;
    if (ipRisk.is_tor) signals.push({ signal: 'Tor exit node detected', severity: 'critical', source: 'ip' });
    if (ipRisk.is_proxy) signals.push({ signal: 'Proxy server detected', severity: 'high', source: 'ip' });
    if (ipRisk.is_vpn) signals.push({ signal: 'VPN service detected', severity: 'high', source: 'ip' });
    if (ipRisk.is_hosting) signals.push({ signal: 'Datacenter or hosting IP detected', severity: 'medium', source: 'ip' });
  }

  const scores = [emailScore, phoneScore, ipScore].filter((_, i) => [req.email, req.phone, req.ip][i]);
  const combinedScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const level = getLevel(combinedScore);
  const recommendation = getRecommendation(combinedScore);

  logger.info({ id, combinedScore, level, recommendation }, 'Risk assessment complete');

  return {
    id,
    combined_score: combinedScore,
    level,
    recommendation,
    signals,
    ...(emailRisk && { email: emailRisk }),
    ...(phoneRisk && { phone: phoneRisk }),
    ...(ipRisk && { ip: ipRisk }),
    checks_performed: checksPerformed,
    latency_ms: Date.now() - t0,
    created_at: new Date().toISOString(),
  };
}
HEREDOC

cat > src/middleware/error.middleware.ts << 'HEREDOC'
import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
export function errorHandler(err: Error, req: Request, res: Response, _next: NextFunction): void {
  logger.error({ err, path: req.path }, 'Unhandled error');
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } });
}
export function notFound(req: Request, res: Response): void { res.status(404).json({ error: { code: 'NOT_FOUND', message: `Route ${req.method} ${req.path} not found` } }); }
HEREDOC

cat > src/middleware/ratelimit.middleware.ts << 'HEREDOC'
import rateLimit from 'express-rate-limit';
import { config } from '../utils/config';
export const rateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs, max: config.rateLimit.maxFree,
  standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: (req) => req.headers['authorization']?.replace('Bearer ', '') ?? req.ip ?? 'unknown',
  handler: (_req, res) => { res.status(429).json({ error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests.' } }); },
});
HEREDOC

cat > src/routes/health.route.ts << 'HEREDOC'
import { Router, Request, Response } from 'express';
export const healthRouter = Router();
const startTime = Date.now();
healthRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok', version: '1.0.0', uptime_seconds: Math.floor((Date.now() - startTime) / 1000), timestamp: new Date().toISOString() });
});
HEREDOC

cat > src/routes/risk.route.ts << 'HEREDOC'
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
HEREDOC

cat > src/routes/openapi.route.ts << 'HEREDOC'
import { Router, Request, Response } from 'express';
import { config } from '../utils/config';
export const openapiRouter = Router();
export const docsRouter = Router();

const docsHtml = `<!DOCTYPE html>
<html>
<head>
  <title>User Risk API — Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 2rem; color: #333; }
    h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
    h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-right: 8px; }
    .get { background: #e3f2fd; color: #1565c0; }
    .post { background: #e8f5e9; color: #2e7d32; }
    .endpoint { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
    .path { font-family: monospace; font-size: 1rem; font-weight: bold; }
    .desc { color: #666; font-size: 0.9rem; margin-top: 0.25rem; }
    pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
    th { background: #f5f5f5; }
  </style>
</head>
<body>
  <h1>User Risk API</h1>
  <p>Score any user's signup risk by combining email, phone and IP intelligence into a single unified risk score.</p>
  <p><strong>Base URL:</strong> <code>https://user-risk-api.onrender.com</code></p>

  <h2>Quick start</h2>
  <pre>const res = await fetch("https://user-risk-api.onrender.com/v1/assess", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "user@example.com",
    phone: "+14155552671",
    ip: "8.8.8.8"
  })
});
const { recommendation, combined_score } = await res.json();
if (recommendation === "block") rejectSignup();
else if (recommendation === "verify") requireOTP();
else allowSignup();</pre>

  <h2>Endpoints</h2>
  <div class="endpoint">
    <div><span class="badge post">POST</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess user risk — pass any combination of email, phone, IP</div>
    <pre>curl -X POST https://user-risk-api.onrender.com/v1/assess \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@gmail.com", "phone": "+14155552671", "ip": "8.8.8.8"}'</pre>
  </div>
  <div class="endpoint">
    <div><span class="badge get">GET</span><span class="path">/v1/assess</span></div>
    <div class="desc">Assess user risk via query parameters</div>
    <pre>curl "https://user-risk-api.onrender.com/v1/assess?email=user@gmail.com&ip=8.8.8.8"</pre>
  </div>

  <h2>Example Response</h2>
  <pre>{
  "id": "risk_abc123",
  "combined_score": 55,
  "level": "high",
  "recommendation": "verify",
  "signals": [
    { "signal": "VoIP phone number detected", "severity": "high", "source": "phone" },
    { "signal": "Datacenter IP detected", "severity": "medium", "source": "ip" }
  ],
  "email": { "score": 10, "valid": true, "disposable": false },
  "phone": { "score": 40, "valid": true, "is_voip": true },
  "ip": { "score": 30, "is_hosting": true, "threat_level": "medium" },
  "checks_performed": ["email", "phone", "ip"],
  "recommendation": "verify",
  "latency_ms": 245
}</pre>

  <h2>Recommendation values</h2>
  <table>
    <tr><th>Value</th><th>Score range</th><th>Meaning</th></tr>
    <tr><td>allow</td><td>0–39</td><td>Low risk — safe to allow signup</td></tr>
    <tr><td>verify</td><td>40–69</td><td>Medium risk — require OTP or extra verification</td></tr>
    <tr><td>block</td><td>70–100</td><td>High risk — reject or flag for review</td></tr>
  </table>

  <h2>OpenAPI Spec</h2>
  <p><a href="/openapi.json">Download openapi.json</a></p>
</body>
</html>`;

docsRouter.get('/', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(docsHtml);
});

openapiRouter.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    openapi: '3.0.3',
    info: { title: 'User Risk API', version: '1.0.0', description: 'Score user signup risk by combining email, phone and IP intelligence.' },
    servers: [{ url: 'https://user-risk-api.onrender.com', description: 'Production' }, { url: `http://localhost:${config.server.port}`, description: 'Local' }],
    paths: {
      '/v1/health': { get: { summary: 'Health check', operationId: 'getHealth', responses: { '200': { description: 'Service is healthy' } } } },
      '/v1/assess': {
        post: { summary: 'Assess user risk', operationId: 'assessRiskPost', requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/RiskRequest' }, examples: { full: { summary: 'Full assessment', value: { email: 'user@gmail.com', phone: '+14155552671', ip: '8.8.8.8' } }, email_only: { summary: 'Email only', value: { email: 'user@gmail.com' } }, ip_only: { summary: 'IP only', value: { ip: '8.8.8.8' } } } } } }, responses: { '200': { description: 'Risk assessment result' }, '422': { description: 'Validation error' } } },
        get: { summary: 'Assess user risk via GET', operationId: 'assessRiskGet', parameters: [{ name: 'email', in: 'query', schema: { type: 'string' } }, { name: 'phone', in: 'query', schema: { type: 'string' } }, { name: 'ip', in: 'query', schema: { type: 'string' } }], responses: { '200': { description: 'Risk assessment result' } } },
      },
    },
    components: {
      schemas: {
        RiskRequest: { type: 'object', properties: { email: { type: 'string', example: 'user@gmail.com' }, phone: { type: 'string', example: '+14155552671' }, ip: { type: 'string', example: '8.8.8.8' }, country_code: { type: 'string', example: 'US' } }, minProperties: 1 },
      },
    },
  });
});
HEREDOC

cat > src/app.ts << 'HEREDOC'
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import pinoHttp from 'pino-http';
import { riskRouter } from './routes/risk.route';
import { healthRouter } from './routes/health.route';
import { openapiRouter, docsRouter } from './routes/openapi.route';
import { errorHandler, notFound } from './middleware/error.middleware';
import { rateLimiter } from './middleware/ratelimit.middleware';
import { logger } from './utils/logger';
import { config } from './utils/config';
const app = express();
app.use(helmet()); app.use(cors()); app.use(compression());
app.use(pinoHttp({ logger }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(`/${config.server.apiVersion}/assess`, rateLimiter);
app.use(`/${config.server.apiVersion}/assess`, riskRouter);
app.use(`/${config.server.apiVersion}/health`, healthRouter);
app.use('/openapi.json', openapiRouter);
app.use('/docs', docsRouter);
app.get('/', (_req, res) => res.redirect(`/${config.server.apiVersion}/health`));
app.use(notFound);
app.use(errorHandler);
export { app };
HEREDOC

cat > src/index.ts << 'HEREDOC'
import { app } from './app';
import { config } from './utils/config';
import { logger } from './utils/logger';
const server = app.listen(config.server.port, () => { logger.info({ port: config.server.port, env: config.server.nodeEnv }, '🚀 User Risk API started'); });
const shutdown = (signal: string) => { logger.info({ signal }, 'Shutting down'); server.close(() => { logger.info('Closed'); process.exit(0); }); setTimeout(() => process.exit(1), 10_000); };
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => logger.error({ reason }, 'Unhandled rejection'));
process.on('uncaughtException', (err) => { logger.fatal({ err }, 'Uncaught exception'); process.exit(1); });
HEREDOC

cat > jest.config.js << 'HEREDOC'
module.exports = { preset: 'ts-jest', testEnvironment: 'node', rootDir: '.', testMatch: ['**/tests/**/*.test.ts'], collectCoverageFrom: ['src/**/*.ts', '!src/index.ts'], setupFiles: ['<rootDir>/tests/setup.ts'] };
HEREDOC

cat > tests/setup.ts << 'HEREDOC'
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'silent';
HEREDOC

cat > .gitignore << 'HEREDOC'
node_modules/
dist/
.env
coverage/
*.log
.DS_Store
HEREDOC

cat > render.yaml << 'HEREDOC'
services:
  - type: web
    name: user-risk-api
    runtime: node
    buildCommand: npm install && npm run build
    startCommand: node dist/index.js
    healthCheckPath: /v1/health
    envVars:
      - key: NODE_ENV
        value: production
      - key: LOG_LEVEL
        value: info
HEREDOC

echo ""
echo "✅ All files created! Run: npm install"