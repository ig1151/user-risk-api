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
