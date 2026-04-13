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
