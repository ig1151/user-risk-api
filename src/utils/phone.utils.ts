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
