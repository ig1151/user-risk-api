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
