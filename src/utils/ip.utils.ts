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
