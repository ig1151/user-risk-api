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
    table { width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 8px; }
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
  "latency_ms": 245
}</pre>

  <h2>Recommendation values</h2>
  <table>
    <tr><th>Value</th><th>Score range</th><th>Meaning</th></tr>
    <tr><td>allow</td><td>0–39</td><td>Low risk — safe to allow signup</td></tr>
    <tr><td>verify</td><td>40–69</td><td>Medium risk — require OTP or extra verification</td></tr>
    <tr><td>block</td><td>70–100</td><td>High risk — reject or flag for review</td></tr>
  </table>

  <h2>Use cases</h2>
  <table>
    <tr><th>Use case</th><th>What to check</th><th>Action</th></tr>
    <tr><td>Signup fraud prevention</td><td>email + phone + ip</td><td>Block if score &gt; 70</td></tr>
    <tr><td>Checkout protection</td><td>email + ip</td><td>Require 3DS if score &gt; 40</td></tr>
    <tr><td>Login anomaly detection</td><td>ip only</td><td>Force re-auth if score &gt; 50</td></tr>
    <tr><td>Lead quality scoring</td><td>email + phone</td><td>Flag low quality if score &gt; 40</td></tr>
    <tr><td>KYC pre-screening</td><td>email + phone + ip</td><td>Manual review if score &gt; 60</td></tr>
  </table>

  <h2>How scoring works</h2>
  <p>Each signal is scored independently from 0–100, then averaged into a combined score:</p>
  <table>
    <tr><th>Signal</th><th>What raises the score</th></tr>
    <tr><td>Email</td><td>Disposable domain (+40), no MX records (+30), invalid format (+50), role-based address (+10)</td></tr>
    <tr><td>Phone</td><td>Fake or sequential digits (+60), invalid number (+40), VoIP number (+40), disposable prefix (+50)</td></tr>
    <tr><td>IP</td><td>Tor exit node (+90), proxy (+70), VPN (+50), hosting/datacenter (+30)</td></tr>
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