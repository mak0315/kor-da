const querystring = require('querystring');
const https = require('https');

function ghPost(body) {
  return new Promise((resolve, reject) => {
    const data = querystring.stringify(body);
    const req = https.request('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { resolve({}); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

module.exports = async function handler(req, res) {
  const CLIENT_ID = process.env.GITHUB_CLIENT_ID || 'Ov23liQ2pR22of3SdES3';
  const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

  if (!CLIENT_SECRET) {
    res.writeHead(500, { 'Content-Type': 'text/html' });
    res.end('<h2>Error: GITHUB_CLIENT_SECRET not set</h2><p>Set it in Vercel Dashboard → Settings → Environment Variables.</p>');
    return;
  }

  const url = new URL(req.url, `https://${req.headers.host}`);
  const code = url.searchParams.get('code');

  if (!code) {
    res.writeHead(400, { 'Content-Type': 'text/html' });
    res.end('<h2>Missing authorization code</h2>');
    return;
  }

  const tok = await ghPost({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code: code
  });

  const token = tok.access_token || '';
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<script>
(function(){
  function f(e){
    window.opener.postMessage('authorization:github:success:{"token":"${token}","provider":"github"}', e.origin);
  }
  window.addEventListener("message", f, false);
  window.opener.postMessage("authorizing:github", "*");
})();
</script>`);
};
