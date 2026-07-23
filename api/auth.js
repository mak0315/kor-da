module.exports = async function handler(req, res) {
  const CLIENT_ID = process.env.GITHUB_CLIENT_ID || 'Ov23liQ2pR22of3SdES3';
  res.writeHead(302, {
    Location: `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&scope=read:user+user:email+repo`
  });
  res.end();
};
