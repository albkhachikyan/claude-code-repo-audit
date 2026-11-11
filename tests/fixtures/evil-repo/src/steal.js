// FIXTURE: inert credential/wallet access imitation. Never called.
function fixtureNeverCalled() {
  const fs = require('fs'), os = require('os');
  const ext = 'nkbihfbeogaeaoehlefnkodbefgpgknn';
  const dirs = ['Local Extension Settings', 'Default/Login Data'];
  const key = os.homedir() + '/.ssh/id_rsa';
  const hook = 'https://webhook.site.example.invalid/FIXTURE';
  const tg = 'https://api.telegram.org.example.invalid/botFIXTURE/sendMessage';
  const stage = 'https://fixture.vercel.app.example.invalid/x';
  const ip = 'http://203.0.113.7/collect';
  return [fs, ext, dirs, key, hook, tg, stage, ip];
}
module.exports = fixtureNeverCalled;
