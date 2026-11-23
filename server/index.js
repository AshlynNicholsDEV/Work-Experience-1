const { createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { sendToSupport } = require('./support');

const app = express();
const PORT = process.env.PORT || 3000;
const publicDirectory = path.join(__dirname, '..', 'public');
const contactPage = fs.readFileSync(path.join(publicDirectory, 'contact.html'), 'utf8');
const formSigningKey = process.env.CONTACT_FORM_SIGNING_KEY || randomBytes(32);
const minimumFormAgeMs = 3000;

function signFormTime(timestamp) {
  return createHmac('sha256', formSigningKey).update(timestamp).digest();
}

function hasValidFormAge(token) {
  if (typeof token !== 'string' || !/^\d{13}\.[a-f0-9]{64}$/.test(token)) {
    return false;
  }

  const [timestamp, signature] = token.split('.');
  return timingSafeEqual(signFormTime(timestamp), Buffer.from(signature, 'hex'))
    && Date.now() - Number(timestamp) >= minimumFormAgeMs;
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get(['/contact', '/contact.html'], (req, res) => {
  const timestamp = String(Date.now());
  const token = timestamp + '.' + signFormTime(timestamp).toString('hex');
  res.set('Cache-Control', 'no-store').send(contactPage.replace('{{formToken}}', token));
});

app.use(express.static(publicDirectory, { extensions: ['html'] }));

app.post('/contact', (req, res) => {
  const { website, formToken, name, email, message } = req.body || {};
  if ((website !== undefined && website !== '') || !hasValidFormAge(formToken)) {
    return res.json({ ok: true });
  }

  if ([name, email, message].some(field => typeof field !== 'string' || !field.trim())) {
    return res.status(400).json({ ok: false, error: 'Please fill in your name, email and message.' });
  }

  sendToSupport({ name: name.trim(), email: email.trim(), message: message.trim() });
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Calico Media site running at http://localhost:${PORT}`);
});
