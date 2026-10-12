'use strict';

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const KDF_VERSION = 1;
const KDF_ITERATIONS = 600000;
const MAX_NOTES = 500;
const rateStores = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const noteSchema = new mongoose.Schema({
  seedHash: { type: String, required: true, match: /^[a-f0-9]{64}$/ },
  noteId: { type: String, required: true },
  encryptedData: { type: mongoose.Schema.Types.Mixed, required: true }
}, { timestamps: true, versionKey: false });
noteSchema.index({ seedHash: 1, noteId: 1 }, { unique: true });
const Note = mongoose.model('SecureNoteV2', noteSchema, 'secure_notes_v2');

const vaultSchema = new mongoose.Schema({
  seedHash: { type: String, required: true, unique: true, match: /^[a-f0-9]{64}$/ },
  salt: { type: String, required: true },
  kdfVersion: { type: Number, required: true },
  iterations: { type: Number, required: true }
}, { timestamps: true, versionKey: false });
const Vault = mongoose.model('SecureVaultV1', vaultSchema, 'secure_vaults_v1');

function securityHeaders(req, res, next) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');

  if (process.env.NODE_ENV === 'production') {
    if (!req.secure) return res.redirect(308, req.originalUrl);
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  }
  next();
}
app.use(securityHeaders);
app.use(express.json({ limit: '256kb' }));

function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip;
    let record = rateStores.get(key);
    if (!record || record.resetAt <= now) {
      record = { count: 0, resetAt: now + windowMs };
      rateStores.set(key, record);
    }
    record.count += 1;
    if (record.count > max) {
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil((record.resetAt - now) / 1000))));
      return res.status(429).json({ error: 'Слишком много запросов. Попробуйте позже.' });
    }
    if (rateStores.size > 10000) {
      for (const [storedKey, stored] of rateStores) {
        if (stored.resetAt <= now) rateStores.delete(storedKey);
      }
    }
    next();
  };
}
const readLimit = rateLimit(900, 15 * 60 * 1000);
const writeLimit = rateLimit(300, 15 * 60 * 1000);

function validSeedHash(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}
function validNoteId(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}
function canonicalBase64(value) {
  return typeof value === 'string'
    && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    && Buffer.from(value, 'base64').toString('base64') === value;
}
function validSalt(value) {
  return canonicalBase64(value) && Buffer.from(value, 'base64').length === 16;
}
function validEnvelope(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && value.v === 1
    && canonicalBase64(value.iv) && Buffer.from(value.iv, 'base64').length === 12
    && canonicalBase64(value.data) && Buffer.from(value.data, 'base64').length >= 16
    && Buffer.from(value.data, 'base64').length <= 140000;
}

function serveFile(file) {
  return (req, res, next) => res.sendFile(path.join(__dirname, file), error => {
    if (error) next(error);
  });
}
app.get('/', serveFile('index.html'));
app.get('/styles.css', serveFile('styles.css'));
app.get('/script.js', serveFile('script.js'));
app.get('/english.txt', serveFile('english.txt'));

app.get('/api/vault/:seedHash', readLimit, async (req, res) => {
  if (!validSeedHash(req.params.seedHash)) return res.status(400).json({ error: 'Некорректный идентификатор хранилища.' });
  try {
    const vault = await Vault.findOne({ seedHash: req.params.seedHash }).select('salt kdfVersion iterations').lean();
    res.json({ vault: vault || null });
  } catch (error) {
    console.error('Не удалось прочитать хранилище:', error);
    res.status(500).json({ error: 'Не удалось открыть хранилище.' });
  }
});

app.post('/api/vault', writeLimit, async (req, res) => {
  const { seedHash, salt, kdfVersion, iterations, replaceIfEmpty } = req.body || {};
  if (!validSeedHash(seedHash) || !validSalt(salt) || kdfVersion !== KDF_VERSION || iterations !== KDF_ITERATIONS) {
    return res.status(400).json({ error: 'Некорректные параметры хранилища.' });
  }
  try {
    let vault = await Vault.findOne({ seedHash });
    if (vault && vault.salt !== salt) {
      if (replaceIfEmpty !== true || await Note.exists({ seedHash })) {
        return res.status(409).json({ error: 'Уже существует хранилище с другими параметрами. Импорт остановлен, данные не изменены.' });
      }
      vault.salt = salt;
      vault.kdfVersion = kdfVersion;
      vault.iterations = iterations;
      await vault.save();
    } else if (!vault) {
      vault = await Vault.create({ seedHash, salt, kdfVersion, iterations });
    }
    res.json({ vault: { salt: vault.salt, kdfVersion: vault.kdfVersion, iterations: vault.iterations } });
  } catch (error) {
    console.error('Не удалось сохранить параметры хранилища:', error);
    res.status(500).json({ error: 'Не удалось создать хранилище.' });
  }
});

app.get('/api/notes/:seedHash', readLimit, async (req, res) => {
  const { seedHash } = req.params;
  if (!validSeedHash(seedHash)) return res.status(400).json({ error: 'Некорректный идентификатор хранилища.' });
  try {
    const records = await Note.find({ seedHash }).sort({ updatedAt: -1 }).limit(MAX_NOTES)
      .select('noteId encryptedData updatedAt').lean();
    res.json({ notes: records });
  } catch (error) {
    console.error('Не удалось загрузить заметки:', error);
    res.status(500).json({ error: 'Не удалось загрузить заметки.' });
  }
});

app.post('/api/notes', writeLimit, async (req, res) => {
  const { seedHash, noteId, encryptedData } = req.body || {};
  if (!validSeedHash(seedHash) || !validNoteId(noteId) || !validEnvelope(encryptedData)) {
    return res.status(400).json({ error: 'Некорректные данные заметки.' });
  }
  try {
    if (!await Vault.exists({ seedHash })) return res.status(404).json({ error: 'Хранилище не найдено.' });
    const existing = await Note.exists({ seedHash, noteId });
    if (!existing && await Note.countDocuments({ seedHash }) >= MAX_NOTES) {
      return res.status(409).json({ error: 'Достигнут лимит в 500 заметок.' });
    }
    const note = await Note.findOneAndUpdate(
      { seedHash, noteId },
      { $set: { encryptedData }, $setOnInsert: { seedHash, noteId } },
      { upsert: true, new: true, runValidators: true }
    ).select('noteId updatedAt').lean();
    res.json({ note });
  } catch (error) {
    console.error('Не удалось сохранить заметку:', error);
    res.status(500).json({ error: 'Не удалось сохранить заметку.' });
  }
});

app.delete('/api/notes/:seedHash/:noteId', writeLimit, async (req, res) => {
  const { seedHash, noteId } = req.params;
  if (!validSeedHash(seedHash) || !validNoteId(noteId)) return res.status(400).json({ error: 'Некорректный идентификатор заметки.' });
  try {
    const result = await Note.deleteOne({ seedHash, noteId });
    if (!result.deletedCount) return res.status(404).json({ error: 'Заметка не найдена.' });
    res.json({ success: true });
  } catch (error) {
    console.error('Не удалось удалить заметку:', error);
    res.status(500).json({ error: 'Не удалось удалить заметку.' });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Маршрут не найден.' }));
app.use((error, req, res, next) => {
  console.error('Ошибка запроса:', error);
  if (res.headersSent) return next(error);
  const status = error.type === 'entity.too.large' ? 413 : 500;
  res.status(status).json({ error: status === 413 ? 'Запрос слишком большой.' : 'Внутренняя ошибка сервера.' });
});

async function start() {
  if (!MONGO_URI) throw new Error('Не задана обязательная переменная окружения MONGO_URI.');
  await mongoose.connect(MONGO_URI);
  await Promise.all([Note.init(), Vault.init()]);
  app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
}

start().catch(error => {
  console.error('Не удалось запустить сервер:', error);
  process.exitCode = 1;
});