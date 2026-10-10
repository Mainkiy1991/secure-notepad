const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Временное хранилище в памяти сервера: ключ (хэш сида) -> зашифрованный текст
const storage = {};

app.use(express.json({ limit: '1mb' }));
app.use(express.static('.')); // Раздаем файлы сайта (html, js)

// Сохранить данные
app.post('/api/save', (req, res) => {
  const { seedHash, encryptedData } = req.body;
  if (!seedHash || !encryptedData) {
    return res.status(400).json({ error: 'Не хватает данных' });
  }
  storage[seedHash] = encryptedData;
  res.json({ success: true });
});

// Загрузить данные
app.get('/api/load/:seedHash', (req, res) => {
  const seedHash = req.params.seedHash;
  const encryptedData = storage[seedHash] || '';
  res.json({ encryptedData });
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
