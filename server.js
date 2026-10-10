const express = require('express');
const mongoose = require('mongoose');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));

// Подключаемся к MongoDB Atlas через секретную переменную окружения
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Успешное подключение к MongoDB'))
  .catch(err => console.error('❌ Ошибка подключения к MongoDB:', err));

// Создаем структуру нашей таблицы (модели) в базе данных
const noteSchema = new mongoose.Schema({
  seedHash: { type: String, required: true, unique: true },
  encryptedData: { type: String, required: true }
});

const Note = mongoose.model('Note', noteSchema);

// Сохранить или обновить данные
app.post('/api/save', async (req, res) => {
  const { seedHash, encryptedData } = req.body;
  if (!seedHash || !encryptedData) {
    return res.status(400).json({ error: 'Не хватает данных' });
  }

  try {
    // Ищем заметку по хэшу сида, если есть — обновляем, если нет — создаем новую
    await Note.findOneAndUpdate(
      { seedHash },
      { encryptedData },
      { upsert: true, new: true }
    );
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера при сохранении' });
  }
});

// Загрузить данные
app.get('/api/load/:seedHash', async (req, res) => {
  try {
    const note = await Note.findOne({ seedHash: req.params.seedHash });
    res.json({ encryptedData: note ? note.encryptedData : '' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера при загрузке' });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
