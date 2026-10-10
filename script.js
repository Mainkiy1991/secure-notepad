// Генерация настоящей криптографической сид-фразы из 12 слов (BIP-39)
function generateSeed() {
  if (typeof bip39 !== 'undefined') {
    const mnemonic = bip39.generateMnemonic(); // 12 слов из 2048 стандартных
    document.getElementById('seed').value = mnemonic;
  } else {
    alert("Ошибка загрузки библиотеки BIP-39, попробуйте обновить страницу.");
  }
}

// Превращаем сид-фразу в уникальный хэш, чтобы сервер не знал саму фразу
function getSeedHash(seed) {
  return CryptoJS.SHA256(seed).toString();
}

// Сохранение данных на сервер
async function saveData() {
  const seed = document.getElementById('seed').value.trim();
  const content = document.getElementById('content').value;

  if (!seed) {
    alert("Пожалуйста, введите или сгенерируйте сид-фразу!");
    return;
  }

  const seedHash = getSeedHash(seed);
  const encryptedData = CryptoJS.AES.encrypt(content, seed).toString();

  try {
    const response = await fetch('/api/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seedHash, encryptedData })
    });

    if (response.ok) {
      alert("Данные успешно зашифрованы и сохранены на сервере!");
    } else {
      alert("Ошибка при сохранении.");
    }
  } catch (error) {
    console.error(error);
    alert("Ошибка соединения с сервером.");
  }
}

// Загрузка данных с сервера
async function loadData() {
  const seed = document.getElementById('seed').value.trim();

  if (!seed) {
    alert("Введите сид-фразу для расшифровки данных!");
    return;
  }

  const seedHash = getSeedHash(seed);

  try {
    const response = await fetch(`/api/load/${seedHash}`);
    const data = await response.json();

    if (!data.encryptedData) {
      alert("Заметки для этой сид-фразы не найдены.");
      document.getElementById('content').value = "";
      return;
    }

    // Расшифровываем текст сид-фразой
    const bytes = CryptoJS.AES.decrypt(data.encryptedData, seed);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);

    if (!originalText) {
      alert("Не удалось расшифровать. Возможно, неверная сид-фраза.");
      return;
    }

    document.getElementById('content').value = originalText;
    alert("Данные успешно загружены и расшифрованы!");
  } catch (error) {
    console.error(error);
    alert("Ошибка при загрузке данных.");
  }
}
