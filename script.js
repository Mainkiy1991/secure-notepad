// Генерация настоящей сид-фразы BIP-39
function generateSeed() {
  try {
    // В этой версии библиотеки генерация идет через bip39.generateMnemonic()
    const mnemonic = bip39.generateMnemonic();
    document.getElementById('seed').value = mnemonic;
  } catch (error) {
    console.error(error);
    alert("Ошибка генерации сид-фразы.");
  }
}

function getSeedHash(seed) {
  return CryptoJS.SHA256(seed).toString();
}

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
