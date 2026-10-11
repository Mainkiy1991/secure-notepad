// Генерация 12-словной мнемоники BIP-39 (128 бит энтропии + 4 бита контрольной суммы).
let bip39EnglishWords;

async function generateSeed() {
  try {
    if (!window.crypto?.getRandomValues || !window.crypto?.subtle) {
      throw new Error('Для безопасной генерации требуется HTTPS или localhost с поддержкой Web Crypto.');
    }

    if (!bip39EnglishWords) {
      const response = await fetch('english.txt');
      if (!response.ok) throw new Error('Не удалось загрузить локальный список слов BIP-39.');
      bip39EnglishWords = (await response.text()).trim().split(/\s+/);
      if (bip39EnglishWords.length !== 2048) throw new Error('Некорректный список слов BIP-39.');
    }

    const entropy = window.crypto.getRandomValues(new Uint8Array(16));
    const digest = new Uint8Array(await window.crypto.subtle.digest('SHA-256', entropy));
    const entropyBits = Array.from(entropy, byte => byte.toString(2).padStart(8, '0')).join('');
    const checksumBits = digest[0].toString(2).padStart(8, '0').slice(0, 4);
    const bits = entropyBits + checksumBits;
    const words = [];

    for (let offset = 0; offset < bits.length; offset += 11) {
      words.push(bip39EnglishWords[parseInt(bits.slice(offset, offset + 11), 2)]);
    }

    document.getElementById('seed').value = words.join(' ');
  } catch (error) {
    console.error(error);
    alert(error.message || "Ошибка генерации сид-фразы.");
  }
}


async function copySeed() {
  const seed = document.getElementById('seed').value.trim();

  if (!seed) {
    alert('Сначала введите или сгенерируйте сид-фразу.');
    return;
  }

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(seed);
    } else {
      throw new Error('Clipboard API недоступен.');
    }
  } catch (error) {
    const temporaryField = document.createElement('textarea');
    temporaryField.value = seed;
    temporaryField.setAttribute('readonly', '');
    temporaryField.style.position = 'fixed';
    temporaryField.style.opacity = '0';
    document.body.appendChild(temporaryField);
    temporaryField.select();

    const copied = document.execCommand('copy');
    temporaryField.remove();

    if (!copied) {
      console.error(error);
      alert('Не удалось скопировать SEED. Выделите сид-фразу и скопируйте её вручную.');
      return;
    }
  }

  alert('SEED скопирован в буфер обмена.');
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
