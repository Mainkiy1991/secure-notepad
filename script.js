let toastTimer;

function showToast(message, type = 'success') {
  const toast = document.getElementById('toast');
  if (!toast) {
    console[type === 'error' ? 'error' : 'log'](message);
    return;
  }

  toast.textContent = message;
  toast.dataset.type = type;
  toast.classList.add('is-visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 3600);
}

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
    showToast(error.message || 'Ошибка генерации сид-фразы.', 'error');
  }
}


async function copySeed() {
  const seed = document.getElementById('seed').value.trim();

  if (!seed) {
    showToast('Сначала введите или сгенерируйте сид-фразу.', 'info');
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
      showToast('Не удалось скопировать SEED. Выделите сид-фразу и скопируйте её вручную.', 'error');
      return;
    }
  }

  showToast('SEED скопирован в буфер обмена.');
}

function getSeedHash(seed) {
  return CryptoJS.SHA256(seed).toString();
}

async function saveData() {
  const seed = document.getElementById('seed').value.trim();
  const content = document.getElementById('content').value;

  if (!seed) {
    showToast('Пожалуйста, введите или сгенерируйте сид-фразу!', 'info');
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
      showToast('Данные успешно зашифрованы и сохранены на сервере!');
    } else {
      showToast('Ошибка при сохранении.', 'error');
    }
  } catch (error) {
    console.error(error);
    showToast('Ошибка соединения с сервером.', 'error');
  }
}

async function loadData() {
  const seed = document.getElementById('seed').value.trim();

  if (!seed) {
    showToast('Введите сид-фразу для расшифровки данных!', 'info');
    return;
  }

  const seedHash = getSeedHash(seed);

  try {
    const response = await fetch(`/api/load/${seedHash}`);
    const data = await response.json();

    if (!data.encryptedData) {
      showToast('Заметки для этой сид-фразы не найдены.', 'info');
      document.getElementById('content').value = "";
      return;
    }

    const bytes = CryptoJS.AES.decrypt(data.encryptedData, seed);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);

    if (!originalText) {
      showToast('Не удалось расшифровать. Возможно, неверная сид-фраза.', 'error');
      return;
    }

    document.getElementById('content').value = originalText;
    showToast('Данные успешно загружены и расшифрованы!');
  } catch (error) {
    console.error(error);
    showToast('Ошибка при загрузке данных.', 'error');
  }
}
