// Функция создания случайной сид-фразы из 12 слов
function generateSeed() {
  const words = ["apple", "banana", "river", "mountain", "cloud", "sun", "forest", "crypto", "safe", "shield", "ocean", "stone"];
  let result = [];
  for (let i = 0; i < 12; i++) {
    const randomIndex = Math.floor(Math.random() * words.length);
    result.push(words[randomIndex]);
  }
  const seedInput = document.getElementById('seed');
  seedInput.type = "text"; // Покажем сид-фразу, чтобы пользователь её скопировал
  seedInput.value = result.join(' ');
}

// Заглушка для сохранения (шифрование)
function saveData() {
  const seed = document.getElementById('seed').value;
  const content = document.getElementById('content').value;

  if (!seed) {
    alert("Пожалуйста, введите сид-фразу!");
    return;
  }

  // Шифруем текст с помощью сид-фразы
  const encrypted = CryptoJS.AES.encrypt(content, seed).toString();
  
  console.log("Зашифрованный текст:", encrypted);
  alert("Данные успешно зашифрованы! (Бэкенд подключим на следующем шаге)");
}

// Заглушка для загрузки (расшифровка)
function loadData() {
  alert("Загрузка с сервера будет настроена, когда подключим базу данных.");
}
