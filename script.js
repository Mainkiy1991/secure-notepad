'use strict';

const KDF_ITERATIONS = 600000;
const KDF_VERSION = 1;
const MAX_NOTES = 500;
const MAX_NOTE_BYTES = 100000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (selector) => document.querySelector(selector);

let englishWords = null;
let activeSeed = '';
let activeSeedHash = '';
let vaultSalt = null;
let encryptionKey = null;
let notes = [];
let activeNoteId = null;
let dirty = false;
let saveTimer = null;
let idleTimer = null;
let toastTimer = null;
let saveInFlight = null;
let saveAgain = false;
let unlocked = false;

function showToast(message, type = 'success') {
  const toast = $('#toast');
  toast.textContent = message;
  toast.dataset.type = type;
  toast.classList.add('is-visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('is-visible'), 3800);
}

function setSaveStatus(message, state = 'saved') {
  const status = $('#save-status');
  status.textContent = message;
  status.dataset.state = state;
}

function setBusy(button, busy, busyLabel) {
  if (busy) {
    button.dataset.originalHtml = button.innerHTML;
    button.textContent = busyLabel;
    button.disabled = true;
  } else {
    button.innerHTML = button.dataset.originalHtml || button.innerHTML;
    button.disabled = false;
    delete button.dataset.originalHtml;
  }
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Резервная копия содержит некорректные данные.');
  }
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

function canonicalizeMnemonic(value) {
  return value.trim().toLowerCase().normalize('NFKD').split(/\s+/u).join(' ');
}

function setSeedVisibility(visible) {
  const field = $('#seed');
  field.classList.toggle('hidden', !visible);
  $('#seed-mask').classList.toggle('hidden', visible);
  const label = visible ? 'Скрыть' : 'Показать';
  $('#seed-visibility-label').textContent = label;
  $('#toggle-seed-visibility').setAttribute('aria-label', `${label} сид-фразу`);
  $('#toggle-seed-visibility').title = `${label} сид-фразу`;
  $('#seed-eye').classList.toggle('hidden', !visible);
  $('#seed-eye-off').classList.toggle('hidden', visible);
}

function toggleSeedVisibility() {
  setSeedVisibility($('#seed').classList.contains('hidden'));
}

async function loadWordlist() {
  if (englishWords) return englishWords;
  const response = await fetch('/english.txt', { cache: 'no-store' });
  if (!response.ok) throw new Error('Не удалось загрузить локальный список BIP-39.');
  englishWords = (await response.text()).trim().split(/\s+/);
  if (englishWords.length !== 2048) throw new Error('Список слов BIP-39 повреждён.');
  return englishWords;
}

async function validateMnemonic(phrase) {
  const words = await loadWordlist();
  const tokens = canonicalizeMnemonic(phrase).split(' ');
  if (tokens.length !== 12) return false;

  const indexes = tokens.map(word => words.indexOf(word));
  if (indexes.some(index => index < 0)) return false;

  const bitString = indexes.map(index => index.toString(2).padStart(11, '0')).join('');
  const entropyBits = bitString.slice(0, 128);
  const checksumBits = bitString.slice(128);
  const entropy = new Uint8Array(16);
  for (let i = 0; i < entropy.length; i += 1) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
  const expectedChecksum = Array.from(digest, byte => byte.toString(2).padStart(8, '0')).join('').slice(0, 4);
  return checksumBits === expectedChecksum;
}

async function generateSeed() {
  try {
    if (!crypto?.getRandomValues || !crypto?.subtle) throw new Error('Для безопасной генерации откройте сервис через HTTPS.');
    const words = await loadWordlist();
    const entropy = crypto.getRandomValues(new Uint8Array(16));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy));
    const bits = Array.from(entropy, byte => byte.toString(2).padStart(8, '0')).join('')
      + digest[0].toString(2).padStart(8, '0').slice(0, 4);
    const phrase = [];
    for (let offset = 0; offset < bits.length; offset += 11) {
      phrase.push(words[parseInt(bits.slice(offset, offset + 11), 2)]);
    }
    $('#seed').value = phrase.join(' ');
    showToast('Новая сид-фраза создана. Сохраните её до продолжения.');
  } catch (error) {
    console.error(error);
    showToast(error.message || 'Не удалось создать сид-фразу.', 'error');
  }
}

async function copySeed() {
  const phrase = canonicalizeMnemonic($('#seed').value);
  if (!phrase) return showToast('Сначала введите или создайте сид-фразу.', 'info');

  try {
    await navigator.clipboard.writeText(phrase);
  } catch (error) {
    const field = document.createElement('textarea');
    field.value = phrase;
    field.setAttribute('readonly', '');
    field.className = 'clipboard-fallback';
    document.body.appendChild(field);
    field.select();
    const copied = document.execCommand('copy');
    field.remove();
    if (!copied) {
      console.error(error);
      return showToast('Не удалось скопировать фразу. Скопируйте её вручную.', 'error');
    }
  }
  showToast('Сид-фраза скопирована в буфер обмена.');
}

async function sha256Hex(value) {
  const material = await crypto.subtle.importKey(
    'raw', encoder.encode(value.normalize('NFKD')), 'PBKDF2', false, ['deriveBits']
  );
  const digest = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: encoder.encode('secure-notepad-vault-id-v1'),
    iterations: KDF_ITERATIONS,
    hash: 'SHA-256'
  }, material, 256));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function deriveEncryptionKey(phrase, salt) {
  const material = await crypto.subtle.importKey(
    'raw', encoder.encode(phrase.normalize('NFKD')), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptNote(note, key) {
  const plaintext = encoder.encode(JSON.stringify({ title: note.title, content: note.content }));
  if (plaintext.length > MAX_NOTE_BYTES) throw new Error('Заметка слишком большая (максимум 100 КБ).');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintext);
  return { v: 1, iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptNote(envelope, key) {
  if (!envelope || envelope.v !== 1) throw new Error('Формат шифрования не поддерживается.');
  const iv = base64ToBytes(envelope.iv);
  const ciphertext = base64ToBytes(envelope.data);
  if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 140000) {
    throw new Error('Зашифрованная заметка повреждена.');
  }
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertext);
  const note = JSON.parse(decoder.decode(plaintext));
  if (typeof note.title !== 'string' || typeof note.content !== 'string' || note.title.length > 120) {
    throw new Error('Содержимое заметки повреждено.');
  }
  return note;
}

function apiError(payload, fallback) {
  return new Error(payload?.error || fallback);
}

async function readJson(response, fallback) {
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw apiError(payload, fallback);
  return payload;
}

function makeId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function renderNoteList() {
  const list = $('#note-list');
  list.replaceChildren();
  for (const note of [...notes].sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''))) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'note-item';
    button.setAttribute('aria-current', String(note.noteId === activeNoteId));
    button.addEventListener('click', () => selectNote(note.noteId));
    const title = document.createElement('span');
    title.className = 'note-item-title';
    title.textContent = note.title.trim() || 'Без названия';
    const date = document.createElement('span');
    date.className = 'note-item-date';
    date.textContent = note.dirty ? 'Есть изменения' : note.updatedAt ? new Date(note.updatedAt).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : 'Новая заметка';
    button.append(title, date);
    list.append(button);
  }
}

function activeNote() {
  return notes.find(note => note.noteId === activeNoteId) || null;
}

function updateEditorFromNote(note) {
  $('#note-title').value = note?.title || '';
  $('#content').value = note?.content || '';
  dirty = Boolean(note?.dirty);
  setSaveStatus(dirty ? 'Есть несохранённые изменения' : note?.updatedAt ? 'Все изменения сохранены' : 'Новая заметка', dirty ? 'dirty' : 'saved');
  $('#delete-note').disabled = !note?.persisted;
}

function setUnlockedUi(value) {
  unlocked = value;
  $('#notes-card').classList.toggle('hidden', !value);
  $('#backup-actions').classList.toggle('hidden', !value);
  $('#open-vault').classList.toggle('hidden', value);
  $('#vault-actions').classList.toggle('hidden', !value);
  $('#seed').disabled = value;
  $('#generate-seed').disabled = value;
  setSeedVisibility(!value);
}

function makeLocalNote(noteId = makeId()) {
  return { noteId, title: '', content: '', updatedAt: null, persisted: false, dirty: false, encryptedData: null };
}

async function fetchNotes(seedHash, key) {
  const payload = await readJson(await fetch(`/api/notes/${seedHash}`, { cache: 'no-store' }), 'Не удалось загрузить заметки.');
  const decrypted = [];
  for (const record of payload.notes || []) {
    const note = await decryptNote(record.encryptedData, key);
    decrypted.push({
      noteId: record.noteId,
      title: note.title,
      content: note.content,
      updatedAt: record.updatedAt,
      persisted: true,
      dirty: false,
      encryptedData: record.encryptedData
    });
  }
  return decrypted;
}

async function openVault() {
  const button = $('#open-vault');
  setBusy(button, true, 'Проверка фразы…');
  try {
    if (!crypto?.subtle || !crypto?.getRandomValues) throw new Error('Для безопасной работы нужен HTTPS.');
    const phrase = canonicalizeMnemonic($('#seed').value);
    if (!await validateMnemonic(phrase)) {
      throw new Error('Введите корректную BIP-39 фразу из 12 слов или создайте новую.');
    }
    const seedHash = await sha256Hex(phrase);
    const vaultResponse = await readJson(await fetch(`/api/vault/${seedHash}`, { cache: 'no-store' }), 'Не удалось проверить хранилище.');
    let vault = vaultResponse.vault;
    if (!vault) {
      const proposedSalt = bytesToBase64(crypto.getRandomValues(new Uint8Array(16)));
      const created = await readJson(await fetch('/api/vault', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seedHash, salt: proposedSalt, kdfVersion: KDF_VERSION, iterations: KDF_ITERATIONS })
      }), 'Не удалось создать защищённое хранилище.');
      vault = created.vault;
    }
    if (vault.kdfVersion !== KDF_VERSION || vault.iterations !== KDF_ITERATIONS) {
      throw new Error('Параметры шифрования этой резервной копии не поддерживаются.');
    }
    const salt = base64ToBytes(vault.salt);
    if (salt.length !== 16) throw new Error('Соль хранилища повреждена.');
    const key = await deriveEncryptionKey(phrase, salt);
    const loadedNotes = await fetchNotes(seedHash, key);

    activeSeed = phrase;
    activeSeedHash = seedHash;
    vaultSalt = salt;
    encryptionKey = key;
    notes = loadedNotes;
    if (!notes.length) notes.push(makeLocalNote());
    activeNoteId = notes[0].noteId;
    $('#seed').value = phrase;
    setUnlockedUi(true);
    updateEditorFromNote(activeNote());
    renderNoteList();
    resetIdleTimer();
    showToast(notes.some(note => note.persisted) ? 'Заметки открыты.' : 'Хранилище готово. Создайте первую заметку.');
  } catch (error) {
    console.error(error);
    showToast(error.message || 'Не удалось открыть заметки.', 'error');
  } finally {
    setBusy(button, false);
  }
}

function markDirty() {
  const note = activeNote();
  if (!note || !unlocked) return;
  note.title = $('#note-title').value;
  note.content = $('#content').value;
  note.dirty = true;
  dirty = true;
  setSaveStatus('Сохраняем изменения…', 'dirty');
  renderNoteList();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => saveCurrentNote(), 900);
  resetIdleTimer();
}

async function saveCurrentNote(force = false) {
  if (!unlocked || !activeNoteId) return false;
  const note = activeNote();
  if (!note || (!note.dirty && note.persisted && !force)) return true;
  if (saveInFlight) {
    saveAgain = true;
    await saveInFlight;
    return !dirty || await saveCurrentNote(force);
  }

  const snapshot = { title: $('#note-title').value.trim().slice(0, 120), content: $('#content').value };
  const noteId = activeNoteId;
  const pending = (async () => {
    try {
      const encryptedData = await encryptNote(snapshot, encryptionKey);
      const response = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seedHash: activeSeedHash, noteId, encryptedData })
      });
      const payload = await readJson(response, 'Не удалось сохранить заметку.');
      const saved = notes.find(item => item.noteId === noteId);
      if (saved) {
        saved.title = snapshot.title;
        saved.content = snapshot.content;
        saved.encryptedData = encryptedData;
        saved.updatedAt = payload.note.updatedAt;
        saved.persisted = true;
        const unchanged = activeNoteId !== noteId
          || ($('#note-title').value.trim().slice(0, 120) === snapshot.title && $('#content').value === snapshot.content);
        saved.dirty = !unchanged;
        if (activeNoteId === noteId) {
          dirty = !unchanged;
          setSaveStatus(unchanged ? 'Сохранено ' + new Date(saved.updatedAt).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) : 'Сохраняем новые изменения…', unchanged ? 'saved' : 'dirty');
        }
        renderNoteList();
      }
      return true;
    } catch (error) {
      console.error(error);
      if (activeNoteId === noteId) setSaveStatus('Не удалось сохранить', 'error');
      showToast(error.message || 'Не удалось сохранить заметку.', 'error');
      return false;
    }
  })();
  saveInFlight = pending;
  const result = await pending;
  saveInFlight = null;
  if (saveAgain) {
    saveAgain = false;
    if (dirty) return saveCurrentNote(true);
  }
  return result;
}

async function selectNote(noteId) {
  if (noteId === activeNoteId) return;
  if (dirty && !await saveCurrentNote()) return;
  const note = notes.find(item => item.noteId === noteId);
  if (!note) return;
  activeNoteId = noteId;
  updateEditorFromNote(note);
  renderNoteList();
  resetIdleTimer();
}

async function createNote() {
  if (dirty && !await saveCurrentNote()) return;
  if (notes.length >= MAX_NOTES) return showToast('Достигнут лимит в 500 заметок.', 'error');
  const note = makeLocalNote();
  notes.unshift(note);
  activeNoteId = note.noteId;
  updateEditorFromNote(note);
  renderNoteList();
  $('#note-title').focus();
  resetIdleTimer();
}

async function deleteCurrentNote() {
  const note = activeNote();
  if (!note) return;
  if (!window.confirm('Удалить эту заметку? Это действие нельзя отменить.')) return;
  clearTimeout(saveTimer);
  try {
    if (note.persisted) {
      await readJson(await fetch(`/api/notes/${activeSeedHash}/${note.noteId}`, { method: 'DELETE' }), 'Не удалось удалить заметку.');
    }
    notes = notes.filter(item => item.noteId !== note.noteId);
    if (!notes.length) notes.push(makeLocalNote());
    activeNoteId = notes[0].noteId;
    dirty = false;
    updateEditorFromNote(activeNote());
    renderNoteList();
    showToast('Заметка удалена.');
  } catch (error) {
    console.error(error);
    showToast(error.message || 'Не удалось удалить заметку.', 'error');
  }
}

async function exportBackup() {
  if (dirty && !await saveCurrentNote()) return;
  try {
    const persistedNotes = notes.filter(note => note.persisted).map(note => ({
      noteId: note.noteId,
      encryptedData: note.encryptedData,
      updatedAt: note.updatedAt
    }));
    const backup = {
      format: 'secure-notepad-backup',
      version: 1,
      seedHash: activeSeedHash,
      vault: { salt: bytesToBase64(vaultSalt), kdfVersion: KDF_VERSION, iterations: KDF_ITERATIONS },
      notes: persistedNotes,
      exportedAt: new Date().toISOString()
    };
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'secure-notepad-backup.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    showToast('Зашифрованная резервная копия скачана.');
  } catch (error) {
    console.error(error);
    showToast('Не удалось создать резервную копию.', 'error');
  }
}

async function importBackupFile(file) {
  if (!file || file.size > 5_000_000) throw new Error('Файл резервной копии слишком большой.');
  const backup = JSON.parse(await file.text());
  if (backup.format !== 'secure-notepad-backup' || backup.version !== 1
      || !backup.vault || backup.vault.kdfVersion !== KDF_VERSION
      || backup.vault.iterations !== KDF_ITERATIONS || !Array.isArray(backup.notes)
      || backup.notes.length > MAX_NOTES) {
    throw new Error('Формат резервной копии не поддерживается.');
  }

  const phrase = unlocked ? activeSeed : canonicalizeMnemonic($('#seed').value);
  if (!await validateMnemonic(phrase)) throw new Error('Сначала введите корректную сид-фразу.');
  const seedHash = await sha256Hex(phrase);
  if (seedHash !== backup.seedHash) throw new Error('Резервная копия создана для другой сид-фразы.');
  const salt = base64ToBytes(backup.vault.salt);
  if (salt.length !== 16) throw new Error('Соль резервной копии повреждена.');
  const key = await deriveEncryptionKey(phrase, salt);
  const verified = [];
  for (const item of backup.notes) {
    if (!item || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(item.noteId)) {
      throw new Error('В резервной копии найден некорректный идентификатор заметки.');
    }
    const decrypted = await decryptNote(item.encryptedData, key);
    verified.push({ noteId: item.noteId, encryptedData: item.encryptedData, updatedAt: item.updatedAt, ...decrypted });
  }

  const vaultResponse = await readJson(await fetch('/api/vault', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      seedHash,
      salt: backup.vault.salt,
      kdfVersion: KDF_VERSION,
      iterations: KDF_ITERATIONS,
      replaceIfEmpty: true
    })
  }), 'Не удалось восстановить параметры хранилища.');

  const uploadButton = $('#import-backup');
  setBusy(uploadButton, true, 'Восстановление…');
  try {
    for (const item of verified) {
      await readJson(await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seedHash, noteId: item.noteId, encryptedData: item.encryptedData })
      }), 'Не удалось восстановить все заметки.');
    }
    const loadedNotes = await fetchNotes(seedHash, key);
    activeSeed = phrase;
    activeSeedHash = seedHash;
    vaultSalt = salt;
    encryptionKey = key;
    notes = loadedNotes.length ? loadedNotes : [makeLocalNote()];
    activeNoteId = notes[0].noteId;
    $('#seed').value = phrase;
    setUnlockedUi(true);
    updateEditorFromNote(activeNote());
    renderNoteList();
    resetIdleTimer();
    showToast('Зашифрованная резервная копия импортирована.');
  } finally {
    setBusy(uploadButton, false);
  }
}

async function lockVault(automatic = false) {
  if (!unlocked) return;
  clearTimeout(saveTimer);
  if (dirty && !await saveCurrentNote()) {
    if (automatic) {
      showToast('Автоматическое закрытие отменено: изменения не удалось сохранить.', 'error');
      resetIdleTimer();
      return;
    }
    if (!window.confirm('Изменения не удалось сохранить. Всё равно закрыть хранилище и очистить экран?')) return;
  }
  clearTimeout(idleTimer);
  activeSeed = '';
  activeSeedHash = '';
  vaultSalt = null;
  encryptionKey = null;
  notes = [];
  activeNoteId = null;
  dirty = false;
  $('#seed').value = '';
  $('#note-title').value = '';
  $('#content').value = '';
  setUnlockedUi(false);
  showToast(automatic ? 'Хранилище автоматически закрыто после бездействия.' : 'Хранилище закрыто.');
}

async function deleteVault() {
  if (!unlocked) return;
  const hasSavedNotes = notes.some(note => note.persisted);
  const warning = hasSavedNotes
    ? 'Будут безвозвратно удалены хранилище и все сохранённые заметки. Несохранённые изменения тоже будут потеряны.'
    : 'Хранилище будет удалено. Несохранённые изменения тоже будут потеряны.';
  if (!window.confirm(`${warning}\n\nСид-фразу можно будет использовать снова, чтобы создать новое хранилище.`)) return;
  if (window.prompt('Для подтверждения введите УДАЛИТЬ:')?.trim().toUpperCase() !== 'УДАЛИТЬ') return;

  const button = $('#delete-vault');
  setBusy(button, true, 'Удаление…');
  try {
    await readJson(await fetch(`/api/vault/${activeSeedHash}`, { method: 'DELETE' }), 'Не удалось удалить хранилище.');
    clearTimeout(saveTimer);
    dirty = false;
    await lockVault(false);
    showToast('Хранилище и заметки удалены. Сид-фразу можно использовать снова.');
  } catch (error) {
    console.error(error);
    showToast(error.message || 'Не удалось удалить хранилище.', 'error');
  } finally {
    setBusy(button, false);
  }
}

function resetIdleTimer() {
  if (!unlocked) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => lockVault(true), 10 * 60 * 1000);
}

function installEventHandlers() {
  $('#toggle-seed-visibility').addEventListener('click', toggleSeedVisibility);
  $('#generate-seed').addEventListener('click', generateSeed);
  $('#copy-seed').addEventListener('click', copySeed);
  $('#open-vault').addEventListener('click', openVault);
  $('#lock-vault').addEventListener('click', () => lockVault(false));
  $('#delete-vault').addEventListener('click', deleteVault);
  $('#new-note').addEventListener('click', createNote);
  $('#save-note').addEventListener('click', () => saveCurrentNote(true));
  $('#delete-note').addEventListener('click', deleteCurrentNote);
  $('#export-backup').addEventListener('click', exportBackup);
  $('#import-backup').addEventListener('click', () => $('#backup-file').click());
  $('#backup-file').addEventListener('change', async event => {
    const file = event.target.files?.[0];
    try {
      await importBackupFile(file);
    } catch (error) {
      console.error(error);
      showToast(error.message || 'Не удалось импортировать копию.', 'error');
    } finally {
      event.target.value = '';
    }
  });
  $('#note-title').addEventListener('input', markDirty);
  $('#content').addEventListener('input', markDirty);
  document.addEventListener('pointerdown', resetIdleTimer, { passive: true });
  document.addEventListener('keydown', resetIdleTimer);
  window.addEventListener('beforeunload', event => {
    if (!dirty) return;
    event.preventDefault();
    event.returnValue = '';
  });
}

installEventHandlers();