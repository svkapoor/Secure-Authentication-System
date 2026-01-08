// Client-side vault encryption/decryption using Web Crypto (PBKDF2 + AES-GCM).
(function () {
  var app = document.getElementById("vault-app");
  if (!app) {
    return;
  }

  var saltB64 = app.getAttribute("data-salt");
  var csrfToken = app.getAttribute("data-csrf");
  var unlockButton = document.getElementById("vault-unlock-button");
  var addButton = document.getElementById("vault-add-button");
  var passphraseInput = document.getElementById("vault-passphrase");
  var loginPasswordRow = document.getElementById("vault-login-password-row");
  var loginPasswordInput = document.getElementById("vault-login-password");
  var passphraseConfirmRow = document.getElementById("vault-passphrase-confirm-row");
  var passphraseConfirmInput = document.getElementById("vault-passphrase-confirm");
  var labelInput = document.getElementById("vault-label");
  var usernameInput = document.getElementById("vault-username");
  var passwordInput = document.getElementById("vault-password");
  var errorEl = document.getElementById("vault-error");
  var lockedStateEl = document.getElementById("vault-locked-state");
  var contentEl = document.getElementById("vault-content");
  var tableEl = document.getElementById("vault-table");
  var tableBodyEl = document.getElementById("vault-table-body");
  var emptyEl = document.getElementById("vault-empty");
  var timerEl = document.getElementById("vault-unlock-timer");
  var remainingEl = document.getElementById("vault-unlock-remaining");

  var unlockDurationMs = 5 * 60 * 1000;
  var unlockExpiresAt = 0;
  var cachedKey = null;
  var entries = [];
  var textEncoder = new TextEncoder();
  var textDecoder = new TextDecoder();
  var countdownTimer = null;
  var vaultInitialized = false;
  var initialPayload = null;

  // Surface errors inline without breaking the page flow.
  function setError(message) {
    if (!message) {
      errorEl.hidden = true;
      errorEl.textContent = "";
      return;
    }
    errorEl.textContent = message;
    errorEl.hidden = false;
  }

  // Toggle locked/unlocked UI.
  function setLockedState(locked) {
    lockedStateEl.hidden = !locked;
    contentEl.hidden = locked;
    timerEl.hidden = locked;
  }

  // Keep the unlock timer live and re-lock when expired.
  function updateCountdown() {
    if (!unlockExpiresAt) {
      return;
    }
    var remainingMs = unlockExpiresAt - Date.now();
    if (remainingMs <= 0) {
      lockVault();
      return;
    }
    remainingEl.textContent = String(Math.ceil(remainingMs / 1000));
  }

  // Start or restart the countdown timer.
  function startCountdown() {
    updateCountdown();
    if (countdownTimer) {
      window.clearInterval(countdownTimer);
    }
    countdownTimer = window.setInterval(updateCountdown, 1000);
  }

  // Clear sensitive state from memory and reset the UI.
  function lockVault() {
    cachedKey = null;
    entries = [];
    unlockExpiresAt = 0;
    if (countdownTimer) {
      window.clearInterval(countdownTimer);
      countdownTimer = null;
    }
    renderEntries();
    setLockedState(true);
    setError("");
  }

  // Base64 helpers for storing ArrayBuffer data as strings.
  function bytesToBase64(bytes) {
    var binary = "";
    var chunkSize = 0x8000;
    for (var i = 0; i < bytes.length; i += chunkSize) {
      var chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Derive an AES-GCM key from the vault passphrase and per-user salt.
  async function deriveKey(passphrase) {
    var saltBytes = base64ToBytes(saltB64);
    var baseKey = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 200000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Decrypt the vault payload into a list of entries.
  async function decryptEntries(payload, key) {
    if (!payload || !payload.ciphertext || !payload.nonce) {
      return [];
    }
    var nonce = base64ToBytes(payload.nonce);
    var ciphertext = base64ToBytes(payload.ciphertext);
    var plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      ciphertext
    );
    var decoded = textDecoder.decode(new Uint8Array(plaintext));
    var data = JSON.parse(decoded);
    return Array.isArray(data) ? data : [];
  }

  // Encrypt the vault entries before sending to the server.
  async function encryptEntries(items, key) {
    var payload = textEncoder.encode(JSON.stringify(items));
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      payload
    );
    return {
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
  }

  // Fetch the encrypted vault blob from the server.
  async function fetchVault() {
    var response = await fetch("/api/vault", { credentials: "same-origin" });
    if (!response.ok) {
      throw new Error("Unable to load vault data.");
    }
    return response.json();
  }

  // Show passphrase setup fields only when no vault exists yet.
  function updatePassphraseUi() {
    if (loginPasswordRow) {
      loginPasswordRow.hidden = vaultInitialized;
      if (vaultInitialized) {
        loginPasswordInput.value = "";
      }
    }
    if (passphraseConfirmRow) {
      passphraseConfirmRow.hidden = vaultInitialized;
      if (vaultInitialized) {
        passphraseConfirmInput.value = "";
      }
    }
  }

  // Determine if a vault exists so we can prompt for setup vs unlock.
  async function detectVaultState() {
    try {
      initialPayload = await fetchVault();
      vaultInitialized = Boolean(initialPayload && initialPayload.ciphertext && initialPayload.nonce);
      updatePassphraseUi();
    } catch (err) {
      setError("Unable to load vault status.");
    }
  }

  // Persist encrypted vault data to the server.
  async function saveVault(items) {
    var payload = await encryptEntries(items, cachedKey);
    var response = await fetch("/api/vault", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error("Unable to save vault data.");
    }
  }

  // Render decrypted entries into the table.
  function renderEntries() {
    tableBodyEl.textContent = "";
    if (!entries.length) {
      tableEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }
    entries.forEach(function (entry) {
      var row = document.createElement("tr");
      var labelCell = document.createElement("td");
      var usernameCell = document.createElement("td");
      var passwordCell = document.createElement("td");
      var storedCell = document.createElement("td");
      var passwordCode = document.createElement("code");

      labelCell.textContent = entry.label || "";
      usernameCell.textContent = entry.login_name || "";
      passwordCode.textContent = entry.password || "";
      storedCell.textContent = entry.created_at || "";

      passwordCell.appendChild(passwordCode);
      row.appendChild(labelCell);
      row.appendChild(usernameCell);
      row.appendChild(passwordCell);
      row.appendChild(storedCell);
      tableBodyEl.appendChild(row);
    });
    tableEl.hidden = false;
    emptyEl.hidden = true;
  }

  // Unlock the vault using the passphrase and load entries.
  async function unlockVault() {
    setError("");
    if (!window.crypto || !window.crypto.subtle) {
      setError("Web Crypto is not available in this browser.");
      return;
    }
    var passphrase = passphraseInput.value || "";
    if (!passphrase.trim()) {
      setError("Vault passphrase is required.");
      return;
    }
    try {
      var key = await deriveKey(passphrase);
      var payload = await fetchVault();
      var hasPayload = Boolean(payload && payload.ciphertext && payload.nonce);
      if (!hasPayload) {
        var loginPassword = loginPasswordInput ? loginPasswordInput.value : "";
        if (!loginPassword.trim()) {
          setError("Login password is required to set the vault passphrase.");
          return;
        }
        if (loginPassword === passphrase) {
          setError("Vault passphrase must differ from the login password.");
          return;
        }
        if (!passphraseConfirmInput || passphraseConfirmInput.value !== passphrase) {
          setError("Confirm your vault passphrase to set it.");
          return;
        }
        cachedKey = key;
        entries = [];
        await saveVault(entries);
        vaultInitialized = true;
        updatePassphraseUi();
      } else {
        entries = await decryptEntries(payload, key);
      }
      cachedKey = key;
      unlockExpiresAt = Date.now() + unlockDurationMs;
      renderEntries();
      setLockedState(false);
      startCountdown();
    } catch (err) {
      lockVault();
      setError("Unable to unlock vault. Check your passphrase.");
    }
  }

  // Add a new entry, re-encrypt, and save the vault.
  async function addEntry() {
    setError("");
    if (!cachedKey) {
      setError("Unlock the vault before adding entries.");
      return;
    }
    var label = labelInput.value.trim();
    var username = usernameInput.value.trim();
    var password = passwordInput.value;
    if (!label || !username || !password) {
      setError("All fields are required to store a password.");
      return;
    }
    var entry = {
      label: label,
      login_name: username,
      password: password,
      created_at: new Date().toISOString(),
    };
    entries = [entry].concat(entries);
    try {
      await saveVault(entries);
    } catch (err) {
      setError("Unable to save vault data. Please try again.");
      entries = entries.slice(1);
      return;
    }
    labelInput.value = "";
    usernameInput.value = "";
    passwordInput.value = "";
    renderEntries();
  }

  unlockButton.addEventListener("click", unlockVault);
  addButton.addEventListener("click", addEntry);
  setLockedState(true);
  detectVaultState();
})();
