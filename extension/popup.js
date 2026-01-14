(() => {
  const DEFAULT_SERVER = "http://127.0.0.1:5000";
  const UNLOCK_WINDOW_MS = 5 * 60 * 1000;

  const serverInput = document.getElementById("server-url");
  const saveServerButton = document.getElementById("save-server");
  const authStatusEl = document.getElementById("auth-status");
  const loginForm = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  const toggleAuthButton = document.getElementById("toggle-auth-mode");
  const logoutButton = document.getElementById("logout-button");
  const loginUsernameInput = document.getElementById("login-username");
  const loginPasswordInput = document.getElementById("login-password");
  const registerUsernameInput = document.getElementById("register-username");
  const registerPasswordInput = document.getElementById("register-password");
  const loginButton = document.getElementById("login-button");
  const registerButton = document.getElementById("register-button");
  const vaultSection = document.getElementById("vault-section");
  const statusText = document.getElementById("status-text");
  const errorEl = document.getElementById("vault-error");
  const lockedStateEl = document.getElementById("locked-state");
  const contentEl = document.getElementById("vault-content");
  const setupExtra = document.getElementById("setup-extra");
  const passphraseInput = document.getElementById("vault-passphrase");
  const passphraseConfirmInput = document.getElementById("vault-passphrase-confirm");
  const passphraseVerifyInput = document.getElementById("vault-login-password");
  const timerRemainingEl = document.getElementById("timer-remaining");
  const labelInput = document.getElementById("vault-label");
  const usernameInput = document.getElementById("vault-username");
  const passwordInput = document.getElementById("vault-password");
  const addForm = document.getElementById("vault-add-form");
  const tableEl = document.getElementById("vault-table");
  const tableBodyEl = document.getElementById("vault-table-body");
  const emptyEl = document.getElementById("vault-empty");
  const unlockButton = document.getElementById("vault-unlock-button");

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const state = {
    serverUrl: DEFAULT_SERVER,
    accessToken: null,
    refreshToken: null,
    vaultSalt: "",
    vaultInitialized: false,
    cachedKey: null,
    unlockExpiresAt: 0,
    countdownTimer: null,
    entries: [],
    authMode: "login",
  };

  function setStatus(message) {
    statusText.textContent = message || "";
  }

  function setError(message) {
    if (!message) {
      errorEl.hidden = true;
      errorEl.textContent = "";
      return;
    }
    errorEl.hidden = false;
    errorEl.textContent = message;
  }

  function setLockedState(locked) {
    lockedStateEl.hidden = !locked;
    contentEl.hidden = locked;
  }

  function updateSetupVisibility() {
    setupExtra.hidden = state.vaultInitialized;
    if (state.vaultInitialized) {
      passphraseVerifyInput.value = "";
      passphraseConfirmInput.value = "";
    }
  }

  function lockVault() {
    state.cachedKey = null;
    state.entries = [];
    state.unlockExpiresAt = 0;
    if (state.countdownTimer) {
      window.clearInterval(state.countdownTimer);
      state.countdownTimer = null;
    }
    renderEntries();
    setLockedState(true);
    timerRemainingEl.textContent = "0";
    setError("");
  }

  function updateCountdown() {
    if (!state.unlockExpiresAt) {
      return;
    }
    const remainingMs = state.unlockExpiresAt - Date.now();
    if (remainingMs <= 0) {
      lockVault();
      return;
    }
    timerRemainingEl.textContent = String(Math.ceil(remainingMs / 1000));
  }

  function startCountdown() {
    updateCountdown();
    if (state.countdownTimer) {
      window.clearInterval(state.countdownTimer);
    }
    state.countdownTimer = window.setInterval(updateCountdown, 1000);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, i + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function deriveKey(passphrase) {
    if (!state.vaultSalt) {
      throw new Error("Missing vault salt. Please log in again.");
    }
    const saltBytes = base64ToBytes(state.vaultSalt);
    const baseKey = await crypto.subtle.importKey(
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

  async function decryptEntries(payload, key) {
    if (!payload || !payload.ciphertext || !payload.nonce) {
      return [];
    }
    const nonce = base64ToBytes(payload.nonce);
    const ciphertext = base64ToBytes(payload.ciphertext);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      ciphertext
    );
    const decoded = textDecoder.decode(new Uint8Array(plaintext));
    const data = JSON.parse(decoded);
    return Array.isArray(data) ? data : [];
  }

  async function encryptEntries(items, key) {
    const payload = textEncoder.encode(JSON.stringify(items));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      payload
    );
    return {
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
  }

  function setAuthMode(mode) {
    state.authMode = mode;
    const loginVisible = mode === "login";
    loginForm.hidden = !loginVisible;
    registerForm.hidden = loginVisible;
    toggleAuthButton.textContent = loginVisible ? "Need an account? Register" : "Have an account? Login";
  }

  function setLoggedIn(loggedIn) {
    vaultSection.hidden = !loggedIn;
    logoutButton.hidden = !loggedIn;
    loginButton.disabled = loggedIn;
    registerButton.disabled = loggedIn;
    if (loggedIn) {
      authStatusEl.textContent = "Authenticated.";
      lockVault();
    } else {
      authStatusEl.textContent = "Not authenticated.";
      lockVault();
    }
  }

  function getStoredConfig() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ serverUrl: DEFAULT_SERVER }, (items) => {
        resolve(items.serverUrl || DEFAULT_SERVER);
      });
    });
  }

  function storeConfig(url) {
    return new Promise((resolve) => {
      chrome.storage.sync.set({ serverUrl: url }, resolve);
    });
  }

  function getStoredTokens() {
    return new Promise((resolve) => {
      chrome.storage.local.get(
        { accessToken: null, refreshToken: null, vaultSalt: "" },
        (items) => resolve(items)
      );
    });
  }

  function storeTokens(accessToken, refreshToken, vaultSalt) {
    state.accessToken = accessToken;
    state.refreshToken = refreshToken;
    if (vaultSalt) {
      state.vaultSalt = vaultSalt;
    }
    return new Promise((resolve) => {
      chrome.storage.local.set(
        { accessToken, refreshToken, vaultSalt: state.vaultSalt },
        resolve
      );
    });
  }

  function clearTokens() {
    state.accessToken = null;
    state.refreshToken = null;
    state.vaultSalt = "";
    return new Promise((resolve) => {
      chrome.storage.local.remove(["accessToken", "refreshToken", "vaultSalt"], resolve);
    });
  }

  async function jsonFetch(path, payload) {
    const response = await fetch(`${state.serverUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }
    return data;
  }

  async function refreshTokens() {
    if (!state.refreshToken) {
      await clearTokens();
      return false;
    }
    try {
      const data = await jsonFetch("/api/auth/refresh", {
        refresh_token: state.refreshToken,
      });
      await storeTokens(data.access_token, data.refresh_token, state.vaultSalt);
      return true;
    } catch (err) {
      await clearTokens();
      setLoggedIn(false);
      setError("Session expired. Login again.");
      return false;
    }
  }

  async function authFetch(path, options = {}, retry = true) {
    if (!state.accessToken) {
      throw new Error("Login required.");
    }
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${state.accessToken}`);
    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(`${state.serverUrl}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body,
    });
    if (response.status === 401 && retry && (await refreshTokens())) {
      return authFetch(path, options, false);
    }
    return response;
  }

  async function fetchVaultPayload() {
    const response = await authFetch("/api/vault");
    if (!response.ok) {
      throw new Error("Unable to load vault data.");
    }
    const data = await response.json();
    if (data.vault_salt) {
      state.vaultSalt = data.vault_salt;
      await storeTokens(state.accessToken, state.refreshToken, state.vaultSalt);
    }
    state.vaultInitialized = Boolean(data.ciphertext && data.nonce);
    updateSetupVisibility();
    return data;
  }

  async function saveVault(items) {
    const payload = await encryptEntries(items, state.cachedKey);
    const response = await authFetch("/api/vault", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error("Unable to save vault data.");
    }
  }

  async function verifyLoginPassword(password) {
    const response = await authFetch("/api/verify-login", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    if (!response.ok) {
      throw new Error("Incorrect login password.");
    }
    const data = await response.json();
    if (!data.ok) {
      throw new Error("Incorrect login password.");
    }
  }

  function renderEntries() {
    tableBodyEl.textContent = "";
    if (!state.entries.length) {
      tableEl.hidden = true;
      emptyEl.hidden = false;
      return;
    }
    state.entries.forEach((entry) => {
      const row = document.createElement("tr");
      const labelCell = document.createElement("td");
      const usernameCell = document.createElement("td");
      const passwordCell = document.createElement("td");
      const storedCell = document.createElement("td");
      const passwordCode = document.createElement("code");

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

  async function unlockVault(event) {
    if (event) {
      event.preventDefault();
    }
    if (!state.accessToken) {
      setError("Login before unlocking the vault.");
      return;
    }
    setError("");
    setStatus("Unlocking vault…");
    try {
      const payload = await fetchVaultPayload();
      const passphrase = passphraseInput.value.trim();
      if (!passphrase) {
        throw new Error("Vault passphrase is required.");
      }
      const key = await deriveKey(passphrase);
      if (!state.vaultInitialized) {
        const loginPassword = passphraseVerifyInput.value.trim();
        if (!loginPassword) {
          throw new Error("Login password is required to set the vault passphrase.");
        }
        if (loginPassword === passphrase) {
          throw new Error("Vault passphrase must differ from the login password.");
        }
        if (passphraseConfirmInput.value !== passphrase) {
          throw new Error("Confirm your vault passphrase.");
        }
        await verifyLoginPassword(loginPassword);
        state.cachedKey = key;
        state.entries = [];
        await saveVault(state.entries);
        state.vaultInitialized = true;
        updateSetupVisibility();
      } else {
        state.entries = await decryptEntries(payload, key);
      }
      state.cachedKey = key;
      state.unlockExpiresAt = Date.now() + UNLOCK_WINDOW_MS;
      renderEntries();
      setLockedState(false);
      startCountdown();
      setStatus("Vault unlocked.");
    } catch (err) {
      lockVault();
      setError(err.message || "Unable to unlock vault.");
      setStatus("Vault locked.");
    }
  }

  async function addEntry(event) {
    event.preventDefault();
    setError("");
    if (!state.cachedKey) {
      setError("Unlock the vault before adding entries.");
      return;
    }
    const label = labelInput.value.trim();
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!label || !username || !password) {
      setError("All fields are required.");
      return;
    }
    const entry = {
      label,
      login_name: username,
      password,
      created_at: new Date().toISOString(),
    };
    state.entries = [entry].concat(state.entries);
    try {
      await saveVault(state.entries);
      labelInput.value = "";
      usernameInput.value = "";
      passwordInput.value = "";
      renderEntries();
      setStatus("Entry saved.");
    } catch (err) {
      state.entries = state.entries.slice(1);
      setError(err.message || "Unable to save entry.");
    }
  }

  async function handleLogin() {
    try {
      const username = loginUsernameInput.value.trim();
      const password = loginPasswordInput.value;
      if (!username || !password) {
        throw new Error("Enter username and password.");
      }
      const data = await jsonFetch("/api/auth/login", { username, password });
      await storeTokens(data.access_token, data.refresh_token, data.vault_salt);
      setLoggedIn(true);
      try {
        await fetchVaultPayload();
      } catch (err) {
        // ignore initial load errors
      }
      setStatus("Logged in.");
    } catch (err) {
      setError(err.message || "Unable to login.");
    }
  }

  async function handleRegister() {
    try {
      const username = registerUsernameInput.value.trim();
      const password = registerPasswordInput.value;
      if (!username || !password) {
        throw new Error("Enter username and password.");
      }
      const data = await jsonFetch("/api/auth/register", { username, password });
      await storeTokens(data.access_token, data.refresh_token, data.vault_salt);
      setLoggedIn(true);
      state.vaultInitialized = false;
      updateSetupVisibility();
      setStatus("Account created. Set a vault passphrase.");
    } catch (err) {
      setError(err.message || "Unable to register.");
    }
  }

  async function handleLogout() {
    try {
      if (state.refreshToken) {
        await jsonFetch("/api/auth/logout", { refresh_token: state.refreshToken });
      }
    } catch (err) {
      // ignore errors on logout
    } finally {
      await clearTokens();
      setLoggedIn(false);
      state.vaultInitialized = false;
      updateSetupVisibility();
      setStatus("Logged out.");
    }
  }

  async function bootstrap() {
    setStatus("Loading configuration…");
    state.serverUrl = await getStoredConfig();
    serverInput.value = state.serverUrl;
    const tokenData = await getStoredTokens();
    state.accessToken = tokenData.accessToken;
    state.refreshToken = tokenData.refreshToken;
    state.vaultSalt = tokenData.vaultSalt || "";
    setStatus("Ready.");
    if (state.accessToken && state.refreshToken) {
      setLoggedIn(true);
      try {
        await fetchVaultPayload();
      } catch (err) {
        setError(err.message);
      }
    } else {
      setLoggedIn(false);
    }
  }

  saveServerButton.addEventListener("click", async () => {
    const url = serverInput.value.trim() || DEFAULT_SERVER;
    await storeConfig(url);
    state.serverUrl = url;
    await clearTokens();
    setLoggedIn(false);
    setStatus("Server saved. Please log in again.");
  });

  toggleAuthButton.addEventListener("click", () => {
    setAuthMode(state.authMode === "login" ? "register" : "login");
  });

  loginButton.addEventListener("click", (event) => {
    event.preventDefault();
    handleLogin();
  });

  registerButton.addEventListener("click", (event) => {
    event.preventDefault();
    handleRegister();
  });

  logoutButton.addEventListener("click", (event) => {
    event.preventDefault();
    handleLogout();
  });

  unlockButton.addEventListener("click", unlockVault);
  addForm.addEventListener("submit", addEntry);

  setAuthMode("login");
  bootstrap();
})();
