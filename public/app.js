import { createUser, getConnections, getAuthUrl, disconnect } from './api.js';

// Local storage key names
const TOKEN_KEY = 'oauthflow_token';
const EMAIL_KEY = 'oauthflow_email';

// Safe localStorage accessors
function getStoredItem(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function setStoredItem(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (err) {
    console.warn('LocalStorage write failed:', err);
  }
}

function removeStoredItem(key) {
  try {
    localStorage.removeItem(key);
  } catch (err) {
    console.warn('LocalStorage remove failed:', err);
  }
}

// DOM Elements
const statusBanner = document.getElementById('status-banner');
const signedOutView = document.getElementById('signed-out-view');
const signedInView = document.getElementById('signed-in-view');

const loginForm = document.getElementById('login-form');
const emailInput = document.getElementById('email-input');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');

const userEmailEl = document.getElementById('user-email');
const signoutBtn = document.getElementById('signout-btn');
const refreshListBtn = document.getElementById('refresh-list-btn');

const connectionsList = document.getElementById('connections-list');
const emptyState = document.getElementById('empty-state');
const loadingSpinner = document.getElementById('loading-spinner');
const connectGoogleBtn = document.getElementById('connect-google-btn');

// Banner helper
function showBanner(message, type = 'info') {
  statusBanner.textContent = message;
  statusBanner.className = `banner banner-${type}`;
  statusBanner.classList.remove('hidden');
}

function hideBanner() {
  statusBanner.classList.add('hidden');
  statusBanner.textContent = '';
}

// Switch UI views
function showSignedInView(email) {
  signedOutView.classList.add('hidden');
  signedInView.classList.remove('hidden');
  userEmailEl.textContent = email;
  hideLoginError();
}

function showSignedOutView() {
  signedInView.classList.add('hidden');
  signedOutView.classList.remove('hidden');
  userEmailEl.textContent = '';
  connectionsList.replaceChildren();
  emptyState.classList.add('hidden');
}

function showLoginError(msg) {
  loginError.textContent = msg;
  loginError.classList.remove('hidden');
}

function hideLoginError() {
  loginError.textContent = '';
  loginError.classList.add('hidden');
}

// Handle 401 Unauthorized / Token Expiry
function handleAuthExpired() {
  removeStoredItem(TOKEN_KEY);
  removeStoredItem(EMAIL_KEY);
  showSignedOutView();
  showBanner('Session expired or invalid. Please sign in again.', 'error');
}

// Fetch and render connections list
async function loadConnections() {
  const token = getStoredItem(TOKEN_KEY);
  if (!token) {
    handleAuthExpired();
    return;
  }

  loadingSpinner.classList.remove('hidden');
  emptyState.classList.add('hidden');
  connectionsList.replaceChildren();

  try {
    const connections = await getConnections(token);
    loadingSpinner.classList.add('hidden');

    if (!Array.isArray(connections) || connections.length === 0) {
      emptyState.classList.remove('hidden');
      return;
    }

    connections.forEach((conn) => {
      const itemEl = document.createElement('div');
      itemEl.className = 'connection-item';

      const mainEl = document.createElement('div');
      mainEl.className = 'connection-main';

      const titleEl = document.createElement('div');
      titleEl.className = 'provider-title';
      titleEl.textContent = conn.provider;

      const badge = document.createElement('span');
      badge.className = 'badge-connected';
      badge.textContent = 'Active';
      titleEl.appendChild(badge);

      const scopesEl = document.createElement('div');
      scopesEl.className = 'scopes-meta';
      scopesEl.textContent = `Scopes: ${Array.isArray(conn.scopes) ? conn.scopes.join(', ') : 'standard'}`;

      const metaEl = document.createElement('div');
      metaEl.className = 'connection-meta';
      const formattedDate = conn.connectedAt ? new Date(conn.connectedAt).toLocaleString() : 'Recently';
      metaEl.textContent = `Connected: ${formattedDate}`;

      mainEl.appendChild(titleEl);
      mainEl.appendChild(scopesEl);
      mainEl.appendChild(metaEl);

      const disconnectBtn = document.createElement('button');
      disconnectBtn.type = 'button';
      disconnectBtn.className = 'btn btn-danger-outline btn-sm';
      disconnectBtn.textContent = 'Disconnect';

      disconnectBtn.addEventListener('click', async () => {
        disconnectBtn.disabled = true;
        disconnectBtn.textContent = 'Disconnecting...';
        try {
          await disconnect(token, conn.provider);
          showBanner(`Successfully disconnected ${conn.provider}.`, 'success');
          await loadConnections();
        } catch (err) {
          disconnectBtn.disabled = false;
          disconnectBtn.textContent = 'Disconnect';
          if (err.status === 401) {
            handleAuthExpired();
          } else {
            showBanner(`Failed to disconnect: ${err.message}`, 'error');
          }
        }
      });

      itemEl.appendChild(mainEl);
      itemEl.appendChild(disconnectBtn);
      connectionsList.appendChild(itemEl);
    });
  } catch (err) {
    loadingSpinner.classList.add('hidden');
    if (err.status === 401) {
      handleAuthExpired();
    } else {
      showBanner(`Could not load connections: ${err.message}`, 'error');
    }
  }
}

// Event Listeners

// 1. Sign In Form Submission
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideLoginError();
  hideBanner();

  const email = emailInput.value.trim().toLowerCase();
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

  if (!email || !emailRegex.test(email)) {
    showLoginError('Please enter a valid email address format (e.g. you@create-ed.in).');
    emailInput.focus();
    return;
  }

  if (!email.endsWith('@create-ed.in')) {
    showLoginError('Only @create-ed.in work email addresses are permitted.');
    emailInput.focus();
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = 'Signing in...';

  try {
    const data = await createUser(email);
    setStoredItem(TOKEN_KEY, data.token);
    setStoredItem(EMAIL_KEY, data.email);

    showSignedInView(data.email);
    await loadConnections();
  } catch (err) {
    showLoginError(err.message || 'Failed to sign in. Please try again.');
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Continue';
  }
});

// 2. Sign Out Button
signoutBtn.addEventListener('click', () => {
  removeStoredItem(TOKEN_KEY);
  removeStoredItem(EMAIL_KEY);
  showSignedOutView();
  showBanner('Signed out successfully.', 'info');
});

// 3. Refresh List Button
refreshListBtn.addEventListener('click', () => {
  loadConnections();
});

// 4. Connect Google Account Button
connectGoogleBtn.addEventListener('click', async () => {
  const token = getStoredItem(TOKEN_KEY);
  if (!token) {
    handleAuthExpired();
    return;
  }

  connectGoogleBtn.disabled = true;
  connectGoogleBtn.textContent = 'Redirecting to Google...';

  try {
    const data = await getAuthUrl(token, 'google');
    if (data.authUrl) {
      // Top-level navigation to Google OAuth consent page
      window.location.href = data.authUrl;
    } else {
      throw new Error('Authorization URL not returned from server');
    }
  } catch (err) {
    connectGoogleBtn.disabled = false;
    connectGoogleBtn.textContent = 'Connect Google Account';
    if (err.status === 401) {
      handleAuthExpired();
    } else {
      showBanner(`Could not start authorization: ${err.message}`, 'error');
    }
  }
});

// App Initialization
function initApp() {
  // Check URL search parameters for OAuth callback flash notices
  const params = new URLSearchParams(window.location.search);
  const connectedProvider = params.get('connected');
  const oauthError = params.get('error');

  if (connectedProvider) {
    showBanner(`Successfully connected ${connectedProvider.toUpperCase()} account!`, 'success');
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (oauthError) {
    showBanner(`OAuth authorization was cancelled or failed: ${oauthError}`, 'error');
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  const token = getStoredItem(TOKEN_KEY);
  const email = getStoredItem(EMAIL_KEY);

  if (token && email) {
    showSignedInView(email);
    loadConnections();
  } else {
    showSignedOutView();
  }
}

// Run initialization on DOM load
initApp();
