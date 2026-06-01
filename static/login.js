/* Fleet multi-user login */
document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('login-form');
  var pwInput = document.getElementById('pw');
  var userInput = document.getElementById('username');
  var passkeyBtn = document.getElementById('passkey-login');

  if (!form || !pwInput) return;

  var invalidPw = form.getAttribute('data-invalid-pw') || 'Invalid username or password';
  var connFailed = form.getAttribute('data-conn-failed') || 'Connection failed';

  function showErr(msg) {
    var err = document.getElementById('err');
    if (err) { err.textContent = msg; err.style.display = 'block'; }
  }

  function hideErr() {
    var err = document.getElementById('err');
    if (err) { err.style.display = 'none'; }
  }

  function _safeNextPath() {
    try {
      var raw = new URL(window.location.href).searchParams.get('next');
      if (!raw) return './';
      if (raw.charAt(0) !== '/') return './';
      if (raw.charAt(1) === '/' || raw.charAt(1) === '\\\\') return './';
      if (/[\\x00-\\x1f\\x7f\\s]/.test(raw)) return './';
      return raw;
    } catch (_) { return './'; }
  }

  async function doLogin(e) {
    e.preventDefault();
    var username = userInput ? userInput.value.trim().toLowerCase() : '';
    var pw = pwInput.value;
    hideErr();
    try {
      var res = await fetch('api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: pw }),
        credentials: 'include',
      });
      var data = {};
      try { data = await res.json(); } catch (_) {}
      if (res.ok && data.ok) {
        window.location.href = _safeNextPath();
      } else {
        showErr(data.error || invalidPw);
      }
    } catch (ex) {
      showErr(connFailed);
    }
  }

  form.addEventListener('submit', doLogin);

  // Passkey support (unchanged)
  function b64uToBytes(s) {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64u(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
  }

  async function doPasskeyLogin() {
    if (!window.PublicKeyCredential || !navigator.credentials) return;
    hideErr();
    try {
      passkeyBtn.disabled = true;
      var optRes = await fetch('api/auth/passkey/options', { method: 'POST', body: '{}', credentials: 'include' });
      var optData = await optRes.json();
      if (!optRes.ok || !optData.publicKey) throw new Error(optData.error || 'Passkey unavailable');
      var pk = optData.publicKey;
      pk.challenge = b64uToBytes(pk.challenge);
      if (Array.isArray(pk.allowCredentials)) {
        pk.allowCredentials = pk.allowCredentials.map(function (c) { return Object.assign({}, c, { id: b64uToBytes(c.id) }); });
      }
      var cred = await navigator.credentials.get({ publicKey: pk });
      if (!cred) throw new Error('Passkey sign-in cancelled');
      var payload = {
        id: cred.id, rawId: bytesToB64u(cred.rawId), type: cred.type,
        response: {
          authenticatorData: bytesToB64u(cred.response.authenticatorData),
          clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
          signature: bytesToB64u(cred.response.signature),
          userHandle: cred.response.userHandle ? bytesToB64u(cred.response.userHandle) : null,
        },
      };
      var res = await fetch('api/auth/passkey/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload), credentials: 'include',
      });
      var data = {};
      try { data = await res.json(); } catch (_) {}
      if (res.ok && data.ok) window.location.href = _safeNextPath();
      else showErr(data.error || invalidPw);
    } catch (ex) {
      showErr(ex && ex.message ? ex.message : connFailed);
    } finally {
      passkeyBtn.disabled = false;
    }
  }

  if (passkeyBtn && window.PublicKeyCredential && navigator.credentials) {
    fetch('api/auth/status', { credentials: 'include' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s && s.passkeys_enabled) passkeyBtn.style.display = 'block'; })
      .catch(function () {});
    passkeyBtn.addEventListener('click', doPasskeyLogin);
  }

  pwInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); doLogin(e); }
  });

  (function checkConnectivity() {
    var retryTimer = null;
    function setFormDisabled(disabled) {
      if (pwInput) pwInput.disabled = disabled;
      if (userInput) userInput.disabled = disabled;
      var btn = form.querySelector('button');
      if (btn) btn.disabled = disabled;
    }
    function probe() {
      fetch('health', { method: 'GET', credentials: 'same-origin' })
        .then(function (r) {
          if (r.ok) {
            if (retryTimer !== null) { clearTimeout(retryTimer); retryTimer = null; window.location.reload(); }
          } else {
            showErr(connFailed + ' (server error ' + r.status + ')');
          }
        })
        .catch(function () {
          showErr('Cannot reach server');
          setFormDisabled(true);
          if (retryTimer === null) { retryTimer = setInterval(probe, 3000); }
        });
    }
    probe();
  })();
});