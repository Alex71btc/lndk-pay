/* Shared Setup/Pay backend selector. Only BOLT11 is enabled for Phoenixd. */
(() => {
  const t = (key) => window.__t ? window.__t(`backend.${key}`) : key;
  const cookie = () => document.cookie.split('; ').find(x => x.startsWith('csrf_token='))?.split('=')[1] || '';
  const api = async (path, payload) => {
    const response = await fetch(path, payload === undefined ? {cache: 'no-store'} : {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': cookie()},
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : t('error'));
    return result;
  };
  window.LightningBackend = {id: null};
  let current = null;
  function render() {
    const phoenix = current && current.active !== 'lnd-default';
    const label = current ? (phoenix ? 'Phoenixd' : 'LND') : t('unavailable');
    document.querySelectorAll('[data-lightning-backend-label]').forEach(el => {
      el.textContent = '';
      el.style.display = 'flex';
      el.style.alignItems = 'center';
      el.style.flexWrap = 'wrap';
      el.style.gap = '6px 9px';
      el.style.fontSize = '16px';
      el.style.lineHeight = '1.5';
      const caption = document.createElement('span');
      caption.textContent = `${t('active')}:`;
      caption.style.cssText = 'color:#cbd5e1;font-weight:400';
      const identity = document.createElement('span');
      identity.style.cssText = 'display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-weight:600';
      if (current) {
        const icon = document.createElement('img');
        icon.src = `/assets/backend-icons/${phoenix ? 'phoenixd' : 'lnd'}.svg?v=5`;
        icon.alt = phoenix ? '' : 'LND';
        if (phoenix) icon.setAttribute('aria-hidden', 'true');
        icon.width = phoenix ? 27 : 34;
        icon.height = phoenix ? 24 : 20;
        icon.style.cssText = 'display:block;object-fit:contain;flex:none';
        if (!phoenix) {
          // The wordmark supplies the visible and accessible backend name.
          icon.onerror = () => { identity.textContent = 'LND'; };
        }
        identity.append(icon);
      }
      if (!current || phoenix) identity.append(document.createTextNode(label));
      el.append(caption, identity);

    });
    document.querySelectorAll('[data-phoenix-tools]').forEach(el => { el.hidden = !current; });
    updateSelection();
    document.querySelectorAll('#lightningBackendPanel [data-backend-text], [data-phoenix-tools] [data-backend-text]').forEach(el => {
      el.textContent = t(el.dataset.backendText);
    });
  }
  function updateSelection() {
    const select = document.getElementById('lightningBackendSelect');
    if (!select) return;
    const phoenix = select.value === 'phoenixd';
    const fields = document.getElementById('phoenixdFields');
    fields.hidden = !phoenix;
    fields.querySelectorAll('input, button').forEach(el => { el.disabled = !phoenix; });
    document.getElementById('lndBackendHint').hidden = phoenix;
    const saved = current?.active === 'lnd-default' ? 'lnd-default' : current ? 'phoenixd' : null;
    const pending = document.getElementById('backendUnsaved');
    pending.textContent = saved && select.value !== saved ? t('unsaved') : '';
  }
  async function refresh() {
    current = await api('/api/lightning-backend');
    window.LightningBackend.id = current.active;
    render();
  }
  async function init() {
    for (const buttonId of ['payOfferBtn', 'createInvoiceBtn']) {
      const button = document.getElementById(buttonId);
      if (button) {
        const label = document.createElement('p');
        label.dataset.lightningBackendLabel = '';
        label.setAttribute('role', 'status');
        label.style.cssText = 'font-size:16px;line-height:1.5;overflow-wrap:anywhere';
        button.parentElement.insertAdjacentElement('beforebegin', label);
      }
    }
    const style = document.createElement('style');
    style.textContent = `
      [data-phoenix-tools] .lnurl-lock-shackle { transform-origin:16px 11px;transition:transform .2s ease; }
      [data-phoenix-tools][open] .lnurl-lock-shackle { transform:rotate(28deg); }
      @media (prefers-reduced-motion:reduce) {
        [data-phoenix-tools] .lnurl-lock-shackle { transition:none; }
      }
      #lightningBackendPanel > h2 { margin:0 0 4px; }
      #lightningBackendPanel > p { margin:0;line-height:1.5; }
      #lightningBackendPanel > p:empty { display:none; }
      #lightningBackendPanel > .row { margin-top:4px; }
    `;
    document.head.append(style);
    const setup = document.getElementById('setupCard');
    if (setup) {
      const panel = document.createElement('section');
      panel.id = 'lightningBackendPanel';
      panel.style.cssText = 'border:1px solid #475569;border-radius:14px;padding:16px;margin:20px 0;display:grid;gap:10px';
      panel.innerHTML = `
        <h2 data-backend-text="title"></h2>
        <p data-backend-text="hint"></p>
        <p data-lightning-backend-label role="status" style="font-size:16px;padding:10px 0"></p>
        <label for="lightningBackendSelect" data-backend-text="selection"></label>
        <select id="lightningBackendSelect"><option value="lnd-default">LND</option><option value="phoenixd">Phoenixd</option></select>
        <p id="backendUnsaved" role="status"></p>
        <p id="lndBackendHint" data-backend-text="lnd_hint"></p>
        <fieldset id="phoenixdFields" style="border:0;padding:0;margin:0">
        <div style="display:grid;gap:10px">
        <label for="phoenixdUrl" data-backend-text="url"></label>
        <input id="phoenixdUrl" type="url" placeholder="http://host.docker.internal:9740" autocomplete="off">
        <label for="phoenixdPassword" data-backend-text="password"></label>
        <input id="phoenixdPassword" type="password" autocomplete="new-password">
        <small data-backend-text="keep_password"></small>
        <div class="row"><button id="testPhoenixdBtn" type="button" data-backend-text="test"></button></div>
        </div></fieldset>
        <div class="row"><button id="saveBackendBtn" type="button" data-backend-text="save"></button></div>
        <p id="backendResult" role="status" style="overflow-wrap:anywhere"></p>`;
      // This section has its own Save button; public addresses are untouched.
      setup.append(panel);
      const result = panel.querySelector('#backendResult');
      async function submit(test) {
        const buttons = panel.querySelectorAll('button');
        buttons.forEach(button => { button.disabled = true; });
        result.textContent = t('working');
        try {
          const active = panel.querySelector('select').value;
          const data = {active, url: panel.querySelector('#phoenixdUrl').value.trim(), password: panel.querySelector('#phoenixdPassword').value};
          // Selecting LND must work even when the configured Phoenixd is offline.
          const payload = !test && active === 'lnd-default' ? {active} : data;
          await api('/api/setup/lightning-backend' + (test ? '/test' : ''), payload);
          result.textContent = t(test ? 'connected' : 'saved');
          if (!test) { panel.querySelector('#phoenixdPassword').value = ''; await refresh(); }
        } catch (error) { result.textContent = error.message; }
        finally { buttons.forEach(button => { button.disabled = false; }); updateSelection(); }
      }
      panel.querySelector('select').onchange = updateSelection;
      panel.querySelector('#testPhoenixdBtn').onclick = () => submit(true);
      panel.querySelector('#saveBackendBtn').onclick = () => submit(false);
    }
    const payButton = document.getElementById('payOfferBtn');
    if (payButton) {
      const tools = document.createElement('details');
      tools.dataset.phoenixTools = '';
      tools.hidden = true;
      tools.style.cssText = 'margin:16px 0;border:1px solid #334155;border-radius:12px;background:#111c2e;padding:0 14px';
      tools.innerHTML = `<summary style="cursor:pointer;padding:13px 0;font-weight:600;color:#e2e8f0;line-height:1.5">
          <svg aria-hidden="true" width="24" height="26" viewBox="0 0 24 26" fill="none" stroke="#5eead4" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-7px;margin:0 8px 0 3px;overflow:visible"><path class="lnurl-lock-shackle" d="M8 11V7a4 4 0 0 1 8 0v4"/><rect x="5" y="11" width="14" height="11" rx="3" fill="rgba(94,234,212,.1)"/><circle cx="12" cy="16" r="1" fill="#5eead4" stroke="none"/><path d="M12 17v2"/></svg><span data-backend-text="lnurl_tools"></span></summary>
        <div style="display:grid;gap:10px;padding:4px 0 14px">
          <p data-backend-text="lnurl_hint"></p>
          <label data-backend-text="lnurl_input" for="phoenixLnurl"></label>
          <input id="phoenixLnurl" type="text" placeholder="lnurl1…" autocomplete="off">
          <div class="row"><button type="button" data-lnurl-scan aria-label="Scan LNURL QR">▣ QR</button><button type="button" data-lnurl-action="withdraw" data-backend-text="withdraw"></button>
          <button type="button" data-lnurl-action="auth" data-backend-text="auth"></button></div>
          <p role="status" aria-live="polite" id="phoenixLnurlResult" style="margin:0;overflow-wrap:anywhere"></p>
        </div>`;
      payButton.parentElement.insertAdjacentElement('afterend', tools);
      tools.querySelector('[data-lnurl-scan]').onclick = () => window.dispatchEvent(new Event('lightning:scan-lnurl'));
      window.addEventListener('lightning:lnurl-scanned', async () => {
        try {
          const info = await api('/api/lightning/lnurl-info', {backend_id: window.LightningBackend.id,
            lnurl: tools.querySelector('input').value.trim(), action: 'auth'});
          if (info.action === 'auth') tools.querySelector('[data-lnurl-action="auth"]').click();
        } catch (error) { tools.querySelector('#phoenixLnurlResult').textContent = error.message; }
      });
      tools.querySelectorAll('[data-lnurl-action]').forEach(button => {
        button.onclick = async () => {
          const result = tools.querySelector('#phoenixLnurlResult');
          tools.querySelectorAll('button').forEach(el => { el.disabled = true; });
          result.style.cssText = 'margin:0;overflow-wrap:anywhere';
          result.textContent = t('working');
          const backendId = window.LightningBackend.id;
          try {
            if (button.dataset.lnurlAction === 'auth') {
              const info = await api('/api/lightning/lnurl-info', {backend_id: backendId,
                lnurl: tools.querySelector('input').value.trim(), action: 'auth'});
              if (!window.confirm(`${t('auth')}: ${info.domain}?`)) { result.textContent = ''; return; }
            }
            await api('/api/lightning/lnurl-action', {backend_id: backendId,
              lnurl: tools.querySelector('input').value.trim(), action: button.dataset.lnurlAction});
            const message = t(button.dataset.lnurlAction === 'auth' ? 'auth_done' : 'lnurl_done');
            result.textContent = message;
            result.style.cssText += ';color:#8fe388;padding:12px;border:1px solid #365648;border-radius:8px;background:rgba(143,227,136,.06)';
            if (window.matchMedia('(max-width: 640px)').matches) {
              requestAnimationFrame(() => result.scrollIntoView({block: 'center',
                behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'}));
            }
            window.dispatchEvent(new CustomEvent('lightning:toast', {detail: {message, type: 'ok'}}));
          } catch (error) {
            result.textContent = error.message;
            window.dispatchEvent(new CustomEvent('lightning:toast', {detail: {message: error.message, type: 'error'}}));
          }
          finally { tools.querySelectorAll('button').forEach(el => { el.disabled = false; }); }
        };
      });
    }
    render();
    try {
      await refresh();
      if (setup) {
        document.getElementById('lightningBackendSelect').value = current.active === 'lnd-default' ? 'lnd-default' : 'phoenixd';
        document.getElementById('phoenixdUrl').value = current.phoenixd?.url || '';
        updateSelection();
      }
    } catch (_) {
      const result = document.getElementById('backendResult');
      if (result) result.textContent = t('login_first');
      render();
    }
  }
  document.addEventListener('DOMContentLoaded', init);
  window.addEventListener('i18n:language-changed', render);
})();
