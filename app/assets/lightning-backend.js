/* Shared Setup/Pay backend selector for new interactive actions. */
(() => {
  const navigationFallback = {switch: 'Switch', configure: 'Configure', setup: 'Setup',
    switch_lnd: 'Switch to LND', switch_phoenix: 'Switch to Phoenixd'};
  const t = (key) => {
    const value = window.__t ? window.__t(`backend.${key}`) : '';
    return value && value !== `backend.${key}` ? value : navigationFallback[key] || key;
  };
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
    const liquidity = document.getElementById('liquiditySection');
    if (liquidity && current) liquidity.hidden = !current.lnd_configured;
    const phoenix = current && current.active !== 'lnd-default';
    const available = phoenix || current?.lnd_configured;
    const label = available ? (phoenix ? 'Phoenixd' : 'LND') : t(current ? 'no_wallet' : 'unavailable');
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
      if (available) {
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
      if (!available || phoenix) identity.append(document.createTextNode(label));
      el.append(caption, identity);
      if (!el.closest('#lightningBackendPanel')) {
        const setupLink = document.createElement('a');
        setupLink.href = '/app?setup=1#lightningBackendPanel';
        setupLink.textContent = t('configure');
        setupLink.style.cssText = 'font-size:13px;color:#94a3b8;text-underline-offset:3px';
        const canSwitch = current && (phoenix ? current.lnd_configured : current.phoenixd && !current.phoenixd.paused);
        if (canSwitch) {
          const switchButton = document.createElement('button');
          switchButton.type = 'button';
          switchButton.className = 'secondary';
          switchButton.textContent = t('switch');
          switchButton.title = t(phoenix ? 'switch_lnd' : 'switch_phoenix');
          switchButton.setAttribute('aria-label', switchButton.title);
          switchButton.style.cssText = 'font-size:13px;padding:5px 9px;width:auto;min-height:32px';
          switchButton.onclick = async () => {
            const expected = current.active;
            switchButton.disabled = true;
            try {
              await api('/api/setup/lightning-backend', {active: phoenix ? 'lnd-default' : 'phoenixd', expected_backend_id: expected});
              await refresh();
              window.dispatchEvent(new CustomEvent('lightning:toast', {detail: {message: t('saved'), type: 'ok'}}));
            } catch (error) {
              const notice = document.createElement('span');
              notice.setAttribute('role', 'alert');
              notice.textContent = error.message;
              notice.style.cssText = 'flex-basis:100%;color:#ff7b72;font-size:13px';
              el.querySelector('[role="alert"]')?.remove();
              el.append(notice);
              switchButton.disabled = false;
            }
          };
          el.append(switchButton);
        }
        const setupRow = document.createElement('span');
        setupRow.style.cssText = 'flex-basis:100%;line-height:1.25;margin-top:2px';
        setupRow.append(setupLink);
        el.append(setupRow);
      }


    });
    document.querySelectorAll('[data-phoenix-tools]').forEach(el => { el.hidden = !available; });
    updateSelection();
    document.querySelectorAll('#lightningBackendPanel [data-backend-text], [data-phoenix-tools] [data-backend-text]').forEach(el => {
      el.textContent = t(el.dataset.backendText);
    });
  }
  function updateSelection() {
    const select = document.getElementById('lightningBackendSelect');
    if (!select) return;
    const phoenix = select.value === 'phoenixd';
    const paused = Boolean(current?.phoenixd?.paused);
    select.querySelector('option[value="phoenixd"]').disabled = paused;
    const fields = document.getElementById('phoenixdFields');
    fields.hidden = !phoenix;
    fields.querySelectorAll('input, button').forEach(el => { el.disabled = !phoenix; });
    document.getElementById('lndBackendHint').hidden = phoenix;
    const saved = current?.active === 'lnd-default' ? 'lnd-default' : current ? 'phoenixd' : null;
    const pending = document.getElementById('backendUnsaved');
    pending.textContent = saved && select.value !== saved ? t('unsaved') : '';
    document.getElementById('phoenixdManagement').hidden = !current?.phoenixd;
    const toggle = document.getElementById('pausePhoenixdBtn');
    toggle.dataset.backendText = paused ? 'resume_phoenixd' : 'pause_phoenixd';
    toggle.textContent = t(toggle.dataset.backendText);
    document.getElementById('phoenixdPaused').hidden = !paused;
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
      #phoenixdManagement { display:flex;align-items:center;gap:6px 10px;flex-wrap:wrap; }
      #phoenixdPaused { font-size:.85rem;color:#94a3b8; }
      #phoenixdManagement button {
        width:auto;min-height:32px;padding:4px 9px;font-size:.82rem;
      }
      #pausePhoenixdBtn, #confirmPhoenixdAction[data-action="pause"] {
        color:#bfdbfe;background:#172b48;border:1px solid #35649a;
      }
      #pausePhoenixdBtn:hover, #confirmPhoenixdAction[data-action="pause"]:hover { background:#203b60; }
      #removePhoenixdBtn, #confirmPhoenixdAction[data-action="remove"] {
        color:#fecaca;background:#3b2029;border:1px solid #8b4553;
      }
      #removePhoenixdBtn:hover, #confirmPhoenixdAction[data-action="remove"]:hover { background:#522936; }
      #phoenixdOptions {
        box-sizing:border-box;width:min(440px, calc(100% - 32px));max-height:calc(100% - 32px);
        padding:16px;border:1px solid #475569;border-radius:14px;background:#0f172a;color:#e2e8f0;
      }
      #phoenixdOptions::backdrop { background:rgba(0,0,0,.6); }
      #phoenixdOptions h3 { margin:0 0 8px; }
      #phoenixdOptions p { margin:0 0 12px; }
      #phoenixdOptions label { display:flex;align-items:center;gap:8px; }
      #phoenixdOptions input { width:auto;flex:none; }
      #phoenixdOptions small { display:block;margin:6px 0 0 24px;color:#cbd5e1; }
      #deletePhoenixdPublicationsOption { margin-top:12px; }
      #phoenixdOptions .row { justify-content:flex-end; }
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
        <div id="phoenixdManagement" hidden>
          <strong>Phoenixd</strong>
          <span id="phoenixdPaused" hidden data-backend-text="phoenixd_paused"></span>
          <button id="pausePhoenixdBtn" type="button" class="secondary" data-backend-text="pause_phoenixd"></button>
          <button id="removePhoenixdBtn" type="button" class="secondary" data-backend-text="remove_phoenixd"></button>
        </div>
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
        <p id="backendResult" role="status" style="overflow-wrap:anywhere;white-space:pre-line"></p>
        <dialog id="phoenixdOptions" aria-labelledby="phoenixdOptionsTitle" aria-describedby="phoenixdOptionsMessage">
          <form method="dialog">
            <h3 id="phoenixdOptionsTitle">Phoenixd</h3>
            <p id="phoenixdOptionsMessage"></p>
            <div id="hidePhoenixdAliasesOption">
              <label><input id="hidePhoenixdAliases" type="checkbox">
                <span data-backend-text="hide_phoenixd_aliases"></span>
              </label>
              <small data-backend-text="hide_phoenixd_aliases_hint"></small>
            </div>
            <label id="deletePhoenixdHistoryOption">
              <input id="deletePhoenixdHistory" type="checkbox">
              <span data-backend-text="delete_phoenixd_history"></span>
            </label>
            <div id="deletePhoenixdPublicationsOption" hidden>
              <label><input id="deletePhoenixdPublications" type="checkbox">
                <span data-backend-text="delete_phoenixd_publications"></span>
              </label>
              <small data-backend-text="delete_phoenixd_publications_hint"></small>
            </div>
            <div class="row">
              <button value="cancel" class="secondary" data-backend-text="cancel" autofocus></button>
              <button value="confirm" id="confirmPhoenixdAction"></button>
            </div>
          </form>
        </dialog>`;
      // Backend choice comes before domain/DNS settings on a fresh installation.
      // Keep both Save buttons independent; do not reset the selected wallet.
      const generalSetup = setup.querySelector(':scope > section.section');
      if (generalSetup) setup.insertBefore(panel, generalSetup);
      else setup.append(panel);
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
      async function manage(action) {
        const deleteHistory = action === 'remove' && panel.querySelector('#deletePhoenixdHistory').checked;
        const deletePublications = action === 'remove' && panel.querySelector('#deletePhoenixdPublications').checked;
        const hideAliasPages = action === 'pause' ? panel.querySelector('#hidePhoenixdAliases').checked : undefined;
        const buttons = panel.querySelectorAll('button');
        buttons.forEach(button => { button.disabled = true; });
        result.textContent = t('working');
        try {
          current = await api('/api/setup/lightning-backend/phoenixd', {
            action, backend_id: current.phoenixd.id, revision: current.phoenixd.revision,
            delete_history: deleteHistory, hide_alias_pages: hideAliasPages, delete_publications: deletePublications,
          });
          window.LightningBackend.id = current.active;
          panel.querySelector('select').value = current.active === 'lnd-default' ? 'lnd-default' : 'phoenixd';
          panel.querySelector('#phoenixdUrl').value = current.phoenixd?.url || '';
          panel.querySelector('#phoenixdPassword').value = '';
          panel.querySelector('#deletePhoenixdHistory').checked = false;
          render();
          result.textContent = action === 'pause' ? '' : t(action === 'remove' ? 'phoenixd_removed' : 'connected');
          if (current.manual_dns_names?.length) {
            result.textContent += '\n' + t('check_manual_dns') + '\n' + current.manual_dns_names.join('\n');
          }
        } catch (error) {
          try { await refresh(); } catch (_) {}
          result.textContent = error.message;
        }
        finally { buttons.forEach(button => { button.disabled = false; }); updateSelection(); }
      }
      const options = panel.querySelector('#phoenixdOptions');
      const historyOption = panel.querySelector('#deletePhoenixdHistory');
      const optionsMessage = panel.querySelector('#phoenixdOptionsMessage');
      let pendingAction;
      const updateOptionsMessage = () => {
        const key = pendingAction === 'pause' ? 'phoenixd_management_hint'
          : historyOption.checked ? 'confirm_remove_history' : 'confirm_remove';
        optionsMessage.dataset.backendText = key;
        optionsMessage.textContent = t(key);
      };
      function showOptions(action) {
        pendingAction = action;
        options.returnValue = '';
        historyOption.checked = false;
        panel.querySelector('#deletePhoenixdPublications').checked = false;
        panel.querySelector('#hidePhoenixdAliases').checked = Boolean(current.phoenixd.alias_pages_hidden);
        panel.querySelector('#hidePhoenixdAliasesOption').hidden = action !== 'pause';
        panel.querySelector('#deletePhoenixdHistoryOption').hidden = action !== 'remove';
        panel.querySelector('#deletePhoenixdPublicationsOption').hidden = action !== 'remove';
        const confirm = panel.querySelector('#confirmPhoenixdAction');
        confirm.dataset.action = action;
        confirm.dataset.backendText = action === 'pause' ? 'pause_phoenixd' : 'remove_phoenixd';
        confirm.textContent = t(confirm.dataset.backendText);
        updateOptionsMessage();
        options.showModal();
      }
      historyOption.onchange = updateOptionsMessage;
      options.addEventListener('close', () => {
        if (options.returnValue === 'confirm') void manage(pendingAction);
      });
      panel.querySelector('#pausePhoenixdBtn').onclick = () => current.phoenixd.paused ? manage('resume') : showOptions('pause');
      panel.querySelector('#removePhoenixdBtn').onclick = () => showOptions('remove');
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
          <button type="button" data-lnurl-action="auth" data-backend-text="auth"></button>
          <button type="button" class="secondary" data-lnurl-inspect data-backend-text="inspect"></button></div>
          <p role="status" aria-live="polite" id="phoenixLnurlResult" style="margin:0;overflow-wrap:anywhere"></p>
        </div>`;
      payButton.parentElement.insertAdjacentElement('afterend', tools);
      tools.querySelector('[data-lnurl-inspect]').onclick = async () => {
        const result = tools.querySelector('#phoenixLnurlResult');
        result.style.cssText = 'margin:0;overflow-wrap:anywhere';
        result.textContent = t('working');
        try {
          const info = await api('/api/lightning/lnurl-inspect', {backend_id: window.LightningBackend.id,
            lnurl: tools.querySelector('input').value.trim(), action: 'withdraw'});
          result.textContent = `${t('inspect_result')}: ${info.host} · HTTP ${info.http_status} · ${info.tag || info.content_type}` +
            (info.callback_host ? ` · Callback: ${info.callback_host}` : '') +
            (info.html ? ` · ${t('inspect_html')}` : '') +
            (info.callback_host && info.callback_host !== info.host ? ` · ${t('inspect_host')}` : '');
        } catch (error) { result.textContent = error.message; }
      };
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
        if (location.hash === '#lightningBackendPanel') {
          const scrollToBackend = () => requestAnimationFrame(() => document.getElementById('lightningBackendPanel').scrollIntoView({block: 'start'}));
          if (setup.hidden) {
            const observer = new MutationObserver(() => {
              if (!setup.hidden) { observer.disconnect(); scrollToBackend(); }
            });
            observer.observe(setup, {attributes: true, attributeFilter: ['hidden']});
          } else { scrollToBackend(); }
        }
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
