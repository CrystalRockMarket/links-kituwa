/* Kituwa Network bar — drop-in custom element.
 *
 * Normal visitors get the 40px network strip and the directory panel. An
 * authenticated operator also gets an "Admin" tab inside the panel with their
 * saved operator apps. There is no page-level admin strip. The admin session
 * is read server-side when the panel opens; no token ever enters this DOM. */
const CSS_URL = new URL('./network.css', import.meta.url);
const ADMIN_SESSION = 'https://admin.kituwa.com/network/session';
const HUB_SESSION = 'https://hub.kituwa.com/network/session';
const ADMIN_PINS = 'https://admin.kituwa.com/admin/network/pins';
const CATEGORIES = ['All', 'Create', 'Play', 'Discover', 'Shop', 'Tools', 'Services'];
const USAGE_KEY = 'kituwa-network:usage:v1';
const USAGE_WINDOW = 30 * 24 * 60 * 60 * 1000;

if (!customElements.get('kituwa-network')) customElements.define('kituwa-network', class extends HTMLElement {
  connectedCallback() {
    if (this.shadowRoot) return;
    const fallback = this.querySelector('a[href]');
    if (!fallback || !window.HTMLDialogElement || !this.attachShadow) return;

    let directory;
    try {
      directory = new URL(fallback.href);
    } catch {
      return;
    }
    const root = this.attachShadow({mode: 'open'});
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = CSS_URL.href;
    root.append(link);
    const template = document.createElement('template');
    template.innerHTML = `
      <nav aria-label="Kituwa Network">
        <strong><span class="mark" aria-hidden="true">\u2756</span>Kituwa Network</strong>
        <button class="open" type="button" aria-haspopup="dialog" aria-expanded="false">Our other sites <span aria-hidden="true">\u2304</span></button>
      </nav>
      <dialog aria-labelledby="kn-heading">
        <header class="head">
          <div class="top"><b>Kituwa Network</b></div>
          <button class="close" type="button" aria-label="Close directory">\u00d7</button>
          <div class="tabs" role="tablist" aria-label="Sections">
            <button class="tab is-active" type="button" role="tab" aria-selected="true" data-tab="network">Network</button>
            <button class="tab" type="button" role="tab" aria-selected="false" data-tab="admin" hidden>Admin</button>
          </div>
          <div class="account">
            <span class="who">Kituwa account</span>
            <a class="signin" href="https://auth.kituwa.com/login" target="_blank" rel="noopener" data-auth="signin">Sign in</a>
            <a href="https://auth.kituwa.com/welcome" target="_blank" rel="noopener" data-auth="signup">Create account</a>
            <a class="op" href="https://admin.kituwa.com/admin/login" target="_blank" rel="noopener">Operator</a>
          </div>
          <div class="alerts">
            <a class="alert alert-rec" href="https://bitwarden.com/" target="_blank" rel="noopener">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M12 2l8 3v6c0 5-3.4 9.2-8 11-4.6-1.8-8-6-8-11V5l8-3z" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M12 7v7m-2.5-3.5H14" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
              <span><strong>Recommended · use a password manager</strong><small>Bitwarden or another open-source manager. One master password, unique logins everywhere.</small></span>
            </a>
            <a class="alert alert-premium" href="https://finance.kituwa.com/premium" target="_blank" rel="noopener">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M4 10h16v10H4zM3 7h18v3H3zM12 7v13M12 7c-3 0-5-1.2-5-3s2-2 3.2-.7C11.2 4.4 12 7 12 7zm0 0c3 0 5-1.2 5-3s-2-2-3.2-.7C12.8 4.4 12 7 12 7z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
              <span><strong>Apply for free premium</strong><small>Can't afford premium? Apply for a $50 credit across the Kituwa network sites.</small></span>
            </a>
          </div>
          <h2 id="kn-heading">Explore our sites</h2>
          <div class="field">
            <input type="search" aria-label="Search sites" placeholder="Search sites or interests" autocomplete="off" spellcheck="false">
          </div>
          <div class="filters" role="group" aria-label="Filter by category"></div>
        </header>
        <div class="results" aria-live="polite"></div>
        <footer><a>Open the full directory</a></footer>
      </dialog>`;
    root.append(template.content);

    const find = (selector) => root.querySelector(selector);
    const dialog = find('dialog');
    const results = find('.results');
    const search = find('input');
    const openButton = find('.open');
    const filters = find('.filters');
    const account = find('.account');
    const tabs = find('.tabs');
    const tabNetwork = find('.tab[data-tab="network"]');
    const tabAdmin = find('.tab[data-tab="admin"]');
    const title = find('h2');
    const field = find('.field');
    let activeTab = 'network';
    find('footer a').href = directory.href;

    function applyAccent(color) {
      if (!color || !/^[#a-zA-Z0-9(),.%\s-]+$/.test(color) || !CSS.supports('color', color)) return;
      try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(`:host{--kn-color:${color}}`);
        root.adoptedStyleSheets = [...root.adoptedStyleSheets, sheet];
      } catch {}
    }
    if (!getComputedStyle(this).getPropertyValue('--kn-color').trim()) {
      const theme = document.querySelector('meta[name="theme-color"]')?.content?.trim();
      applyAccent(this.dataset.accent?.trim() || theme || '');
    }

    let fitSheet = null;
    function fitDialog() {
      try {
        if (!fitSheet) {
          fitSheet = new CSSStyleSheet();
          root.adoptedStyleSheets = [...root.adoptedStyleSheets, fitSheet];
        }
        const vv = window.visualViewport;
        const width = Math.round(Math.min(vv ? vv.width : window.innerWidth, 620));
        const height = Math.round((vv ? vv.height : window.innerHeight) * 0.88);
        fitSheet.replaceSync(
          `@media (max-width: 620px) { dialog { width: ${width}px !important; max-width: ${width}px !important; height: ${height}px !important; max-height: ${height}px !important; } }`
        );
      } catch {}
    }

    let sessionChecked = false;
    let sessionData = null;

    // Sign in and sign up open a focused Kituwa ID window. The page underneath
    // never reloads; the popup carries the passkey ceremony and the account
    // form. If a browser blocks the popup, a new tab is used instead.
    function openAuthWindow(kind) {
      const url = kind === 'signup'
        ? 'https://auth.kituwa.com/welcome'
        : 'https://auth.kituwa.com/login';
      const width = 480;
      const height = 780;
      let left = 0;
      let top = 0;
      try {
        left = Math.max(0, Math.round((window.screenX || 0) + ((window.outerWidth || width) - width) / 2));
        top = Math.max(0, Math.round((window.screenY || 0) + ((window.outerHeight || height) - height) / 2));
      } catch {}
      const features = `popup=yes,width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=yes`;
      let popup = null;
      try {
        popup = window.open(url, 'kituwa-auth', features);
      } catch {}
      if (!popup) {
        try { window.open(url, '_blank', 'noopener'); } catch {}
        return;
      }
      try { popup.focus(); } catch {}
    }

    function signedOutAccount() {
      const who = document.createElement('span');
      who.className = 'who';
      who.textContent = 'Kituwa account';
      const signin = document.createElement('a');
      signin.className = 'signin';
      signin.href = 'https://auth.kituwa.com/login';
      signin.target = '_blank';
      signin.rel = 'noopener';
      signin.dataset.auth = 'signin';
      signin.textContent = 'Sign in';
      const signup = document.createElement('a');
      signup.href = 'https://auth.kituwa.com/welcome';
      signup.target = '_blank';
      signup.rel = 'noopener';
      signup.dataset.auth = 'signup';
      signup.textContent = 'Create account';
      const op = document.createElement('a');
      op.className = 'op';
      op.href = 'https://admin.kituwa.com/admin/login';
      op.target = '_blank';
      op.rel = 'noopener';
      op.textContent = 'Operator';
      account.append(who, signin, signup, op);
    }

    function renderSession() {
      const admin = Boolean(sessionData && sessionData.admin);
      tabAdmin.hidden = !admin;
      account.replaceChildren();
      if (admin) {
        const who = document.createElement('span');
        who.className = 'who';
        who.textContent = 'Operator';
        const link = document.createElement('a');
        link.href = sessionData.admin_url;
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = 'Admin';
        account.append(who, link);
        return;
      }
      if (sessionData && sessionData.authenticated) {
        const who = document.createElement('span');
        who.className = 'who';
        who.textContent = 'Signed in as ' + (sessionData.name || 'Kituwa account');
        const link = document.createElement('a');
        link.href = sessionData.account_url;
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = 'Account';
        account.append(who, link);
        return;
      }
      signedOutAccount();
    }

    function renderAdminApps() {
      results.replaceChildren();
      const links = (sessionData && Array.isArray(sessionData.hotlinks)) ? sessionData.hotlinks : [];
      const note = document.createElement('p');
      note.className = 'admin-note';
      note.textContent = 'Only visible to you. These are the operator apps saved in the admin console.';
      const grid = document.createElement('div');
      grid.className = 'admin-apps';
      for (const item of links) {
        if (!item || typeof item.label !== 'string' || typeof item.url !== 'string') continue;
        const a = document.createElement('a');
        a.className = 'admin-app';
        a.href = item.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        const strong = document.createElement('strong');
        strong.textContent = item.label;
        const small = document.createElement('small');
        try { small.textContent = new URL(item.url).hostname; } catch { small.textContent = item.url; }
        a.append(strong, small);
        grid.append(a);
      }
      results.append(note);
      if (links.length) results.append(grid);
      else {
        const empty = document.createElement('p');
        empty.className = 'empty';
        empty.textContent = 'No admin apps saved yet. Add them in the admin console.';
        results.append(empty);
      }
      if (sessionData && sessionData.admin_url) {
        const manage = document.createElement('a');
        manage.className = 'admin-manage';
        manage.href = sessionData.admin_url;
        manage.target = '_blank';
        manage.rel = 'noopener';
        manage.textContent = 'Manage this list in the admin console \u2192';
        results.append(manage);
      }
      results.scrollTop = 0;
    }

    function selectTab(name) {
      if (name === 'admin' && (!sessionData || !sessionData.admin)) name = 'network';
      activeTab = name;
      for (const tab of [tabNetwork, tabAdmin]) {
        const active = tab.dataset.tab === name;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', String(active));
      }
      const onAdmin = name === 'admin';
      title.textContent = onAdmin ? 'Admin apps' : 'Explore our sites';
      field.hidden = onAdmin;
      filters.hidden = onAdmin;
      if (onAdmin) { renderAdminApps(); return; }
      if (rows) render(); else loadCatalog();
    }

    tabNetwork.onclick = () => selectTab('network');
    tabAdmin.onclick = () => selectTab('admin');

    account.addEventListener('click', (event) => {
      const link = event.target.closest('a[data-auth]');
      if (!link) return;
      event.preventDefault();
      openAuthWindow(link.dataset.auth);
    });

    async function loadSession() {
      if (sessionChecked) return;
      sessionChecked = true;
      try {
        const read = async (url) => {
          try {
            const response = await fetch(url, {
              credentials: 'include',
              mode: 'cors',
              cache: 'no-store',
              signal: readTimeout(),
            });
            return response.ok ? await response.json() : null;
          } catch {
            return null;
          }
        };
        let data = await read(ADMIN_SESSION);
        if (!data || !data.admin) {
          const user = await read(HUB_SESSION);
          if (user && user.authenticated) data = user;
        }
        if (data && data.authenticated) sessionData = data;
        renderSession();
        if (activeTab === 'admin' && sessionData && sessionData.admin) renderAdminApps();
      } catch {
        renderSession();
      }
    }

    // A host page can be wider than the phone's visual viewport; fitDialog
    // keeps the panel inside the visible screen.
    const current = (this.dataset.site || '').trim();
    let rows = null;
    let featured = [];
    let sponsored = [];
    let isAdmin = false;
    let loading = null;
    let adminChecked = false;
    let category = 'All';

    for (const name of CATEGORIES) {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = name;
      button.setAttribute('aria-pressed', String(name === 'All'));
      button.onclick = () => {
        category = name;
        paintFilters();
        if (rows) render();
      };
      filters.append(button);
    }

    function paintFilters() {
      for (const button of filters.children) {
        button.setAttribute('aria-pressed', String(button.textContent === category));
      }
    }

    function recordUse(id) {
      try {
        const raw = JSON.parse(localStorage.getItem(USAGE_KEY) || '[]');
        const list = Array.isArray(raw) ? raw : [];
        list.push({id, t: Date.now()});
        localStorage.setItem(USAGE_KEY, JSON.stringify(list.slice(-2000)));
      } catch {}
    }

    function usageCounts() {
      const counts = {};
      const cutoff = Date.now() - USAGE_WINDOW;
      for (const key of [USAGE_KEY, 'kituwa-start:usage:v1']) {
        try {
          const raw = JSON.parse(localStorage.getItem(key) || '[]');
          if (!Array.isArray(raw)) continue;
          for (const event of raw) {
            if (!event || typeof event.id !== 'string' || typeof event.t !== 'number') continue;
            if (event.t < cutoff) continue;
            counts[event.id] = (counts[event.id] || 0) + 1;
          }
        } catch {}
      }
      return counts;
    }

    function heatCloud(entries) {
      const counts = usageCounts();
      const used = entries.filter((row) => (counts[row.id] || 0) > 0);
      if (!used.length) return;
      const max = Math.max(...used.map((row) => counts[row.id]));
      used.sort((left, right) =>
        counts[right.id] - counts[left.id] || left.name.localeCompare(right.name)
      );
      const wrap = document.createElement('div');
      wrap.className = 'heat';
      for (const row of used) {
        const link = document.createElement('a');
        link.className = 'heat-word';
        link.href = row.url;
        link.textContent = row.name;
        const ratio = counts[row.id] / max;
        link.style.fontSize = (9 + Math.pow(ratio, 1.1) * 11).toFixed(1) + 'px';
        link.style.fontWeight = String(600 + Math.round(Math.pow(ratio, 0.8) * 200));
        link.title = `${row.name} \u2014 ${counts[row.id]} ${counts[row.id] === 1 ? 'open' : 'opens'} in 30 days`;
        link.addEventListener('click', () => recordUse(row.id));
        wrap.append(link);
      }
      results.append(heading('Heat \u00b7 your most used'), wrap);
    }

    function heading(text) {
      const h = document.createElement('h3');
      h.textContent = text;
      return h;
    }

    function card(row) {
      const wrap = document.createElement('div');
      wrap.className = 'card';
      const a = document.createElement('a');
      a.className = 'card-link';
      a.href = row.url;
      a.addEventListener('click', () => recordUse(row.id));
      const tile = document.createElement('span');
      tile.className = 'tile';
      tile.setAttribute('aria-hidden', 'true');
      if (row.icon) {
        const image = document.createElement('img');
        image.src = row.icon;
        image.alt = '';
        image.width = 28;
        image.height = 28;
        image.loading = 'lazy';
        image.onerror = () => { image.remove(); tile.textContent = row.name.slice(0, 1); };
        tile.append(image);
      } else {
        tile.textContent = row.name.slice(0, 1);
      }
      const label = document.createElement('span');
      const name = document.createElement('strong');
      name.textContent = row.name;
      if (row.badge) {
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = row.badge;
        name.append(' ', badge);
      }
      const description = document.createElement('small');
      description.textContent = row.description;
      label.append(name, description);
      a.append(tile, label);
      const slot = document.createElement('span');
      slot.className = 'pin-slot';
      if (isAdmin) {
        const pinned = featured.includes(row.id);
        const pin = document.createElement('button');
        pin.type = 'button';
        pin.className = 'pin';
        pin.dataset.pin = row.id;
        pin.setAttribute('aria-pressed', String(pinned));
        pin.setAttribute('aria-label', `${pinned ? 'Unpin' : 'Pin'} ${row.name} ${pinned ? 'from' : 'to'} Featured`);
        pin.title = pinned ? 'Unpin from Featured' : 'Pin to Featured';
        pin.textContent = '\u{1F4CC}';
        pin.onclick = (event) => { event.preventDefault(); togglePin(row, pin); };
        slot.append(pin);
      }
      wrap.append(a, slot);
      return wrap;
    }

    function group(title, entries) {
      if (!entries.length) return;
      const grid = document.createElement('div');
      grid.className = 'grid';
      for (const row of entries) grid.append(card(row));
      results.append(heading(title), grid);
    }

    function sponsoredGroup(entries) {
      const visible = entries.filter((row) => {
        try { return new URL(row.url).hostname !== location.hostname; } catch { return false; }
      });
      if (!visible.length) return;
      const grid = document.createElement('div');
      grid.className = 'grid';
      for (const row of visible) {
        const wrap = document.createElement('div');
        wrap.className = 'card sponsored-card';
        const a = document.createElement('a');
        a.className = 'card-link';
        a.href = row.url;
        a.rel = 'sponsored noopener';
        const tile = document.createElement('span');
        tile.className = 'tile';
        tile.setAttribute('aria-hidden', 'true');
        tile.textContent = row.name.slice(0, 1);
        const label = document.createElement('span');
        const name = document.createElement('strong');
        name.textContent = row.name;
        const badge = document.createElement('span');
        badge.className = 'sponsor-label';
        badge.textContent = row.status === 'paid'
          ? (row.days_left != null ? `Sponsored \u00b7 ${row.days_left}d` : 'Sponsored')
          : 'Requires approval';
        name.append(' ', badge);
        const description = document.createElement('small');
        description.textContent = row.description;
        label.append(name, description);
        a.append(tile, label);
        wrap.append(a);
        if (row.status !== 'paid' && row.cashapp_url) {
          const pay = document.createElement('a');
          pay.className = 'sponsor-pay';
          pay.href = row.cashapp_url;
          pay.rel = 'noopener';
          pay.textContent = `Pay $${row.price_usd ?? '0'} via Cash App`;
          wrap.append(pay);
        }
        grid.append(wrap);
      }
      const cta = document.createElement('a');
      cta.className = 'sponsor-cta';
      cta.href = 'https://sponsor.kituwa.com/?utm_source=network&utm_medium=bar';
      cta.textContent = 'Want to see your page here? \u2192';
      results.append(heading('Sponsored'), grid, cta);
    }

    function matches() {
      const query = search.value.trim().toLowerCase();
      return (rows || []).filter((row) =>
        row.id !== current
        && (category === 'All' || row.category === category)
        && `${row.name} ${row.category} ${row.description} ${row.url}`.toLowerCase().includes(query)
      );
    }

    function render() {
      if (!rows) return;
      const found = matches();
      const related = (rows.find((row) => row.id === current)?.related) || [];
      const defaultView = !search.value.trim() && category === 'All';
      const featuredRows = defaultView ? featured.map((id) => found.find((row) => row.id === id)).filter(Boolean) : [];
      const picks = defaultView ? related.map((id) => found.find((row) => row.id === id)).filter((row) => row && !featuredRows.includes(row)) : [];
      const shown = new Set([...featuredRows, ...picks]);
      results.replaceChildren();
      sponsoredGroup(sponsored);
      group('Featured', featuredRows);
      if (defaultView) heatCloud(found);
      group('Suggested for you', picks);
      group(defaultView ? 'Browse sites' : `Results \u00b7 ${found.length}`, found.filter((row) => !shown.has(row)));
      if (!found.length) {
        const empty = document.createElement('p');
        empty.className = 'empty';
        empty.textContent = 'No matching sites. Try another search or category.';
        results.append(empty);
      }
      results.scrollTop = 0;
      paintFilters();
    }

    function showError() {
      results.replaceChildren();
      const message = document.createElement('p');
      message.className = 'empty';
      message.textContent = 'The site menu could not load. Check your connection and try again.';
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'retry';
      retry.textContent = 'Try again';
      retry.onclick = () => loadCatalog();
      const fallbackLink = document.createElement('a');
      fallbackLink.className = 'fallback';
      fallbackLink.href = directory.href;
      fallbackLink.textContent = 'Open the full directory';
      results.append(message, retry, fallbackLink);
    }

    function readTimeout() {
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) return AbortSignal.timeout(8000);
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 8000);
      return controller.signal;
    }

    async function fetchCatalog() {
      const response = await fetch(new URL('catalog.json', directory), {
        credentials: 'omit', mode: 'cors', cache: 'no-cache', signal: readTimeout(),
      });
      if (!response.ok) throw new Error(`catalog ${response.status}`);
      const data = await response.json();
      if (!Array.isArray(data)) throw new Error('catalog is not a list');
      rows = data.filter((row) =>
        row && typeof row.id === 'string' && typeof row.name === 'string'
        && typeof row.category === 'string' && typeof row.description === 'string'
        && typeof row.url === 'string' && /^https:\/\//i.test(row.url)
      );
    }

    async function fetchSponsored() {
      try {
        const response = await fetch(new URL('sponsored.json', directory), {
          credentials: 'omit', mode: 'cors', cache: 'no-cache', signal: readTimeout(),
        });
        if (!response.ok) return;
        const data = await response.json();
        if (Array.isArray(data?.items)) {
          sponsored = data.items.filter((row) => row && typeof row.name === 'string' && typeof row.url === 'string');
        }
      } catch {}
    }

    async function fetchFeatured() {
      try {
        const response = await fetch(new URL('featured.json', directory), {
          credentials: 'omit', mode: 'cors', cache: 'no-cache', signal: readTimeout(),
        });
        if (!response.ok) return;
        const data = await response.json();
        if (Array.isArray(data?.ids)) featured = data.ids.filter((id) => typeof id === 'string');
      } catch {}
    }

    async function checkAdmin() {
      if (adminChecked) return;
      adminChecked = true;
      const host = location.hostname.toLowerCase();
      if (host !== 'kituwa.com' && !host.endsWith('.kituwa.com')) return;
      try {
        const response = await fetch(ADMIN_PINS, {
          credentials: 'include', mode: 'cors', cache: 'no-store', signal: readTimeout(),
        });
        if (!response.ok) return;
        const data = await response.json();
        if (data?.authenticated) {
          isAdmin = true;
          if (Array.isArray(data.ids)) featured = data.ids;
        }
      } catch {}
    }

    async function togglePin(row, button) {
      const pinned = !featured.includes(row.id);
      button.disabled = true;
      try {
        const response = await fetch(ADMIN_PINS, {
          method: 'POST', credentials: 'include', mode: 'cors',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: row.id, pinned}), signal: readTimeout(),
        });
        if (!response.ok) throw new Error(`pin ${response.status}`);
        const data = await response.json();
        if (Array.isArray(data.ids)) featured = data.ids;
        render();
        const next = results.querySelector(`button.pin[data-pin="${CSS.escape(row.id)}"]`);
        if (next) next.focus();
      } catch {
        button.disabled = false;
        const note = document.createElement('p');
        note.className = 'empty';
        note.textContent = 'The pin could not be saved. Sign in again and retry.';
        results.prepend(note);
      }
    }

    async function loadCatalog() {
      if (loading) return loading;
      results.setAttribute('aria-busy', 'true');
      results.replaceChildren();
      const note = document.createElement('p');
      note.className = 'empty';
      note.textContent = 'Loading sites\u2026';
      results.append(note);
      loading = Promise.allSettled([fetchCatalog(), fetchFeatured(), fetchSponsored(), checkAdmin()]);
      await loading;
      loading = null;
      results.removeAttribute('aria-busy');
      if (!rows) { showError(); return; }
      render();
    }

    function openPanel() {
      category = 'All';
      search.value = '';
      paintFilters();
      selectTab('network');
      dialog.showModal();
      fitDialog();
      if (!sessionChecked) loadSession();
      openButton.setAttribute('aria-expanded', 'true');
      search.focus();
      if (!rows) loadCatalog();
      else {
        render();
        checkAdmin().then(() => { if (isAdmin) render(); });
      }
    }

    openButton.onclick = openPanel;
    find('.close').onclick = () => dialog.close();
    dialog.addEventListener('close', () => {
      openButton.setAttribute('aria-expanded', 'false');
      openButton.focus();
    });
    dialog.addEventListener('click', (event) => {
      const rect = dialog.getBoundingClientRect();
      if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right
          || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close();
    });
    search.addEventListener('input', render);
    window.addEventListener('resize', () => { if (dialog.open) fitDialog(); });
    window.visualViewport?.addEventListener('resize', () => { if (dialog.open) fitDialog(); });

    // The operator session is checked only when the panel opens.
  }
});
