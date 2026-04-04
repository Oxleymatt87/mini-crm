/* =============================================
   Oxley Tire CRM — Main Application
   Firebase-only, mobile-first
   ============================================= */

// Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyDdxP9prJjiFFeJ1XGZewkzstgxf7Ciy4E",
  authDomain: "inventory-setup-b3f20.firebaseapp.com",
  projectId: "inventory-setup-b3f20",
  storageBucket: "inventory-setup-b3f20.firebasestorage.app",
  messagingSenderId: "162750059985",
  appId: "1:162750059985:web:bbe5328412c7ef49893cf0"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

// ─── State ───
let items = [];
let customers = [];
let movements = [];
let orders = [];
let supplierCatalog = [];
let invoices = [];

// ─── Auth ───
auth.onAuthStateChanged(user => {
  if (user) {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    loadAllData();
  } else {
    document.getElementById('login-screen').style.display = 'block';
    document.getElementById('app').style.display = 'none';
  }
});

function doLogin() {
  const email = document.getElementById('login-email').value;
  const pass = document.getElementById('login-pass').value;
  const errEl = document.getElementById('login-error');
  errEl.style.display = 'none';
  auth.signInWithEmailAndPassword(email, pass).catch(err => {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  });
}

function signOut() {
  auth.signOut();
}

// Enter key on password field
document.getElementById('login-pass').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// ─── Tabs ───
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// ─── Data Loading ───
async function loadAllData() {
  try {
    await Promise.all([
      loadItems(),
      loadMovements(),
      loadCustomers(),
      loadOrders(),
      loadSupplierCatalog(),
      loadInvoices()
    ]);
    renderDashboard();
    renderInventory();
    renderContacts();
    renderOrders();
    renderStock();
    renderRecentInvoices();
    populateLineItemSelects();
  } catch (err) {
    console.error('Load error:', err);
    toast('Failed to load data', 'error');
  }
}

async function loadItems() {
  const snap = await db.collection('items').get();
  items = snap.docs.map(d => {
    const data = d.data();
    return {
      id: d.id,
      ...data,
      cost: data.cost || data.landedCost || data.unitCost || 0,
      quantity: data.quantity || data.qty || 0,
      qb_item_id: data.qb_item_id || data.qbItemId || null,
    };
  });
}

async function loadMovements() {
  const snap = await db.collection('movements').orderBy('timestamp', 'desc').limit(50).get();
  movements = snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function loadCustomers() {
  const snap = await db.collection('customers').get();
  customers = snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function loadOrders() {
  const snap = await db.collection('orders').orderBy('created_at', 'desc').get();
  orders = snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function loadSupplierCatalog() {
  const snap = await db.collection('supplier_catalog').get();
  supplierCatalog = snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function loadInvoices() {
  const snap = await db.collection('invoices').orderBy('created_at', 'desc').limit(50).get();
  invoices = snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

// ─── Dashboard ───
function renderDashboard() {
  const totalSkus = items.length;
  const totalUnits = items.reduce((s, i) => s + (Number(i.quantity) || 0), 0);
  const totalValue = items.reduce((s, i) => s + (Number(i.quantity) || 0) * (Number(i.cost) || 0), 0);

  document.getElementById('stat-skus').textContent = totalSkus;
  document.getElementById('stat-units').textContent = totalUnits;
  document.getElementById('stat-value').textContent = '$' + totalValue.toFixed(0).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  document.getElementById('stat-customers').textContent = customers.length;

  // Low stock
  const lowStock = items.filter(i => (Number(i.quantity) || 0) <= 2).sort((a, b) => (a.quantity || 0) - (b.quantity || 0));
  const lsEl = document.getElementById('low-stock-list');
  if (lowStock.length === 0) {
    lsEl.innerHTML = '<p style="color:var(--text2);font-size:.85rem">All stock levels OK</p>';
  } else {
    lsEl.innerHTML = lowStock.map(i => `
      <div class="alert-item">
        <span>${esc(i.brand || '')} ${esc(i.size || '')} ${esc(i.model || '')}</span>
        <span class="badge badge-red">${i.quantity || 0} left</span>
      </div>
    `).join('');
  }

  // Recent activity
  const actEl = document.getElementById('activity-list');
  if (movements.length === 0) {
    actEl.innerHTML = '<p style="color:var(--text2);font-size:.85rem">No recent activity</p>';
  } else {
    actEl.innerHTML = movements.slice(0, 15).map(m => {
      const ts = m.timestamp ? formatDate(m.timestamp) : '';
      const typeLabel = m.type === 'physical_count' ? 'Count' : m.type === 'auto_receive' ? 'Auto-Receive' : (m.type || 'Move');
      return `
        <div class="activity-item">
          <span class="activity-text">
            <span class="badge ${m.type === 'auto_receive' ? 'badge-green' : 'badge-blue'}">${typeLabel}</span>
            ${esc(m.brand || '')} ${esc(m.size || '')} — qty: ${m.quantity || m.new_quantity || '?'}
          </span>
          <span class="activity-time">${ts}</span>
        </div>
      `;
    }).join('');
  }
}

// ─── Inventory ───
function renderInventory() {
  let filtered = [...items];
  const q = (document.getElementById('inv-search').value || '').toLowerCase();
  if (q) {
    filtered = filtered.filter(i =>
      (i.brand || '').toLowerCase().includes(q) ||
      (i.size || '').toLowerCase().includes(q) ||
      (i.model || '').toLowerCase().includes(q)
    );
  }

  const sort = document.getElementById('inv-sort').value;
  filtered.sort((a, b) => {
    switch (sort) {
      case 'brand': return (a.brand || '').localeCompare(b.brand || '');
      case 'qty_low': return (a.quantity || 0) - (b.quantity || 0);
      case 'qty_high': return (b.quantity || 0) - (a.quantity || 0);
      case 'cost': return (b.cost || 0) - (a.cost || 0);
      default: return (a.size || '').localeCompare(b.size || '');
    }
  });

  const tbody = document.getElementById('inv-tbody');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text2)">No items found</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(i => `
    <tr>
      <td>${esc(i.brand || '')}</td>
      <td>${esc(i.model || '')}</td>
      <td>${esc(i.size || '')}</td>
      <td><span class="badge ${(i.quantity || 0) <= 2 ? 'badge-red' : 'badge-green'}">${i.quantity || 0}</span></td>
      <td>$${(Number(i.cost) || 0).toFixed(2)}</td>
      <td>${esc(i.zone || '')}</td>
      <td>
        <button class="btn btn-sm btn-outline" onclick="openEditItem('${i.id}')">Edit</button>
      </td>
    </tr>
  `).join('');
}

document.getElementById('inv-search').addEventListener('input', renderInventory);
document.getElementById('inv-sort').addEventListener('change', renderInventory);

// ─── Edit Item ───
function openEditItem(id) {
  const modal = document.getElementById('modal-edit-item');
  if (id) {
    const item = items.find(i => i.id === id);
    if (!item) return;
    document.getElementById('edit-item-title').textContent = 'Edit Item';
    document.getElementById('edit-item-id').value = id;
    document.getElementById('edit-brand').value = item.brand || '';
    document.getElementById('edit-model').value = item.model || '';
    document.getElementById('edit-size').value = item.size || '';
    document.getElementById('edit-zone').value = item.zone || '';
    document.getElementById('edit-qty').value = item.quantity || 0;
    document.getElementById('edit-cost').value = item.cost || 0;
    document.getElementById('edit-fet').value = item.fet || 0;
  } else {
    document.getElementById('edit-item-title').textContent = 'Add Item';
    document.getElementById('edit-item-id').value = '';
    document.getElementById('edit-brand').value = '';
    document.getElementById('edit-model').value = '';
    document.getElementById('edit-size').value = '';
    document.getElementById('edit-zone').value = '';
    document.getElementById('edit-qty').value = 0;
    document.getElementById('edit-cost').value = 0;
    document.getElementById('edit-fet').value = 0;
  }
  openModal('modal-edit-item');
}

async function saveItem() {
  const id = document.getElementById('edit-item-id').value;
  const data = {
    brand: document.getElementById('edit-brand').value.trim(),
    model: document.getElementById('edit-model').value.trim(),
    size: document.getElementById('edit-size').value.trim(),
    zone: document.getElementById('edit-zone').value.trim(),
    quantity: Number(document.getElementById('edit-qty').value) || 0,
    cost: Number(document.getElementById('edit-cost').value) || 0,
    fet: Number(document.getElementById('edit-fet').value) || 0,
    updated_at: firebase.firestore.FieldValue.serverTimestamp()
  };

  try {
    if (id) {
      await db.collection('items').doc(id).update(data);
      toast('Item updated');
    } else {
      data.created_at = firebase.firestore.FieldValue.serverTimestamp();
      await db.collection('items').add(data);
      toast('Item added');
    }
    closeModal('modal-edit-item');
    await loadItems();
    renderInventory();
    renderDashboard();
    populateLineItemSelects();
  } catch (err) {
    toast('Error saving: ' + err.message, 'error');
  }
}

// ─── Contacts ───
function renderContacts() {
  const q = (document.getElementById('contact-search').value || '').toLowerCase();
  let filtered = customers;
  if (q) {
    filtered = customers.filter(c =>
      (c.display_name || '').toLowerCase().includes(q) ||
      (c.company_name || '').toLowerCase().includes(q) ||
      (c.given_name || '').toLowerCase().includes(q) ||
      (c.family_name || '').toLowerCase().includes(q)
    );
  }

  const tbody = document.getElementById('contacts-tbody');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text2)">No contacts found</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(c => `
    <tr>
      <td>${esc(c.display_name || c.given_name || '')}</td>
      <td>${esc(c.company_name || '')}</td>
      <td>${esc(c.phone || '')}</td>
      <td>${c.qbo_id ? '<span class="badge badge-blue">QBO:' + esc(c.qbo_id) + '</span>' : '--'}</td>
      <td><button class="btn btn-sm btn-outline" onclick="openPortalModal('${c.id}')">Portal Link</button></td>
    </tr>
  `).join('');
}

document.getElementById('contact-search').addEventListener('input', renderContacts);

// ─── QBO Customer Sync ───
async function syncQBOCustomers() {
  toast('Syncing customers from QBO...', 'info');
  try {
    // Read QBO tokens from Firestore
    const tokenDoc = await db.collection('config').doc('qbo_tokens').get();
    if (!tokenDoc.exists) {
      toast('QBO tokens not configured in Firestore config/qbo_tokens', 'error');
      return;
    }
    const tokens = tokenDoc.data();
    let accessToken = tokens.access_token;
    const realmId = tokens.realm_id || '9130357532009796';

    // Try fetching customers, refresh token if 401
    let resp = await fetchQBO(`/v3/company/${realmId}/query?query=${encodeURIComponent('SELECT * FROM Customer MAXRESULTS 1000')}`, accessToken);

    if (resp.status === 401) {
      // Refresh the token
      accessToken = await refreshQBOToken(tokens);
      if (!accessToken) return;
      resp = await fetchQBO(`/v3/company/${realmId}/query?query=${encodeURIComponent('SELECT * FROM Customer MAXRESULTS 1000')}`, accessToken);
    }

    if (!resp.ok) {
      toast('QBO API error: ' + resp.status, 'error');
      return;
    }

    const data = await resp.json();
    const qboCustomers = (data.QueryResponse && data.QueryResponse.Customer) || [];

    // Batch write to Firestore
    const batch = db.batch();
    for (const qc of qboCustomers) {
      const ref = db.collection('customers').doc('qbo_' + qc.Id);
      batch.set(ref, {
        qbo_id: qc.Id,
        display_name: qc.DisplayName || '',
        given_name: qc.GivenName || '',
        family_name: qc.FamilyName || '',
        company_name: qc.CompanyName || '',
        phone: (qc.PrimaryPhone && qc.PrimaryPhone.FreeFormNumber) || '',
        email: (qc.PrimaryEmailAddr && qc.PrimaryEmailAddr.Address) || '',
        balance: qc.Balance || 0,
        active: qc.Active !== false,
        synced_at: firebase.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
    await batch.commit();

    toast(`Synced ${qboCustomers.length} customers from QBO`);
    await loadCustomers();
    renderContacts();
    renderDashboard();
  } catch (err) {
    toast('Sync error: ' + err.message, 'error');
  }
}

async function fetchQBO(path, accessToken) {
  return fetch('https://quickbooks.api.intuit.com' + path, {
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Accept': 'application/json'
    }
  });
}

async function refreshQBOToken(tokens) {
  try {
    const resp = await fetch('https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + btoa(tokens.client_id + ':' + tokens.client_secret)
      },
      body: 'grant_type=refresh_token&refresh_token=' + encodeURIComponent(tokens.refresh_token)
    });

    if (!resp.ok) {
      toast('Failed to refresh QBO token', 'error');
      return null;
    }

    const data = await resp.json();
    // Update tokens in Firestore
    await db.collection('config').doc('qbo_tokens').update({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      updated_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    return data.access_token;
  } catch (err) {
    toast('Token refresh error: ' + err.message, 'error');
    return null;
  }
}

// ─── Portal Link ───
function openPortalModal(customerId) {
  const c = customers.find(x => x.id === customerId);
  if (!c) return;
  document.getElementById('portal-customer-name').value = c.display_name || c.given_name || '';
  document.getElementById('portal-customer-id').value = customerId;
  document.getElementById('portal-qbo-id').value = c.qbo_id || '';
  document.getElementById('portal-markup').value = 30;
  document.getElementById('portal-link-result').style.display = 'none';
  openModal('modal-portal');
}

async function generatePortalLink() {
  const customerId = document.getElementById('portal-customer-id').value;
  const qboId = document.getElementById('portal-qbo-id').value;
  const markup = Number(document.getElementById('portal-markup').value) || 30;
  const customerName = document.getElementById('portal-customer-name').value;

  // Generate a random token
  const token = generateToken();

  try {
    await db.collection('portal_access').doc(token).set({
      customer_id: customerId,
      qbo_id: qboId,
      customer_name: customerName,
      markup_pct: markup,
      active: true,
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    const url = 'https://inventory-setup-b3f20.web.app/portal/' + token;
    document.getElementById('portal-link-url').value = url;
    document.getElementById('portal-link-result').style.display = 'block';
    toast('Portal link generated');
  } catch (err) {
    toast('Error: ' + err.message, 'error');
  }
}

function copyPortalLink() {
  const url = document.getElementById('portal-link-url').value;
  navigator.clipboard.writeText(url).then(() => toast('Copied!')).catch(() => {
    // Fallback
    const el = document.getElementById('portal-link-url');
    el.select();
    document.execCommand('copy');
    toast('Copied!');
  });
}

function generateToken() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let t = '';
  for (let i = 0; i < 24; i++) t += chars[Math.floor(Math.random() * chars.length)];
  return t;
}

// ─── Orders ───
function renderOrders() {
  const q = (document.getElementById('order-search').value || '').toLowerCase();
  let filtered = orders;
  if (q) {
    filtered = orders.filter(o =>
      (o.order_number || '').toLowerCase().includes(q) ||
      (o.source || '').toLowerCase().includes(q) ||
      (o.customer_name || '').toLowerCase().includes(q)
    );
  }

  const tbody = document.getElementById('orders-tbody');
  const emptyEl = document.getElementById('orders-empty');

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    emptyEl.style.display = 'block';
    return;
  }
  emptyEl.style.display = 'none';

  tbody.innerHTML = filtered.map(o => {
    const date = o.created_at ? formatDate(o.created_at) : '';
    const itemCount = (o.line_items || []).length;
    const total = (o.total || 0).toFixed(2);
    const typeBadge = o.type === 'portal' ? 'badge-gold' : o.type === 'auto_receive' ? 'badge-green' : 'badge-blue';
    return `
      <tr class="order-row" onclick="toggleOrderDetail(this)">
        <td>${date}</td>
        <td>${esc(o.order_number || o.id)}</td>
        <td>${esc(o.source || o.customer_name || '')}</td>
        <td><span class="badge ${typeBadge}">${esc(o.type || 'order')}</span></td>
        <td>${itemCount}</td>
        <td>$${total}</td>
      </tr>
      <tr class="order-detail" style="display:none">
        <td colspan="6" style="padding:12px;background:var(--bg)">
          ${(o.line_items || []).map(li => `
            <div style="font-size:.85rem;padding:4px 0;border-bottom:1px solid var(--border)">
              ${esc(li.brand || '')} ${esc(li.size || '')} ${esc(li.description || '')} — Qty: ${li.quantity || 0} @ $${(li.price || 0).toFixed(2)}
            </div>
          `).join('') || '<p style="color:var(--text2)">No line items</p>'}
        </td>
      </tr>
    `;
  }).join('');
}

document.getElementById('order-search').addEventListener('input', renderOrders);

function toggleOrderDetail(row) {
  const detail = row.nextElementSibling;
  if (detail) {
    detail.style.display = detail.style.display === 'none' ? 'table-row' : 'none';
  }
}

// ─── Stock / Supplier Catalog ───
function renderStock() {
  const q = (document.getElementById('stock-search').value || '').toLowerCase().trim();
  let filtered = supplierCatalog;
  if (q) {
    filtered = supplierCatalog.filter(s =>
      (s.size || '').toLowerCase().includes(q) ||
      (s.brand || '').toLowerCase().includes(q) ||
      (s.description || '').toLowerCase().includes(q) ||
      (s.supplier || '').toLowerCase().includes(q)
    );
  }

  // Sort by cost low→high so cheapest shows first
  filtered.sort((a, b) => (Number(a.cost) || 999999) - (Number(b.cost) || 999999));

  // Find most recent timestamp
  let latest = null;
  supplierCatalog.forEach(s => {
    if (s.scraped_at) {
      const d = s.scraped_at.toDate ? s.scraped_at.toDate() : new Date(s.scraped_at);
      if (!latest || d > latest) latest = d;
    }
  });
  document.getElementById('stock-updated').textContent = latest
    ? 'Last refreshed: ' + latest.toLocaleDateString() + ' ' + latest.toLocaleTimeString()
    : 'Last refreshed: --';

  // Quick-link buttons to supplier portals (show when searching)
  const linksEl = document.getElementById('stock-quick-links');
  if (q.length >= 3) {
    const sizeQuery = document.getElementById('stock-search').value.trim();
    linksEl.innerHTML = `
      <span style="font-size:.8rem;color:var(--text2);margin-right:8px">Search manually:</span>
      <a href="https://atdonline.com/search?q=${encodeURIComponent(sizeQuery)}" target="_blank" rel="noopener" class="btn btn-sm btn-outline" style="margin-right:6px">Search ATD</a>
      <a href="https://kmtire.com" target="_blank" rel="noopener" class="btn btn-sm btn-outline" style="margin-right:6px">Search K&amp;M</a>
      <a href="https://b2b.dktire.com" target="_blank" rel="noopener" class="btn btn-sm btn-outline">Search Hesselbein</a>
    `;
    linksEl.style.display = 'flex';
  } else {
    linksEl.style.display = 'none';
  }

  const tbody = document.getElementById('stock-tbody');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text2)">No cached results. Check supplier portals above or click Refresh.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(s => {
    const supplierColors = { 'BZO': 'badge-blue', 'Hesselbein': 'badge-gold', 'ATD': 'badge-green', 'K&M': 'badge-red' };
    const badgeClass = supplierColors[s.supplier] || 'badge-blue';
    return `
    <tr>
      <td><span class="badge ${badgeClass}">${esc(s.supplier || '')}</span></td>
      <td>${esc(s.brand || '')}</td>
      <td>${esc(s.description || '')}</td>
      <td>${esc(s.size || '')}</td>
      <td>$${(Number(s.cost) || 0).toFixed(2)}</td>
      <td>$${(Number(s.fet) || 0).toFixed(2)}</td>
      <td>${esc(s.availability || '')}</td>
    </tr>
  `;
  }).join('');
}

document.getElementById('stock-search').addEventListener('input', renderStock);

async function refreshCatalog() {
  toast('Triggering scraper service...', 'info');
  try {
    // Trigger the Render scraper service
    const resp = await fetch('https://mini-crm-scraper.onrender.com/run', { method: 'POST' });
    if (resp.ok) {
      toast('Scraper triggered. Data will refresh in a few minutes.');
    } else {
      toast('Scraper returned status ' + resp.status, 'error');
    }
  } catch (err) {
    toast('Could not reach scraper: ' + err.message, 'error');
  }
}

// ─── Invoices ───
let lineCount = 1;

function populateLineItemSelects() {
  document.querySelectorAll('.line-item-select').forEach(sel => {
    const val = sel.value;
    sel.innerHTML = '<option value="">Select item...</option>' +
      items.map(i => `<option value="${i.id}" data-cost="${i.cost || 0}" data-fet="${i.fet || 0}">${esc(i.brand || '')} ${esc(i.size || '')} ${esc(i.model || '')} — $${(i.cost || 0).toFixed(2)}</option>`).join('');
    if (val) sel.value = val;
  });
}

function onLineItemSelect(sel) {
  const idx = sel.dataset.idx;
  const opt = sel.options[sel.selectedIndex];
  if (opt && opt.value) {
    const cost = Number(opt.dataset.cost) || 0;
    const fet = Number(opt.dataset.fet) || 0;
    document.querySelector(`.line-price[data-idx="${idx}"]`).value = cost.toFixed(2);
    document.querySelector(`.line-fet[data-idx="${idx}"]`).value = fet.toFixed(2);
  }
  calcLineTotal();
}

function addInvoiceLine() {
  const idx = lineCount++;
  const div = document.createElement('div');
  div.className = 'invoice-line';
  div.dataset.idx = idx;
  div.innerHTML = `
    <div class="form-row" style="grid-template-columns: 2fr 1fr 1fr 1fr auto; gap:8px; margin-bottom:8px; align-items:end;">
      <div class="form-group" style="margin-bottom:0">
        <label>Item</label>
        <select class="search-input line-item-select" data-idx="${idx}" onchange="onLineItemSelect(this)">
          <option value="">Select item...</option>
        </select>
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label>Qty</label>
        <input type="number" class="search-input line-qty" data-idx="${idx}" value="1" min="1" onchange="calcLineTotal()">
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label>Price</label>
        <input type="number" class="search-input line-price" data-idx="${idx}" step="0.01" onchange="calcLineTotal()">
      </div>
      <div class="form-group" style="margin-bottom:0">
        <label>FET</label>
        <input type="number" class="search-input line-fet" data-idx="${idx}" step="0.01" value="0" readonly>
      </div>
      <button class="btn btn-sm btn-danger" onclick="removeLine(this)" style="margin-bottom:0;height:36px">X</button>
    </div>
  `;
  document.getElementById('invoice-lines').appendChild(div);
  populateLineItemSelects();
}

function removeLine(btn) {
  const line = btn.closest('.invoice-line');
  if (document.querySelectorAll('.invoice-line').length > 1) {
    line.remove();
    calcLineTotal();
  }
}

function calcLineTotal() {
  let total = 0;
  document.querySelectorAll('.invoice-line').forEach(line => {
    const qty = Number(line.querySelector('.line-qty').value) || 0;
    const price = Number(line.querySelector('.line-price').value) || 0;
    const fet = Number(line.querySelector('.line-fet').value) || 0;
    total += qty * (price + fet);
  });
  document.getElementById('invoice-total').textContent = total.toFixed(2);
}

// Customer typeahead for invoice
const invCustSearch = document.getElementById('inv-customer-search');
const invCustList = document.getElementById('inv-customer-list');

invCustSearch.addEventListener('input', () => {
  const q = invCustSearch.value.toLowerCase();
  if (q.length < 2) { invCustList.classList.remove('open'); return; }
  const matches = customers.filter(c =>
    (c.display_name || '').toLowerCase().includes(q) ||
    (c.company_name || '').toLowerCase().includes(q)
  ).slice(0, 10);

  if (matches.length === 0) { invCustList.classList.remove('open'); return; }

  invCustList.innerHTML = matches.map(c => `
    <div class="typeahead-item" data-id="${c.qbo_id || ''}" data-fid="${c.id}" data-name="${esc(c.display_name || '')}">
      ${esc(c.display_name || '')} ${c.company_name ? '(' + esc(c.company_name) + ')' : ''}
    </div>
  `).join('');
  invCustList.classList.add('open');

  invCustList.querySelectorAll('.typeahead-item').forEach(item => {
    item.addEventListener('click', () => {
      invCustSearch.value = item.dataset.name;
      document.getElementById('inv-customer-id').value = item.dataset.id;
      document.getElementById('inv-customer-name').value = item.dataset.name;
      invCustList.classList.remove('open');
    });
  });
});

document.addEventListener('click', e => {
  if (!e.target.closest('.typeahead-wrap')) {
    document.querySelectorAll('.typeahead-list').forEach(l => l.classList.remove('open'));
  }
});

async function createInvoice() {
  const qboId = document.getElementById('inv-customer-id').value;
  const customerName = document.getElementById('inv-customer-name').value;

  if (!qboId) {
    toast('Select a customer first', 'error');
    return;
  }

  // Gather line items
  const lineItems = [];
  let valid = true;
  document.querySelectorAll('.invoice-line').forEach(line => {
    const sel = line.querySelector('.line-item-select');
    const itemId = sel.value;
    const qty = Number(line.querySelector('.line-qty').value) || 0;
    const price = Number(line.querySelector('.line-price').value) || 0;
    const fet = Number(line.querySelector('.line-fet').value) || 0;

    if (!itemId || qty <= 0) { valid = false; return; }
    const item = items.find(i => i.id === itemId);
    lineItems.push({
      item_id: itemId,
      brand: item ? item.brand : '',
      size: item ? item.size : '',
      model: item ? item.model : '',
      description: `${item ? item.brand : ''} ${item ? item.size : ''} ${item ? item.model : ''}`.trim(),
      quantity: qty,
      price: price,
      fet: fet,
      amount: qty * (price + fet)
    });
  });

  if (!valid || lineItems.length === 0) {
    toast('Add at least one valid line item', 'error');
    return;
  }

  const total = lineItems.reduce((s, li) => s + li.amount, 0);

  try {
    // 1. Create QBO Invoice
    const tokenDoc = await db.collection('config').doc('qbo_tokens').get();
    if (!tokenDoc.exists) {
      toast('QBO tokens not configured', 'error');
      return;
    }
    const tokens = tokenDoc.data();
    let accessToken = tokens.access_token;
    const realmId = tokens.realm_id || '9130357532009796';

    const qboInvoice = {
      CustomerRef: { value: qboId },
      Line: lineItems.map(li => ({
        Amount: li.amount,
        DetailType: 'SalesItemLineDetail',
        Description: li.description + (li.fet > 0 ? ` (FET: $${li.fet.toFixed(2)})` : ''),
        SalesItemLineDetail: {
          ItemRef: { value: '1' },
          Qty: li.quantity,
          UnitPrice: li.price + li.fet,
          IncomeAccountRef: { value: '7', name: 'Sales' }
        }
      }))
    };

    let resp = await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/invoice`, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(qboInvoice)
    });

    if (resp.status === 401) {
      accessToken = await refreshQBOToken(tokens);
      if (!accessToken) return;
      resp = await fetch(`https://quickbooks.api.intuit.com/v3/company/${realmId}/invoice`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + accessToken,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(qboInvoice)
      });
    }

    if (!resp.ok) {
      const errData = await resp.text();
      toast('QBO invoice error: ' + errData.slice(0, 120), 'error');
      return;
    }

    const invoiceData = await resp.json();
    const qboInvoiceId = invoiceData.Invoice ? invoiceData.Invoice.Id : null;

    // 2. Save invoice to Firestore
    await db.collection('invoices').add({
      qbo_invoice_id: qboInvoiceId,
      customer_qbo_id: qboId,
      customer_name: customerName,
      line_items: lineItems,
      total: total,
      status: 'created',
      created_at: firebase.firestore.FieldValue.serverTimestamp()
    });

    // 3. Deduct inventory and create movements
    const batch = db.batch();
    for (const li of lineItems) {
      const itemRef = db.collection('items').doc(li.item_id);
      const item = items.find(i => i.id === li.item_id);
      const newQty = Math.max(0, (item ? item.quantity : 0) - li.quantity);
      batch.update(itemRef, { quantity: newQty, updated_at: firebase.firestore.FieldValue.serverTimestamp() });

      const movRef = db.collection('movements').doc();
      batch.set(movRef, {
        item_id: li.item_id,
        brand: li.brand,
        size: li.size,
        type: 'invoice_sale',
        quantity: -li.quantity,
        new_quantity: newQty,
        customer: customerName,
        invoice_id: qboInvoiceId,
        timestamp: firebase.firestore.FieldValue.serverTimestamp()
      });
    }
    await batch.commit();

    toast('Invoice created! QBO #' + (qboInvoiceId || 'pending'));

    // Reset form
    document.getElementById('inv-customer-search').value = '';
    document.getElementById('inv-customer-id').value = '';
    document.getElementById('inv-customer-name').value = '';
    document.getElementById('invoice-lines').innerHTML = '';
    lineCount = 0;
    addInvoiceLine();

    // Reload
    await Promise.all([loadItems(), loadMovements(), loadInvoices()]);
    renderInventory();
    renderDashboard();
    renderRecentInvoices();

  } catch (err) {
    toast('Invoice error: ' + err.message, 'error');
  }
}

function renderRecentInvoices() {
  const el = document.getElementById('recent-invoices');
  if (invoices.length === 0) {
    el.innerHTML = '<p style="color:var(--text2);font-size:.85rem">No invoices yet</p>';
    return;
  }

  el.innerHTML = invoices.slice(0, 20).map(inv => {
    const date = inv.created_at ? formatDate(inv.created_at) : '';
    return `
      <div class="activity-item">
        <span class="activity-text">
          <strong>${esc(inv.customer_name || '')}</strong> — $${(inv.total || 0).toFixed(2)}
          ${inv.qbo_invoice_id ? '<span class="badge badge-green">QBO #' + esc(inv.qbo_invoice_id) + '</span>' : ''}
        </span>
        <span class="activity-time">${date}</span>
      </div>
    `;
  }).join('');
}

// ─── Utilities ───
function openModal(id) {
  document.getElementById(id).classList.add('open');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('open');
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.classList.remove('open');
  });
});

function toast(msg, type = 'success') {
  const container = document.getElementById('toast-container');
  const div = document.createElement('div');
  div.className = 'toast toast-' + type;
  div.textContent = msg;
  container.appendChild(div);
  setTimeout(() => div.remove(), 4000);
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function formatDate(ts) {
  let d;
  if (ts && ts.toDate) d = ts.toDate();
  else if (ts && ts.seconds) d = new Date(ts.seconds * 1000);
  else d = new Date(ts);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Territory tab
let territoryData = [], terrSortCol = 'Trucks', terrSortAsc = false;
fetch('/territory-data.json').then(r=>r.json()).then(d=>{territoryData=d;renderTerritory()});

function renderTerritory() {
  let data = [...territoryData];
  const q = (document.getElementById('territory-search')?.value || '').toLowerCase();
  if (q) data = data.filter(r =>
    (r['Company Name']||'').toLowerCase().includes(q) ||
    (r.City||'').toLowerCase().includes(q) ||
    (r.Notes||'').toLowerCase().includes(q) ||
    (r.Address||'').toLowerCase().includes(q)
  );
  data.sort((a,b) => {
    let va = a[terrSortCol] ?? '', vb = b[terrSortCol] ?? '';
    if (typeof va === 'number' || typeof vb === 'number') { va = va || 0; vb = vb || 0; }
    if (va < vb) return terrSortAsc ? -1 : 1;
    if (va > vb) return terrSortAsc ? 1 : -1;
    return 0;
  });
  const tbody = document.getElementById('territory-tbody');
  if (!tbody) return;
  tbody.innerHTML = data.map(r => `<tr>
    <td>${r['Company Name']||''}</td>
    <td>${r.Status||''}</td>
    <td>${r.City||''}</td>
    <td>${r.Trucks||''}</td>
    <td>${r.Phone ? '<a href="tel:'+r.Phone+'">'+r.Phone+'</a>' : ''}</td>
    <td>${r['Est. Spend']||''}</td>
    <td>${r.Notes||''}</td>
  </tr>`).join('');
}

document.addEventListener('click', e => {
  if (e.target.classList.contains('sort-th')) {
    const col = e.target.dataset.col;
    if (terrSortCol === col) terrSortAsc = !terrSortAsc;
    else { terrSortCol = col; terrSortAsc = true; }
    renderTerritory();
  }
});

document.addEventListener('input', e => {
  if (e.target.id === 'territory-search') renderTerritory();
});
