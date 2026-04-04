function parseVoiceTranscript(text) {
  var t=text.toLowerCase().trim();
  t=t.replace(/\bor\b/gi,'r').replace(/\bare\b/gi,'r').replace(/\bour\b/gi,'r').replace(/\bby\b/gi,'/').replace(/\bpoint\b/gi,'.');
  t=t.replace(/(\d)\s+r\s*(\d)/gi,'$1r$2').replace(/(\d)\s+\/\s*(\d)/g,'$1/$2').replace(/(\d)\s+\.\s*(\d)/g,'$1.$2');
  var sizes=["11R22.5","11R24.5","12R22.5","215/75R17.5","225/70R19.5","235/75R17.5","245/70R19.5","255/70R22.5","265/70R19.5","275/70R22.5","275/80R22.5","285/75R24.5","295/60R22.5","295/75R22.5","295/80R22.5","305/70R19.5","315/70R22.5","315/80R22.5","365/65R22.5","385/65R22.5","425/65R22.5","445/50R22.5","445/65R22.5","ST235/80R16","ST235/85R16"];
  var brands={"amulet":"Amulet","royal black":"Royal Black","jinyu":"Jinyu","atlas":"Atlas","lancaster":"Lancaster","giti":"Giti","sailun":"Sailun","inlet":"Amulet","hamlet":"Amulet"};
  var models={"at505":"AT505","ad507":"AD507","aa610":"AA610","aa612":"AA612","ad515":"AD515","sl101":"SL101","sl102":"SL102","dl301":"DL301","am201":"AM201","av211":"AV211","wdv01":"WDV01","dv302":"DV302","dm325":"DM325","tl001":"TL001","8505":"AT505","8505s":"AT505","a505":"AT505","80505":"AT505"};
  var foundBrand=null,foundModel=null,foundSize=null,foundQty=null;
  // Find brand
  Object.keys(brands).forEach(function(b){if(t.indexOf(b)!==-1)foundBrand=brands[b];});
  // Find model from text tokens
  t.split(/[\s,]+/).forEach(function(w){
    var wu=w.replace(/[^a-z0-9]/g,"");
    if(models[wu])foundModel=models[wu];
    if(!foundModel){Object.keys(models).forEach(function(k){if(wu.indexOf(k)!==-1)foundModel=models[k];});}
  });
  // Find size - check for pattern like "511r22.5" -> qty 5 + 11R22.5
  sizes.forEach(function(s){
    var sl=s.toLowerCase();
    // Direct match
    if(t.indexOf(sl)!==-1){foundSize=s;return;}
    // Match with qty prefix: "511r22.5" -> 5 + 11r22.5, "1011r22.5" -> 10 + 11r22.5
    for(var q=1;q<=99;q++){
      if(t.indexOf(q+sl)!==-1||t.indexOf(q+" "+sl)!==-1){foundSize=s;foundQty=q;return;}
    }
    // Match in tokens
    t.split(/[\s,]+/).forEach(function(w){
      if(w===sl){foundSize=s;return;}
      for(var q=1;q<=99;q++){if(w===q+sl){foundSize=s;foundQty=q;}}
    });
  });
  // Find qty if not found from size prefix
  if(!foundQty){
    var qm=t.match(/^(\d{1,2})\s/);
    if(qm)foundQty=parseInt(qm[1]);
    if(!foundQty){qm=t.match(/\b(\d{1,2})\b/);if(qm&&parseInt(qm[1])<=50)foundQty=parseInt(qm[1]);}
  }
  var pos="All Position";
  if(/\b(steer|front)\b/i.test(t))pos="Steer";
  if(/\bdrive\b/i.test(t))pos="Drive";
  if(/\btrailer\b/i.test(t))pos="Trailer";
  return {brand:foundBrand||"",model:foundModel||"",size:foundSize||"",quantity:foundQty,position:pos,condition:"New"};
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

// ---- CONSTANTS ----
const TBR_SIZES = [
  "ST235/85R16",
  "ST235/80R16",
  "11R22.5","11R24.5","12R22.5",
  "215/75R17.5","225/70R19.5","235/75R17.5","245/70R19.5",
  "255/70R22.5","265/70R19.5","275/70R22.5","275/80R22.5",
  "285/75R24.5","295/60R22.5","295/75R22.5","295/80R22.5",
  "305/70R19.5","315/70R22.5","315/80R22.5",
  "365/65R22.5","385/65R22.5","425/65R22.5",
  "445/50R22.5","445/65R22.5"
];

const BRANDS_MODELS = {
  "Atlas":[""],
  "Lancaster":[""],
  "Amulet":["AT505","AD507","AA610","AA612","AD515"],
  "Jinyu":["YS82","YS81","JY512","JU565","JY588","JF568","JT560","JY516"],
  "Royal Black":["SL101","RS201","RB401","RT301","RD801"],
  "Giti":["GSR225","GTL919","GAL831","GDR665","GTL925","GAM851"],
  "Sailun":["S637","S665","S668","S825","S753"],
  "Linglong":["LLF86","LDL831","LFL827","KLD200"],
  "Double Coin":["RLB490","RR680","RT500","RLB400","FD405","RLB900"],
  "Triangle":["TRS02","TRD06","TR685","TR657","TR689"],
  "Westlake":["CM983","CM985","CR960A","AL37","AT161"],
  "Aeolus":["HN308","HN355","ADL67","AGC28","HN366"],
  "Boto":["BT388","BT556","BT926","BT215"],
  "Prinx":["AR602","DR700","GR600"],
  "Thunderer":["OD432","LA432","RA403","RR432"],
  "Roadmaster":["RM185A","RM230","RM170","RM254","RM275","RM832"],
  "Ironman":["I-109","I-208","I-307","I-601"],
  "Cosmo":["CT701","CT519","CT708"],
  "Michelin":["XDS2","XDN2","X Line Energy","XZA3","XDA5","XDE2+","XTE2"],
  "Bridgestone":["R283A","R250F","M726EL","R197","R268","M710"],
  "Goodyear":["G572","G661","G949","Marathon LHT","G316","G399A","Fuel Max"],
  "Continental":["HSL2","HDL2","Conti EcoPlus","HSR2","HDR2","HTL2"],
  "Firestone":["FS591","FD691","FT491","FS561"],
  "Hankook":["TH22","DL11","AL22","TH31","SmartFlex AH35","DH37"],
  "Toyo":["M144","M655","M647","M920"],
  "Yokohama":["TY517","RY587","TY023","104ZR","RY507"],
  "Cooper":["WORK Series","PRO Series"],
  "General":["RA","RD","S360","S581"],
  "Kelly":["KDA","KLS","Armorsteel"],
  "Kumho":["KRD50","KRS02","KLD11"],
  "Nexen":["NTD85","NRD82","NRD21"],
  "Falken":["BI830","RI151","GI368"],
  "BF Goodrich":["DR454","ST230","Cross Control"],
  "Sumitomo":["ST778SE","ST948SE","SP160"],
  "Pirelli":["H89","R89","FR01","TR01"],
  "Dunlop":["SP461","SP160","SP346"],
  "Zenna":["DR-750","AP-250","MP-860"],
  "Nitto":["Dura Grappler"],
  "Maxxis":["UR-275","UE-168"]
};

// ---- STATE ----
let currentUser = null;
let currentRole = null;
let sessionMoves = [];
let allMovements = [];  // cached
let allItems = {};      // cached: sku -> item doc
let allZones = [];
let fetMode = "separate";
let onHandCache = {};   // sku -> qty

// ---- AUTH ----
auth.onAuthStateChanged(async user => {
  if (user) {
    currentUser = user;
    const doc = await db.collection("users").doc(user.uid).get();
    if (!doc.exists) {
      // First user ever = auto-admin
      const count = (await db.collection("users").limit(1).get()).size;
      if (count === 0) {
        await db.collection("users").doc(user.uid).set({
          email: user.email, role: "admin", createdAt: firebase.firestore.FieldValue.serverTimestamp()
        });
        currentRole = "admin";
      } else {
        toast("Account not set up. Ask admin.", "err");
        auth.signOut();
        return;
      }
    } else {
      currentRole = doc.data().role;
    }
    showApp();
  } else {
    currentUser = null;
    currentRole = null;
    document.getElementById("loginScreen").style.display = "flex";
    document.getElementById("appScreen").style.display = "none";
  }
});

window.doLogin = async function() {
  const email = document.getElementById("loginEmail").value.trim();
  const pass = document.getElementById("loginPass").value;
  const errEl = document.getElementById("loginErr");
  errEl.style.display = "none";
  if (!email || !pass) { errEl.textContent = "Enter email and password"; errEl.style.display = "block"; return; }
  try {
    await auth.signInWithEmailAndPassword(email, pass);
  } catch (e) {
    errEl.textContent = e.message.replace("Firebase: ", "");
    errEl.style.display = "block";
  }
};

window.doLogout = function() { auth.signOut(); };

// ---- INIT APP ----
async function showApp() {
  document.getElementById("loginScreen").style.display = "none";
  document.getElementById("appScreen").style.display = "grid";
  document.getElementById("userEmail").textContent = currentUser.email;
  const badge = document.getElementById("roleBadge");
  badge.textContent = currentRole;
  badge.className = "role-badge " + currentRole;

  // Show admin tabs
  document.querySelectorAll(".tab.admin-only").forEach(t => {
    t.classList.toggle("show", currentRole === "admin");
  });

  // Init dropdowns
  populateBrands();
  populateSizes();
  try {
    await loadZones();
  await loadItems();
  await loadConfig();
  await computeOnHand();
  refreshDash();
  } catch(e) { console.error("Init error:", e); }
}

// ---- DROPDOWNS ----
function populateBrands() {
  const brands = Object.keys(BRANDS_MODELS).sort();
  ["mvBrand", "fBrand"].forEach(id => {
    const sel = document.getElementById(id);
    const first = sel.options[0];
    sel.innerHTML = "";
    sel.appendChild(first);
    brands.forEach(b => { const o = document.createElement("option"); o.value = b; o.textContent = b; sel.appendChild(o); });
  });
}

function populateSizes() {
  ["mvSize", "fSize", "iSize"].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const first = sel.options[0];
    sel.innerHTML = "";
    sel.appendChild(first);
    TBR_SIZES.forEach(s => { const o = document.createElement("option"); o.value = s; o.textContent = s; sel.appendChild(o); });
  });
}

window.onBrandChange = function() {
  const brand = document.getElementById("mvBrand").value;
  const sel = document.getElementById("mvModel");
  sel.innerHTML = '<option value="">Select model...</option>';
  if (brand && BRANDS_MODELS[brand]) {
    BRANDS_MODELS[brand].forEach(m => {
      const o = document.createElement("option"); o.value = m; o.textContent = m; sel.appendChild(o);
    });
  }
};

// ---- QUICK SELECT HELPERS ----
window.setMvType = function(btn) {
  btn.parentElement.querySelectorAll(".qs-btn").forEach(b => b.classList.remove("active","neg"));
  btn.classList.add("active");
  if (btn.dataset.val === "sale") btn.classList.add("neg");
};

window.setQS = function(btn) {
  btn.parentElement.querySelectorAll(".qs-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
};

function getQS(parentId) {
  const active = document.querySelector(`#${parentId} .qs-btn.active`);
  return active ? active.dataset.val : "";
}

window.adjQty = function(delta) {
  const inp = document.getElementById("mvQty");
  let v = parseInt(inp.value) || 0;
  v = Math.max(1, v + delta);
  inp.value = v;
};

// ---- ZONES ----
async function loadZones() {
  const snap = await db.collection("zones").orderBy("name").get();
  allZones = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  ["mvZone", "fZone"].forEach(id => {
    const sel = document.getElementById(id);
    const first = sel.options[0];
    sel.innerHTML = "";
    sel.appendChild(first);
    allZones.forEach(z => { const o = document.createElement("option"); o.value = z.name; o.textContent = z.name; sel.appendChild(o); });
  });
}

window.addZone = async function() {
  const name = document.getElementById("newZone").value.trim();
  if (!name) return;
  await db.collection("zones").add({ name, createdBy: currentUser.uid });
  document.getElementById("newZone").value = "";
  await loadZones();
  renderZoneList();
  toast("Zone added");
};

function renderZoneList() {
  const el = document.getElementById("zoneList");
  if (!allZones.length) { el.innerHTML = '<div class="small">No zones yet</div>'; return; }
  el.innerHTML = allZones.map(z =>
    `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--bd)">
      <span>${z.name}</span>
      ${currentRole === "admin" ? `<button class="btn btn-sm btn-danger" onclick="delZone('${z.id}')" style="padding:4px 10px;min-height:auto;font-size:12px">-</button>` : ""}
    </div>`
  ).join("");
}

window.delZone = async function(id) {
  if (!confirm("Delete this zone?")) return;
  await db.collection("zones").doc(id).delete();
  await loadZones();
  renderZoneList();
};

// ---- CONFIG ----
async function loadConfig() {
  const doc = await db.collection("config").doc("settings").get();
  if (doc.exists) {
    fetMode = doc.data().fetMode || "separate";
  }
  updateFETButtons();
}

function updateFETButtons() {
  document.getElementById("fetSep").classList.toggle("active", fetMode === "separate");
  document.getElementById("fetInc").classList.toggle("active", fetMode === "included");
}

window.setFET = async function(mode) {
  fetMode = mode;
  await db.collection("config").doc("settings").set({ fetMode }, { merge: true });
  updateFETButtons();
  toast("FET mode: " + mode);
};

// ---- ITEMS (SKU MASTER) ----
async function loadItems() {
  const snap = await db.collection("items").get();
  allItems = {};
  snap.docs.forEach(d => { allItems[d.id] = { id: d.id, ...d.data() }; });
}

function makeSKU(brand, model, size, position, condition) {
  return [brand, model, size, position || "", condition || ""].map(s => (s || "").toLowerCase().trim()).join("|");
}

window.renderItems = function() {
  const search = (document.getElementById("itemSearch")?.value || "").toLowerCase();
  const tbody = document.getElementById("itemsTbody");
  const items = Object.values(allItems).filter(i => {
    if (!search) return true;
    return (i.brand + i.model + i.size).toLowerCase().includes(search);
  }).sort((a, b) => (a.brand + a.size).localeCompare(b.brand + b.size));

  tbody.innerHTML = items.map(i => {
    const landed = (parseFloat(i.unitCost) || 0) + (parseFloat(i.fet) || 0);
    return `<tr>
      <td class="mono">${i.brand || ""}</td>
      <td>${i.model || ""}</td>
      <td class="mono">${i.size || ""}</td>
      <td class="small">${i.position || "-"}</td>
      <td style="text-align:right" class="mono">$${(i.unitCost || 0).toFixed(2)}</td>
      <td style="text-align:right" class="mono">$${(i.fet || 0).toFixed(2)}</td>
      <td style="text-align:right" class="mono" style="color:var(--g)">$${landed.toFixed(2)}</td>
      <td><button class="btn btn-sm" onclick="editItem('${i.id}')" style="padding:4px 10px;min-height:auto;font-size:12px">--</button></td>
    </tr>`;
  }).join("") || '<tr><td colspan="8" class="small">No items yet. Add SKUs to track costs.</td></tr>';
};

window.openItemModal = function(id) {
  document.getElementById("itemEditId").value = id || "";
  document.getElementById("itemModalTitle").textContent = id ? "Edit Item" : "Add Item";
  populateSizes(); // ensure iSize is populated
  if (id && allItems[id]) {
    const i = allItems[id];
    document.getElementById("iBrand").value = i.brand || "";
    document.getElementById("iModel").value = i.model || "";
    document.getElementById("iSize").value = i.size || "";
    document.getElementById("iPos").value = i.position || "";
    document.getElementById("iCond").value = i.condition || "New";
    document.getElementById("iCost").value = i.unitCost || "";
    document.getElementById("iFET").value = i.fet || "";
    document.getElementById("iLanded").value = ((parseFloat(i.unitCost) || 0) + (parseFloat(i.fet) || 0)).toFixed(2);
  } else {
    ["iBrand","iModel","iCost","iFET","iLanded"].forEach(id => document.getElementById(id).value = "");
    document.getElementById("iPos").value = "";
    document.getElementById("iCond").value = "New";
    if (document.getElementById("iSize").options.length > 1) document.getElementById("iSize").selectedIndex = 0;
  }
  openModal("modalItem");
};

window.editItem = function(id) { openItemModal(id); };

// Auto-calc landed cost
document.addEventListener("input", e => {
  if (e.target.id === "iCost" || e.target.id === "iFET") {
    const cost = parseFloat(document.getElementById("iCost").value) || 0;
    const fet = parseFloat(document.getElementById("iFET").value) || 0;
    document.getElementById("iLanded").value = (cost + fet).toFixed(2);
  }
});

window.saveItem = async function() {
  const brand = document.getElementById("iBrand").value.trim();
  const model = document.getElementById("iModel").value.trim();
  const size = document.getElementById("iSize").value;
  const position = document.getElementById("iPos").value;
  const condition = document.getElementById("iCond").value;
  const unitCost = parseFloat(document.getElementById("iCost").value) || 0;
  const fet = parseFloat(document.getElementById("iFET").value) || 0;

  if (!brand || !size) { toast("Brand and Size required", "err"); return; }

  const sku = makeSKU(brand, model, size, position, condition);
  const editId = document.getElementById("itemEditId").value;
  const docId = editId || sku;

  const data = {
    brand, model, size, position, condition, unitCost, fet,
    landedCost: unitCost + fet,
    sku,
    updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
    updatedBy: currentUser.uid
  };

  // If editing and SKU changed, delete old doc
  if (editId && editId !== sku) {
    await db.collection("items").doc(editId).delete();
  }

  await db.collection("items").doc(docId).set(data, { merge: true });

  // Add cost history entry
  await db.collection("items").doc(docId).collection("costHistory").add({
    unitCost, fet, landedCost: unitCost + fet,
    effectiveDate: firebase.firestore.FieldValue.serverTimestamp(),
    setBy: currentUser.email
  });

  await loadItems();
  renderItems();
  closeModal("modalItem");
  toast("Item saved");
};

// ---- MOVEMENTS ----
window.submitMovement = async function() {
  const btn = document.getElementById("btnSubmit");
  btn.disabled = true;
  btn.textContent = "Saving...";

  try {
    const source = getQS("mvType");
    const brand = document.getElementById("mvBrand").value;
    const model = document.getElementById("mvModel").value;
    const size = document.getElementById("mvSize").value;
    const position = document.getElementById("mvPos").value;
    const condition = getQS("mvCond");
    const zone = document.getElementById("mvZone").value;
    const rawQty = parseInt(document.getElementById("mvQty").value) || 0;
    const notes = document.getElementById("mvNotes").value.trim();

    if (!brand || !size || rawQty < 1) {
      toast("Brand, Size, and Qty required", "err");
      return;
    }

    // Sale = negative qty
    const qty = (source === "sale") ? -rawQty : rawQty;
    const sku = makeSKU(brand, model, size, position, condition);

    const movement = {
      timestamp: firebase.firestore.FieldValue.serverTimestamp(),
      userId: currentUser.uid,
      userEmail: currentUser.email,
      brand, model, size, position, condition, zone,
      qty, source, notes, sku
    };

    await db.collection("movements").add(movement);

    // Update on-hand cache
    onHandCache[sku] = (onHandCache[sku] || 0) + qty;

    // Track session
    sessionMoves.unshift({ ...movement, qty, timestamp: new Date() });
    renderRecent();

    // Reset qty
    document.getElementById("mvQty").value = "1";
    document.getElementById("mvNotes").value = "";

    toast(`${qty > 0 ? "+" : ""}${qty} ${brand} ${size} recorded`);
  } catch (e) {
    toast("Error: " + e.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "- Record Movement";
  }
};

function renderRecent() {
  const el = document.getElementById("recentList");
  if (!sessionMoves.length) { el.innerHTML = '<div class="small">No entries yet</div>'; return; }
  el.innerHTML = sessionMoves.slice(0, 20).map(m => {
    const cls = m.qty > 0 ? "pos" : "neg";
    const sign = m.qty > 0 ? "+" : "";
    return `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--bd)">
      <span><span class="mono ${cls}">${sign}${m.qty}</span> <strong>${m.brand}</strong> ${m.model || ""} <span class="mono">${m.size}</span></span>
      <span class="small">${m.source}</span>
    </div>`;
  }).join("");
}

// ---- COMPUTE ON-HAND ----
async function computeOnHand() {
  const snap = await db.collection("movements").get();
  allMovements = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  onHandCache = {};
  allMovements.forEach(m => {
    const sku = m.sku || makeSKU(m.brand, m.model, m.size, m.position, m.condition);
    onHandCache[sku] = (onHandCache[sku] || 0) + (m.qty || 0);
  });
}

// ---- DASHBOARD ----
window.refreshDash = async function() {
  await computeOnHand();
  await loadItems();

  const fBrand = document.getElementById("fBrand").value;
  const fSize = document.getElementById("fSize").value;
  const fPos = document.getElementById("fPos").value;
  const fZone = document.getElementById("fZone").value;
  const fSearch = (document.getElementById("fSearch").value || "").toLowerCase();

  // Build on-hand rows with details
  // Group movements by SKU to get details
  const skuDetails = {};
  allMovements.forEach(m => {
    const sku = m.sku || makeSKU(m.brand, m.model, m.size, m.position, m.condition);
    if (!skuDetails[sku]) {
      skuDetails[sku] = { brand: m.brand, model: m.model, size: m.size, position: m.position, condition: m.condition, zone: m.zone };
    }
  });

  let rows = [];
  for (const [sku, qty] of Object.entries(onHandCache)) {
    if (qty === 0) continue;
    const d = skuDetails[sku] || {};
    const item = allItems[sku] || {};
    const landed = item.landedCost || 0;
    const value = qty * landed;

    // Filters
    if (fBrand && d.brand !== fBrand) continue;
    if (fSize && d.size !== fSize) continue;
    if (fPos && d.position !== fPos) continue;
    if (fZone && d.zone !== fZone) continue;
    if (fSearch && !(d.brand + d.model + d.size + d.position + d.condition).toLowerCase().includes(fSearch)) continue;

    rows.push({ sku, qty, value, landed, ...d });
  }

  rows.sort((a, b) => b.qty - a.qty);

  // Stats
  const totalUnits = rows.reduce((s, r) => s + r.qty, 0);
  const totalValue = rows.reduce((s, r) => s + r.value, 0);
  const today = new Date().toDateString();
  const todayMoves = allMovements.filter(m => {
    const t = m.timestamp?.toDate ? m.timestamp.toDate() : new Date(m.timestamp);
    return t.toDateString() === today;
  }).length;

  document.getElementById("statTotalUnits").textContent = totalUnits.toLocaleString();
  document.getElementById("statTotalSKU").textContent = rows.length;
  document.getElementById("statTotalValue").textContent = "$" + totalValue.toLocaleString(undefined, { minimumFractionDigits: 0, maximumFractionDigits: 0 });
  document.getElementById("statTodayMoves").textContent = todayMoves;

  // Table
  const tbody = document.getElementById("dashTbody");
  tbody.innerHTML = rows.map(r => {
    const cls = r.qty < 0 ? "neg" : "";
    return `<tr>
      <td class="mono">${r.brand || ""}</td>
      <td>${r.model || ""}</td>
      <td class="mono">${r.size || ""}</td>
      <td class="small">${r.position || "-"}</td>
      <td class="small">${r.condition || "---"}</td>
      <td style="text-align:right" class="mono ${cls}">${r.qty}</td>
      <td style="text-align:right" class="mono">${r.landed > 0 ? "$" + r.value.toFixed(0) : "-"}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="7" class="small">No inventory on hand</td></tr>';

  // Top sizes
  renderTopSizes(rows);
};

function renderTopSizes(rows) {
  // By units
  const bySize = {};
  rows.forEach(r => {
    if (!bySize[r.size]) bySize[r.size] = { qty: 0, value: 0 };
    bySize[r.size].qty += r.qty;
    bySize[r.size].value += r.value;
  });

  const topUnits = Object.entries(bySize).sort((a, b) => b[1].qty - a[1].qty).slice(0, 8);
  const topValue = Object.entries(bySize).sort((a, b) => b[1].value - a[1].value).slice(0, 8);

  document.getElementById("topUnits").innerHTML = topUnits.map(([size, d]) =>
    `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd)">
      <span class="mono">${size}</span><span class="mono pos">${d.qty}</span>
    </div>`
  ).join("") || '<div class="small">No data</div>';

  document.getElementById("topValue").innerHTML = topValue.map(([size, d]) =>
    `<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--bd)">
      <span class="mono">${size}</span><span class="mono">$${d.value.toFixed(0)}</span>
    </div>`
  ).join("") || '<div class="small">No data</div>';
}

// ---- CYCLE COUNT ----
function loadCycleSkus() {
  const sel = document.getElementById("ccSku");
  sel.innerHTML = '<option value="">Pick a SKU...</option>';
  const skus = Object.entries(onHandCache).filter(([, q]) => q !== 0).sort((a, b) => a[0].localeCompare(b[0]));
  // Also add items with 0 on hand (they might still be in items master)
  const allSkus = new Set([...Object.keys(onHandCache), ...Object.keys(allItems)]);
  Array.from(allSkus).sort().forEach(sku => {
    const parts = sku.split("|");
    const label = `${parts[0]} ${parts[1]} ${parts[2]} ${parts[3] || ""} ${parts[4] || ""}`.trim();
    const o = document.createElement("option");
    o.value = sku;
    o.textContent = `${label} (${onHandCache[sku] || 0} on hand)`;
    sel.appendChild(o);
  });
}

window.loadCCSku = function() {
  const sku = document.getElementById("ccSku").value;
  const infoEl = document.getElementById("ccInfo");
  if (!sku) { infoEl.style.display = "none"; return; }
  infoEl.style.display = "block";
  const sysQty = onHandCache[sku] || 0;
  document.getElementById("ccSystem").textContent = sysQty;
  document.getElementById("ccPhysical").value = sysQty;
  document.getElementById("ccDelta").textContent = "0";

  document.getElementById("ccPhysical").oninput = function() {
    const phys = parseInt(this.value) || 0;
    const delta = phys - sysQty;
    const el = document.getElementById("ccDelta");
    el.textContent = (delta > 0 ? "+" : "") + delta;
    el.className = "mono " + (delta > 0 ? "pos" : delta < 0 ? "neg" : "");
    el.style.fontSize = "24px";
  };
};

window.submitCycleCount = async function() {
  const sku = document.getElementById("ccSku").value;
  if (!sku) return;
  const sysQty = onHandCache[sku] || 0;
  const physical = parseInt(document.getElementById("ccPhysical").value) || 0;
  const delta = physical - sysQty;
  if (delta === 0) { toast("No adjustment needed"); return; }

  const parts = sku.split("|");
  const notes = document.getElementById("ccNotes").value.trim();

  await db.collection("movements").add({
    timestamp: firebase.firestore.FieldValue.serverTimestamp(),
    userId: currentUser.uid,
    userEmail: currentUser.email,
    brand: parts[0] || "", model: parts[1] || "", size: parts[2] || "",
    position: parts[3] || "", condition: parts[4] || "",
    zone: "", qty: delta, source: "count",
    notes: `Cycle count: system=${sysQty}, physical=${physical}. ${notes}`.trim(),
    sku
  });

  onHandCache[sku] = physical;
  toast(`Count recorded: ${delta > 0 ? "+" : ""}${delta}`);
  document.getElementById("ccSku").value = "";
  document.getElementById("ccInfo").style.display = "none";
};

// ---- AUDIT ----
window.loadAudit = async function() {
  const snap = await db.collection("movements").orderBy("timestamp", "desc").limit(100).get();
  const tbody = document.getElementById("auditTbody");
  tbody.innerHTML = snap.docs.map(d => {
    const m = d.data();
    const t = m.timestamp?.toDate ? m.timestamp.toDate() : null;
    const timeStr = t ? t.toLocaleString() : "-";
    const cls = (m.qty || 0) > 0 ? "pos" : "neg";
    const sign = (m.qty || 0) > 0 ? "+" : "";
    return `<tr>
      <td class="small">${timeStr}</td>
      <td class="small">${m.userEmail || "-"}</td>
      <td>${m.source || "-"}</td>
      <td class="mono">${m.brand || ""}</td>
      <td>${m.model || ""}</td>
      <td class="mono">${m.size || ""}</td>
      <td style="text-align:right" class="mono ${cls}">${sign}${m.qty || 0}</td>
      <td class="small">${m.notes || ""}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="8" class="small">No movements yet</td></tr>';
};

// ---- ADMIN: USERS ----
window.loadUsers = async function() {
  const snap = await db.collection("users").get();
  const el = document.getElementById("userList");
  el.innerHTML = snap.docs.map(d => {
    const u = d.data();
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--bd)">
      <div><strong>${u.email}</strong> <span class="role-badge ${u.role}" style="font-size:9px">${u.role}</span></div>
      <div class="btn-group">
        <button class="btn btn-sm" onclick="toggleRole('${d.id}','${u.role}')" style="padding:4px 10px;min-height:auto;font-size:11px">
          Switch to ${u.role === "admin" ? "warehouse" : "admin"}
        </button>
      </div>
    </div>`;
  }).join("") || '<div class="small">No users</div>';
};

window.toggleRole = async function(uid, current) {
  const newRole = current === "admin" ? "warehouse" : "admin";
  await db.collection("users").doc(uid).update({ role: newRole });
  toast(`Role changed to ${newRole}`);
  loadUsers();
};

window.openAddUser = function() { openModal("modalAddUser"); };

window.createUser = async function() {
  const email = document.getElementById("nuEmail").value.trim();
  const pass = document.getElementById("nuPass").value;
  const role = getQS("modalAddUser") || "warehouse";

  if (!email || !pass) { toast("Email and password required", "err"); return; }
  if (pass.length < 6) { toast("Password must be 6+ chars", "err"); return; }

  // We need to create user via Auth, but Firebase client SDK signs in the new user
  // Workaround: save current user, create new, then sign back in
  // Better: use a secondary auth instance
  try {
    const secondaryApp = firebase.initializeApp(firebaseConfig, "secondary-" + Date.now());
    const secondaryAuth = secondaryApp.auth();
    const cred = await secondaryAuth.createUserWithEmailAndPassword(email, pass);

    // Determine selected role from quick-select buttons
    const roleBtn = document.querySelector("#modalAddUser .qs-btn.active");
    const selectedRole = roleBtn ? roleBtn.dataset.val : "warehouse";

    await db.collection("users").doc(cred.user.uid).set({
      email, role: selectedRole, createdAt: firebase.firestore.FieldValue.serverTimestamp(), createdBy: currentUser.uid
    });

    await secondaryAuth.signOut();
    await secondaryApp.delete();

    closeModal("modalAddUser");
    toast(`User ${email} created as ${selectedRole}`);
    loadUsers();
  } catch (e) {
    toast("Error: " + e.message, "err");
  }
};

// ---- EXPORT ----
window.exportOnHand = function() {
  const skuDetails = {};
  allMovements.forEach(m => {
    const sku = m.sku || makeSKU(m.brand, m.model, m.size, m.position, m.condition);
    if (!skuDetails[sku]) skuDetails[sku] = { brand: m.brand, model: m.model, size: m.size, position: m.position, condition: m.condition };
  });

  let csv = "Brand,Model,Size,Position,Condition,OnHand,UnitCost,FET,LandedCost,Value\n";
  for (const [sku, qty] of Object.entries(onHandCache)) {
    if (qty === 0) continue;
    const d = skuDetails[sku] || {};
    const item = allItems[sku] || {};
    const landed = item.landedCost || 0;
    csv += `${d.brand || ""},${d.model || ""},${d.size || ""},${d.position || ""},${d.condition || ""},${qty},${item.unitCost || 0},${item.fet || 0},${landed},${(qty * landed).toFixed(2)}\n`;
  }
  downloadCSV(csv, `oxley-onhand-${dateStr()}.csv`);
};

window.exportMovements = async function() {
  const snap = await db.collection("movements").orderBy("timestamp", "desc").get();
  let csv = "Timestamp,User,Source,Brand,Model,Size,Position,Condition,Zone,Qty,Notes\n";
  snap.docs.forEach(d => {
    const m = d.data();
    const t = m.timestamp?.toDate ? m.timestamp.toDate().toISOString() : "";
    csv += `${t},${m.userEmail || ""},${m.source || ""},${m.brand || ""},${m.model || ""},${m.size || ""},${m.position || ""},${m.condition || ""},${m.zone || ""},${m.qty || 0},"${(m.notes || "").replace(/"/g, '""')}"\n`;
  });
  downloadCSV(csv, `oxley-movements-${dateStr()}.csv`);
};

function downloadCSV(csv, filename) {
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
  toast("Exported " + filename);
}

function dateStr() {
  return new Date().toISOString().slice(0, 10);
}

// ---- MODALS ----
window.openModal = function(id) { document.getElementById(id).classList.add("show"); };
window.closeModal = function(id) { document.getElementById(id).classList.remove("show"); };

// Close modal on background click
document.querySelectorAll(".modal-bg").forEach(bg => {
  bg.addEventListener("click", e => { if (e.target === bg) bg.classList.remove("show"); });
});

// ---- TOAST ----
function toast(msg, type = "ok") {
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

// ---- KEYBOARD: Enter to submit on login ----
document.getElementById("loginPass")?.addEventListener("keydown", e => {
  if (e.key === "Enter") doLogin();
});


window.saveGeminiKey=async function(){var k=document.getElementById("geminiKey").value.trim();if(!k)return;await db.collection("config").doc("gemini").set({key:k},{merge:true});window._gemKey=k;toast("Key saved");document.getElementById("voiceSettingsCard").style.display="none";};;


var voiceOn=false,voiceSession=[];
function voiceListen(){
  var s=document.getElementById("voiceStatus");
  var h=document.getElementById("voiceHeard");
  s.textContent="Listening...";
  document.getElementById("voiceMicBtn").className="listening";
  var SR=window.SpeechRecognition||window.webkitSpeechRecognition;
  var rec=new SR();
  rec.lang="en-US";
  rec.onresult=function(e){
    var text=e.results[0][0].transcript;
    h.textContent=text;
    s.textContent="Processing...";
    document.getElementById("voiceMicBtn").className="thinking";
    var r;try{r=parseVoiceTranscript(text);}catch(err){document.getElementById("voiceStatus").textContent="PARSE ERR: "+err.message;document.getElementById("voiceMicBtn").className="";if(voiceOn)setTimeout(voiceListen,2000);return;}document.getElementById("voiceStatus").textContent="GOT: "+JSON.stringify(r);
    if(r.size||r.brand){
      if(r.quantity&&r.quantity>0){
        document.getElementById("voiceStatus").textContent="Saving: "+r.brand+" "+r.size+" x"+r.quantity;voiceSaveEntry(r).then(function(){
          s.textContent="+"+r.quantity+" "+r.brand+" "+r.size;
          document.getElementById("voiceMicBtn").className="success";
          if(voiceOn)setTimeout(voiceListen,1500);
        });
      }else{
        s.textContent=r.brand+" "+r.size+" - how many?";
        document.getElementById("voiceMicBtn").className="asking";
      }
    }else{
      s.textContent="Didn't catch that";
      if(voiceOn)setTimeout(voiceListen,1000);
    }
  };
  rec.onerror=function(e){s.textContent="MIC ERROR: "+e.error;document.getElementById("voiceMicBtn").className="";};
  rec.onend=function(){if(voiceOn&&document.getElementById("voiceMicBtn").className==="listening")setTimeout(voiceListen,500);};
  rec.start();
}
window.voiceToggle=function(){
  if(voiceOn){voiceOn=false;document.getElementById("voiceStatus").textContent="Stopped";document.getElementById("voiceMicBtn").className="";return;}
  voiceOn=true;
  voiceListen();
};
async function voiceSaveEntry(entry){
  var sku=[entry.brand,entry.model,entry.size,entry.position||"",entry.condition||""].map(function(x){return(x||"").toLowerCase().trim();}).join("|");
  try{
    var ref=await db.collection("movements").add({timestamp:firebase.firestore.FieldValue.serverTimestamp(),userId:currentUser.uid,userEmail:currentUser.email,brand:entry.brand,model:entry.model||"",size:entry.size,position:entry.position||"",condition:entry.condition||"New",zone:"",qty:entry.quantity,source:"count",notes:"Voice count",sku:sku});
    entry.fid=ref.id;
    onHandCache[sku]=(onHandCache[sku]||0)+entry.quantity;
  }catch(e){document.getElementById("voiceStatus").textContent="Error: "+e.message;return;}
  voiceSession.unshift(entry);
  voiceRenderLog();
}
window.voiceUndo=async function(){
  if(!voiceSession.length)return;
  var last=voiceSession.shift();
  if(last.fid){try{await db.collection("movements").doc(last.fid).delete();}catch(e){}var sku=[last.brand,last.model,last.size,last.position||"",last.condition||""].map(function(x){return(x||"").toLowerCase().trim();}).join("|");onHandCache[sku]=(onHandCache[sku]||0)-last.quantity;}
  voiceRenderLog();
  document.getElementById("voiceStatus").textContent="Removed "+last.brand+" "+last.size;
};
window.voiceClear=function(){voiceSession=[];voiceRenderLog();};
function voiceRenderLog(){
  var el=document.getElementById("voiceLog");
  var total=voiceSession.reduce(function(s,e){return s+(e.quantity||0);},0);
  document.getElementById("voiceSessionCount").textContent=total+" tires";
  if(!voiceSession.length){el.innerHTML="No entries yet";return;}
  el.innerHTML=voiceSession.map(function(e){return "<div style=\"display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #333\"><span><b style=\"color:#0f0\">"+e.brand+"</b> "+(e.model||"")+" <code>"+e.size+"</code></span><span style=\"font-size:20px;font-weight:bold\">+"+e.quantity+"</span></div>";}).join("");
}

async function voiceGemini(text){
  var prompt="You are a TBR tire inventory parser. The input is garbled speech-to-text. Figure out what tire is being described. Return ONLY JSON: {brand,model,size,quantity,position,condition}. Voice mangles: or/are/our=R, by/buy=/, point=., amulet/inlet/hamlet=Amulet, royal black/royalblack=Royal Black. Brands: Amulet(AT505,AD507,AA610,AA612,AD515), Royal Black(SL101,SL102,DL301,AM201,AV211,WDV01,DV302,DM325,TL001), Jinyu, Atlas, Lancaster. Sizes: 11R22.5,11R24.5,225/70R19.5,235/75R17.5,255/70R22.5,275/70R22.5,285/75R24.5,295/75R22.5,315/80R22.5,385/65R22.5,425/65R22.5,ST235/80R16,ST235/85R16. Input: "+text;
  var resp=await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=AIzaSyDGeGbcMQrcMNeZzNutbbb4oUsTXEimnSo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({contents:[{parts:[{text:prompt}]}]})});
  if(!resp.ok){var e=await resp.text();throw new Error("API "+resp.status);}
  var data=await resp.json();
  var t=data.candidates[0].content.parts[0].text;
  var m=t.match(/\{[\s\S]*\}/);
  if(m)return JSON.parse(m[0]);
  return JSON.parse(t);
}
