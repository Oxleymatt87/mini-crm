/* Oxley Tire CRM — Shared header + bottom navigation
 * Auto-injects on every page that loads this script.
 * Highlights the tab matching window.location.pathname.
 */
(function () {
  if (window.__oxleyNavInjected) return;
  window.__oxleyNavInjected = true;

  var TABS = [
    { href: '/index.html',     icon: '\u{1F3E0}', label: 'Home',      match: ['/', '/index.html'] },
    { href: '/map.html',       icon: '\u{1F5FA}', label: 'Territory', match: ['/map.html'] },
    { href: '/intake.html',    icon: '\u{1F4E6}', label: 'Intake',    match: ['/intake.html'] },
    { href: '/ledger.html',    icon: '\u{1F4CA}', label: 'Ledger',    match: ['/ledger.html'] },
    { href: '/customers.html', icon: '\u{1F465}', label: 'Customers', match: ['/customers.html'] }
  ];

  var css = ''
    + ':root{--ox-nav-bg:#080a0d;--ox-nav-border:#15181f;--ox-nav-active:#d4a12a;--ox-nav-inactive:#4a5568;--ox-nav-text:#e8eaf0;}'
    + '.ox-header{position:fixed;top:0;left:0;right:0;z-index:90;background:#080a0d;border-bottom:1px solid #15181f;padding:10px 16px;display:flex;align-items:center;justify-content:space-between;height:52px}'
    + '.ox-header-brand{display:flex;align-items:center;gap:10px;color:#d4a12a;font-weight:800;letter-spacing:1.5px;font-size:14px;text-transform:uppercase;text-decoration:none}'
    + '.ox-header-brand .ox-logo{width:28px;height:28px;border-radius:7px;background:linear-gradient(135deg,#d4a12a,#a67e1e);color:#080a0d;display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:900;box-shadow:0 2px 6px rgba(212,161,42,.35)}'
    + '.ox-header-right{display:flex;align-items:center;gap:8px}'
    + '.ox-header-extra{display:flex;align-items:center;gap:8px}'
    + '.ox-header-extra:empty{display:none}'
    + '.ox-header-bell{position:relative;width:38px;height:38px;border-radius:50%;border:1px solid #1e2229;background:transparent;color:#9499aa;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:color .15s,border-color .15s;flex-shrink:0}'
    + '.ox-header-bell:active{transform:scale(.94)}'
    + '.ox-header-bell .ox-bell-dot{position:absolute;top:8px;right:9px;width:7px;height:7px;border-radius:50%;background:#ef4444;border:1.5px solid #080a0d;display:none}'
    + '.ox-header-bell.has-unread .ox-bell-dot{display:block}'
    + '.ox-bottom-nav{position:fixed;left:0;right:0;bottom:0;z-index:95;background:#080a0d;border-top:1px solid #15181f;display:flex;justify-content:space-around;align-items:stretch;height:calc(64px + env(safe-area-inset-bottom,0px));padding-bottom:env(safe-area-inset-bottom,0px);box-shadow:0 -4px 16px rgba(0,0,0,.55);-webkit-tap-highlight-color:transparent}'
    + '.ox-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;background:none;border:none;color:#4a5568;text-decoration:none;font-family:inherit;cursor:pointer;padding:6px 4px;min-height:64px;transition:color .18s ease,transform .12s ease;-webkit-tap-highlight-color:transparent}'
    + '.ox-tab .ox-tab-icon{font-size:26px;line-height:1;transition:transform .18s ease,filter .18s ease;filter:grayscale(.55) opacity(.85)}'
    + '.ox-tab .ox-tab-label{font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;line-height:1}'
    + '.ox-tab:active{transform:scale(.94)}'
    + '.ox-tab:active .ox-tab-icon{transform:scale(1.05)}'
    + '.ox-tab.is-active{color:#d4a12a}'
    + '.ox-tab.is-active .ox-tab-icon{filter:none;transform:translateY(-1px)}'
    + 'body.has-ox-nav{padding-top:52px}'
    + 'body.has-ox-nav:not([data-ox-fixed-layout]){padding-bottom:calc(64px + env(safe-area-inset-bottom,0px)) !important}';

  function injectStyle() {
    var s = document.createElement('style');
    s.id = 'ox-nav-style';
    s.textContent = css;
    document.head.appendChild(s);
  }

  function currentPath() {
    var p = window.location.pathname || '/';
    if (p === '' || p === '/') return '/index.html';
    return p;
  }

  function buildHeader() {
    var header = document.createElement('header');
    header.className = 'ox-header';
    header.id = 'ox-header';
    header.innerHTML =
      '<a href="/index.html" class="ox-header-brand">' +
        '<span class="ox-logo">O</span>' +
        '<span>Oxley Tire</span>' +
      '</a>' +
      '<div class="ox-header-right">' +
        '<div class="ox-header-extra" id="ox-header-extra"></div>' +
        '<button type="button" class="ox-header-bell" id="ox-header-bell" aria-label="Notifications">' +
          '\u{1F514}' +
          '<span class="ox-bell-dot"></span>' +
        '</button>' +
      '</div>';
    return header;
  }

  function migrateExtras(sourceEl, extraSlot) {
    if (!sourceEl || !extraSlot) return;
    var nodes = sourceEl.querySelectorAll('[data-ox-extra]');
    for (var i = 0; i < nodes.length; i++) {
      extraSlot.appendChild(nodes[i]);
    }
  }

  function buildNav() {
    var path = currentPath();
    var nav = document.createElement('nav');
    nav.className = 'ox-bottom-nav';
    nav.id = 'ox-bottom-nav';
    nav.setAttribute('role', 'navigation');
    nav.setAttribute('aria-label', 'Primary');
    TABS.forEach(function (t) {
      var isActive = t.match.indexOf(path) !== -1;
      var a = document.createElement('a');
      a.className = 'ox-tab' + (isActive ? ' is-active' : '');
      a.href = t.href;
      a.setAttribute('aria-current', isActive ? 'page' : 'false');
      a.innerHTML =
        '<span class="ox-tab-icon" aria-hidden="true">' + t.icon + '</span>' +
        '<span class="ox-tab-label">' + t.label + '</span>';
      a.addEventListener('click', function () {
        if (navigator.vibrate) { try { navigator.vibrate(10); } catch (e) {} }
      });
      nav.appendChild(a);
    });
    return nav;
  }

  function mount() {
    if (!document.body) return;
    injectStyle();
    document.body.classList.add('has-ox-nav');

    if (!document.getElementById('ox-header')) {
      var header = buildHeader();
      document.body.insertBefore(header, document.body.firstChild);
      var marked = document.querySelector('[data-ox-replace-header]');
      if (marked) {
        marked.style.display = 'none';
        migrateExtras(marked, header.querySelector('#ox-header-extra'));
      }
    }

    if (!document.getElementById('ox-bottom-nav')) {
      document.body.appendChild(buildNav());
    }

    var bell = document.getElementById('ox-header-bell');
    if (bell) {
      bell.addEventListener('click', function () {
        if (navigator.vibrate) { try { navigator.vibrate(10); } catch (e) {} }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mount);
  } else {
    mount();
  }
})();
