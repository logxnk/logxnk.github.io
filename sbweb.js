/* sbweb.js — web edition (logxnk.github.io) of the PVT report app.
 * Replaces google.script.run with Supabase: email/password login (GoTrue REST), permissions from my_permissions(),
 * data packs from table `packs` (RLS returns only packs the user may read). No secrets here: URL + publishable key are public.
 * Writes/approvals, AI and Cấu hình go through Edge Functions in step B5; until then they are refused with a clear message. */
(function () {
  'use strict';
  var C = {
    url: 'https://knmgtxfqguxquuvztvnm.supabase.co',
    key: 'sb_publishable_uD-F-2qywApoZQK9WTVeXg_jWu5B6G0',
    maxAgeMs: 8 * 3600 * 1000,   // session ends 8 h after login
    minPw: 10,
    ls: 'sbw_session'
  };
  var SBW = window.SBW = { perms: null, user: null, profile: null, C: C };

  // ---------- page id (UI) -> resource id (DB) ----------
  var ALIAS = { 'ai/chat': 'chung/ai', 'cfg': 'chung/cfg' };
  var B5_ONLY = { 'chung/ai': 1, 'chung/cfg': 1 };   // need server calls (B5): hidden for now
  function rid(id) { id = String(id || ''); var p = id.split('/'); var head = p.slice(0, 2).join('/'); return (ALIAS[head] || head) + (p.length > 2 ? '/' + p.slice(2).join('/') : ''); }
  /** my_permissions() lists every catalogued page/tab the user sees (inheritance already resolved). A tab missing from the
   *  catalogue (new in the UI, not yet in resources) falls back to its page. */
  SBW.level = function (id) {
    var r = rid(id), P = SBW.perms || {};
    if (P[r] !== undefined) return P[r];
    if (SBW.known[r]) return 0;
    var par = r.split('/').slice(0, 2).join('/');
    return par !== r && P[par] !== undefined ? P[par] : 0;
  };
  SBW.known = {};
  SBW.can = function (id) { var r = rid(id); if (B5_ONLY[r.split('/').slice(0, 2).join('/')]) return false; return SBW.level(id) >= 1; };
  SBW.firstPage = function () {
    var out = null;
    (window.MODULES || []).some(function (mo) { return mo.pages.some(function (pg) { var id = mo.id + '/' + pg.id; if (!mo.soon && !pg.soon && SBW.can(id)) { out = id; return true; } return false; }); });
    return out;
  };
  SBW.setPerms = function (rows, catalogue) {
    var P = {}, K = {};
    (rows || []).forEach(function (r) { P[r.resource_id] = Number(r.level) || 0; });
    (catalogue || []).forEach(function (r) { K[r.id] = 1; });
    SBW.perms = P; SBW.known = K;
  };

  // ---------- session ----------
  function now() { return Date.now(); }
  function lsGet() { try { return JSON.parse(localStorage.getItem(C.ls)); } catch (e) { return null; } }
  function lsSet(s) { try { if (s) localStorage.setItem(C.ls, JSON.stringify(s)); else localStorage.removeItem(C.ls); } catch (e) { } }
  function keep(tok, t0) {
    var s = { at: tok.access_token, rt: tok.refresh_token, exp: now() + (Number(tok.expires_in) || 3600) * 1000, uid: tok.user && tok.user.id, email: tok.user && tok.user.email, t0: t0 || now() };
    lsSet(s); return s;
  }
  var VI = [
    [/invalid login credentials/i, 'Sai email hoặc mật khẩu.'],
    [/email not confirmed/i, 'Email chưa được xác nhận. Liên hệ quản trị.'],
    [/rate limit|too many|security purposes/i, 'Thử quá nhiều lần. Đợi vài phút rồi thử lại.'],
    [/should be different/i, 'Mật khẩu mới phải khác mật khẩu cũ.'],
    [/weak|at least|characters/i, 'Mật khẩu quá yếu: tối thiểu ' + C.minPw + ' ký tự, nên có chữ hoa, chữ thường và số.'],
    [/expired|invalid.*(token|jwt)|refresh token/i, 'Phiên đăng nhập đã hết hạn. Đăng nhập lại.'],
    [/failed to fetch|network/i, 'Không kết nối được máy chủ. Kiểm tra mạng rồi thử lại.']
  ];
  function viMsg(m) { m = String(m || ''); for (var i = 0; i < VI.length; i++) if (VI[i][0].test(m)) return VI[i][1]; return m || 'Lỗi không rõ.'; }
  SBW.viMsg = viMsg;
  function err(m, code) { var e = new Error(viMsg(m)); e.code = code; return e; }

  function http(method, path, body, token, extra) {
    var h = { apikey: C.key, 'Content-Type': 'application/json' };
    if (token) h.Authorization = 'Bearer ' + token;
    Object.keys(extra || {}).forEach(function (k) { h[k] = extra[k]; });
    return fetch(C.url + path, { method: method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit' })
      .catch(function (e) { throw err(e && e.message); })
      .then(function (r) {
        return r.text().then(function (t) {
          var j = null; try { j = t ? JSON.parse(t) : null; } catch (e) { }
          if (!r.ok) throw err((j && (j.msg || j.message || j.error_description || j.error)) || ('HTTP ' + r.status), r.status);
          return j;
        });
      });
  }
  SBW.http = http;

  function signIn(email, pw) {
    return http('POST', '/auth/v1/token?grant_type=password', { email: String(email).trim().toLowerCase(), password: pw }).then(function (t) { return keep(t); });
  }
  var refreshing = null;
  function refresh(s) {
    if (!refreshing) refreshing = http('POST', '/auth/v1/token?grant_type=refresh_token', { refresh_token: s.rt })
      .then(function (t) { refreshing = null; return keep(t, s.t0); }, function (e) { refreshing = null; throw e; });
    return refreshing;
  }
  /** Valid session or a rejected promise (code 'auth'). */
  function session() {
    var s = lsGet();
    if (!s || !s.rt) return Promise.reject(err('Chưa đăng nhập.', 'auth'));
    if (now() - (s.t0 || 0) > C.maxAgeMs) { signOutLocal(); return Promise.reject(err('Phiên làm việc đã quá 8 giờ. Đăng nhập lại.', 'auth')); }
    if (s.exp - now() > 60000) return Promise.resolve(s);
    return refresh(s).catch(function (e) { if (e.code === 400 || e.code === 401) { signOutLocal(); e.code = 'auth'; } throw e; });
  }
  SBW.session = session;
  /** Authenticated call; one retry after a refresh on 401. */
  function api(method, path, body, extra) {
    return session().then(function (s) {
      return http(method, path, body, s.at, extra).catch(function (e) {
        if (e.code !== 401) throw e;
        return refresh(s).then(function (s2) { return http(method, path, body, s2.at, extra); });
      });
    });
  }
  SBW.api = api;

  function wipeData() {
    try { indexedDB.deleteDatabase('pvt_web'); } catch (e) { }
    try { localStorage.removeItem('pvt_chat'); } catch (e) { }
    packCache = {};
  }
  function signOutLocal() { lsSet(null); wipeData(); }
  SBW.signOut = function () {
    var s = lsGet();
    var p = s && s.at ? http('POST', '/auth/v1/logout', {}, s.at).catch(function () { }) : Promise.resolve();
    return p.then(function () { signOutLocal(); location.replace(location.pathname); });
  };

  // ---------- data packs ----------
  var packCache = {};   // name -> {ver, obj}
  function b64gunzip(b64) {
    return fetch('data:application/octet-stream;base64,' + b64).then(function (r) { return r.arrayBuffer(); })
      .then(function (buf) { return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).text(); })
      .then(JSON.parse);
  }
  function gzipB64(obj) {
    return new Response(new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream('gzip'))).blob()
      .then(function (b) { return new Promise(function (ok, no) { var fr = new FileReader(); fr.onload = function () { ok(String(fr.result).split(',')[1]); }; fr.onerror = function () { no(fr.error); }; fr.readAsDataURL(b); }); });
  }
  function packVers(names) {
    return api('GET', '/rest/v1/packs?select=pack,ver&pack=in.(' + names.join(',') + ')').then(function (rows) {
      var m = {}; (rows || []).forEach(function (r) { m[r.pack] = r.ver; }); return m;
    });
  }
  /** {name: obj} for the packs this user may read among `names` (cached by version). */
  function getPacks(names) {
    return packVers(names).then(function (vers) {
      var need = Object.keys(vers).filter(function (n) { return !packCache[n] || packCache[n].ver !== vers[n]; });
      var load = need.length ? api('GET', '/rest/v1/packs?select=pack,ver,data&pack=in.(' + need.join(',') + ')') : Promise.resolve([]);
      return load.then(function (rows) {
        return Promise.all((rows || []).map(function (r) { return b64gunzip(r.data).then(function (o) { packCache[r.pack] = { ver: r.ver, obj: o }; }); }));
      }).then(function () {
        var out = {}; Object.keys(vers).forEach(function (n) { if (packCache[n]) out[n] = packCache[n].obj; }); return out;
      });
    });
  }
  function verOf(vers) { return Object.keys(vers).sort().map(function (k) { return k + ':' + vers[k]; }).join(','); }
  function emptyPack() {
    var e = function (ks) { var o = {}; ks.forEach(function (k) { o[k] = []; }); return o; };
    return packMerge({ kt: { v: '', today: new Date().toISOString().slice(0, 10), src: '', dict: {}, cfg: {}, sc: e(['cn', 'loai', 'pb', 'ma', 'cp', 'n']), sct: e(['pt', 'hk', 'y', 'loai', 'pb', 'ma', 'm']), vt: e(['tra', 'end', 'f', 'dt', 'dau', 'vetc', 'luong', 'khac', 'tk', 'upc', 'n']) } });
  }

  var LATER = 'Chức năng này (ghi, duyệt, gọi máy chủ) sẽ có ở bước tiếp theo. Hiện bản web chỉ để xem.';
  var H = {
    webPackVersion: function () {
      return packVers(['vt', 'kt']).then(function (v) { return { v: verOf(v) || 'none', ai: false, tc: SBW.can('pkte/cn') }; });
    },
    webGetPack: function () {
      return getPacks(['vt', 'kt']).then(function (p) {
        var P = packMerge(p) || emptyPack(), v = verOf(Object.keys(p).reduce(function (o, k) { o[k] = packCache[k].ver; return o; }, {})) || 'none';
        return gzipB64(P).then(function (b64) { return { v: v, b64: b64 }; });
      });
    },
    webHqvtPack: function () {
      return getPacks(['hqvt']).then(function (p) {
        if (!p.hqvt) throw err('Không có quyền xem dữ liệu Hiệu quả VT.');
        return Object.assign({}, p.hqvt, { canEdit: false, canApprove: false, role: 'xem', me: SBW.user && SBW.user.email, url: '' });
      });
    },
    webTcktPack: function () {
      return getPacks(['tckt']).then(function (p) {
        if (!p.tckt) throw err('Không có quyền xem dữ liệu Kế toán.');
        return Object.assign({}, p.tckt, { canEdit: false });
      });
    },
    webCfgGet: function () { return Promise.resolve({ can: false, msg: LATER }); },
    webAiStatus: function () { return Promise.resolve([]); }
  };
  SBW.handlers = H;
  function call(name, args) {
    var f = H[name];
    if (!f) return Promise.reject(err(LATER));
    return Promise.resolve().then(function () { return f.apply(null, args); }).catch(function (e) {
      if (e && e.code === 'auth') { showLogin(e.message); }
      throw e;
    });
  }
  SBW.call = call;

  // ---------- google.script shim (Index.html / HqvtUi.html stay unchanged) ----------
  function runner(ok, no) {
    return new Proxy({}, {
      get: function (_, name) {
        if (name === 'withSuccessHandler') return function (f) { return runner(f, no); };
        if (name === 'withFailureHandler') return function (f) { return runner(ok, f); };
        if (name === 'withUserObject') return function () { return runner(ok, no); };
        return function () {
          var a = Array.prototype.slice.call(arguments);
          call(String(name), a).then(function (r) { if (ok) ok(r); }, function (e) { if (no) no(e); });
        };
      }
    });
  }
  window.google = window.google || {};
  window.google.script = {
    get run() { return runner(null, null); },
    url: { getLocation: function (cb) { cb({ hash: String(location.hash || '').replace(/^#/, ''), parameter: {}, parameters: {} }); } }
  };

  // ---------- login UI ----------
  var CSS = '#sbw{position:fixed;inset:0;z-index:9999;background:var(--bg,#F2F5F7);display:flex;align-items:center;justify-content:center;padding:16px;font-family:"Be Vietnam Pro",system-ui,sans-serif;color:var(--ink,#22303C)}' +
    '#sbw .sbw-box{width:100%;max-width:380px;background:var(--card,#fff);border:1px solid var(--line,#DFE5EA);border-radius:12px;padding:28px 24px;box-shadow:0 6px 24px rgba(20,30,40,.08)}' +
    '#sbw h1{font-size:19px;margin:0 0 4px}#sbw p.sbw-s{margin:0 0 18px;color:var(--sub,#66737F);font-size:13.5px}' +
    '#sbw label{display:block;font-size:13px;font-weight:600;margin:12px 0 5px}#sbw input{width:100%;box-sizing:border-box;padding:10px 12px;font:inherit;font-size:15px;border:1px solid var(--line,#DFE5EA);border-radius:8px;background:var(--card,#fff);color:inherit}' +
    '#sbw input:focus{outline:2px solid var(--pri,#2E6E8E);outline-offset:0}#sbw button.sbw-go{width:100%;margin-top:18px;padding:11px;font:inherit;font-weight:600;font-size:15px;border:0;border-radius:8px;background:var(--pri2,#2E6E8E);color:#fff;cursor:pointer}' +
    '#sbw button.sbw-go:disabled{opacity:.6;cursor:default}#sbw .sbw-lk{background:none;border:0;padding:0;margin-top:14px;color:var(--pri,#2E6E8E);font:inherit;font-size:13.5px;cursor:pointer;text-decoration:underline}' +
    '#sbw .sbw-msg{margin-top:14px;font-size:13.5px;min-height:1em}#sbw .sbw-msg.bad{color:var(--neg,#C2453A)}#sbw .sbw-msg.ok{color:var(--pos,#2F8A5B)}' +
    '#sbw .sbw-brand{font-weight:700;color:var(--brand,#2E6E8E);font-size:13px;letter-spacing:.04em;margin-bottom:14px}' +
    '.sbw-me{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--sub,#66737F);max-width:40vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}';
  function esc(s) { return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function box() {
    var el = document.getElementById('sbw');
    if (!el) {
      var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
      el = document.createElement('div'); el.id = 'sbw'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-modal', 'true'); document.body.appendChild(el);
    }
    el.style.display = 'flex';
    return el;
  }
  function hideBox() { var el = document.getElementById('sbw'); if (el) el.remove(); }
  function form(el, html, onSubmit) {
    el.innerHTML = '<form class="sbw-box" novalidate><div class="sbw-brand">XNK LOGISTICS · BÁO CÁO VẬN HÀNH</div>' + html + '<div class="sbw-msg" role="status" aria-live="polite"></div></form>';
    var f = el.querySelector('form'), m = f.querySelector('.sbw-msg'), b = f.querySelector('button.sbw-go');
    function say(t, ok) { m.textContent = t || ''; m.className = 'sbw-msg' + (t ? (ok ? ' ok' : ' bad') : ''); }
    f.onsubmit = function (ev) {
      ev.preventDefault(); say(''); b.disabled = true;
      Promise.resolve().then(function () { return onSubmit(f, say); }).catch(function (e) { say((e && e.message) || String(e)); }).then(function () { b.disabled = false; });
    };
    var first = f.querySelector('input'); if (first) setTimeout(function () { first.focus(); }, 30);
    return { f: f, say: say };
  }

  function showLogin(note) {
    var el = box();
    var x = form(el, '<h1>Đăng nhập</h1><p class="sbw-s">Dùng email công ty và mật khẩu được cấp.</p>' +
      '<label for="sbwE">Email</label><input id="sbwE" type="email" autocomplete="username" required>' +
      '<label for="sbwP">Mật khẩu</label><input id="sbwP" type="password" autocomplete="current-password" required>' +
      '<button class="sbw-go" type="submit">Đăng nhập</button><button class="sbw-lk" type="button" id="sbwF">Quên mật khẩu?</button>',
      function (f) {
        var e = f.sbwE.value.trim(), p = f.sbwP.value;
        if (!e || !p) throw err('Nhập email và mật khẩu.');
        wipeData();   // never show a previous user's cached data
        return signIn(e, p).then(afterLogin);
      });
    if (note) x.say(note);
    el.querySelector('#sbwF').onclick = function () { showForgot(el.querySelector('#sbwE').value); };
  }

  function showForgot(email) {
    var el = box();
    var x = form(el, '<h1>Quên mật khẩu</h1><p class="sbw-s">Nhập email đăng nhập. Nếu email có trong hệ thống, bạn sẽ nhận thư có liên kết đặt lại mật khẩu (kiểm tra cả thư rác).</p>' +
      '<label for="sbwE">Email</label><input id="sbwE" type="email" autocomplete="username" required value="' + esc(email || '') + '">' +
      '<button class="sbw-go" type="submit">Gửi thư đặt lại</button><button class="sbw-lk" type="button" id="sbwB">‹ Quay lại đăng nhập</button>',
      function (f, say) {
        var e = f.sbwE.value.trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) throw err('Email không hợp lệ.');
        var to = location.origin + location.pathname;
        return http('POST', '/auth/v1/recover?redirect_to=' + encodeURIComponent(to), { email: e })
          .then(function () { say('Đã gửi. Mở thư và bấm liên kết trong vòng 1 giờ.', true); });
      });
    el.querySelector('#sbwB').onclick = function () { showLogin(); };
    return x;
  }

  function pwCheck(a, b) {
    if (a.length < C.minPw) throw err('Mật khẩu tối thiểu ' + C.minPw + ' ký tự.');
    if (!/[a-z]/.test(a) || !/[A-Z]/.test(a) || !/[0-9]/.test(a)) throw err('Mật khẩu cần có chữ thường, chữ hoa và số.');
    if (a !== b) throw err('Hai lần nhập mật khẩu không khớp.');
  }
  SBW.pwCheck = pwCheck;
  function showSetPw(title, why) {
    var el = box();
    form(el, '<h1>' + esc(title) + '</h1><p class="sbw-s">' + esc(why) + '</p>' +
      '<label for="sbwP">Mật khẩu mới</label><input id="sbwP" type="password" autocomplete="new-password" required>' +
      '<label for="sbwP2">Nhập lại</label><input id="sbwP2" type="password" autocomplete="new-password" required>' +
      '<p class="sbw-s" style="margin:8px 0 0">Tối thiểu ' + C.minPw + ' ký tự, có chữ hoa, chữ thường và số.</p>' +
      '<button class="sbw-go" type="submit">Lưu mật khẩu</button><button class="sbw-lk" type="button" id="sbwO">Đăng xuất</button>',
      function (f, say) {
        var a = f.sbwP.value, b = f.sbwP2.value; pwCheck(a, b);
        return api('PUT', '/auth/v1/user', { password: a }).then(function () {
          say('Đã đổi mật khẩu.', true);
          return afterLogin();
        });
      });
    el.querySelector('#sbwO').onclick = function () { SBW.signOut(); };
  }
  SBW.changePassword = function () { showSetPw('Đổi mật khẩu', 'Đặt mật khẩu mới cho tài khoản ' + ((SBW.user && SBW.user.email) || '') + '.'); };

  /** After a session exists: profile → must change pw? → permissions → start the app. */
  var booted = false;
  function afterLogin() {
    return session().then(function (s) {
      SBW.user = { id: s.uid, email: s.email };
      return Promise.all([
        api('GET', '/rest/v1/profiles?select=full_name,is_active,must_change_pw,is_admin&user_id=eq.' + encodeURIComponent(s.uid)),
        api('POST', '/rest/v1/rpc/my_permissions', {}),
        api('GET', '/rest/v1/resources?select=id')
      ]);
    }).then(function (r) {
      var pr = (r[0] || [])[0];
      if (!pr || !pr.is_active) { signOutLocal(); throw err('Tài khoản đã bị khoá hoặc chưa được kích hoạt. Liên hệ quản trị.'); }
      SBW.profile = pr; SBW.setPerms(r[1], r[2]);
      if (pr.must_change_pw) { showSetPw('Đặt mật khẩu mới', 'Lần đầu đăng nhập (hoặc vừa được đặt lại mật khẩu): hãy đặt mật khẩu riêng của bạn.'); return; }
      hideBox(); start();
    });
  }
  function userBar() {
    var top = document.querySelector('header.top'), rl = document.getElementById('reload');
    if (!top || document.getElementById('sbwMe')) return;
    var me = document.createElement('span'); me.className = 'sbw-me'; me.id = 'sbwMe';
    me.title = (SBW.user && SBW.user.email) || ''; me.textContent = (SBW.profile && SBW.profile.full_name) || (SBW.user && SBW.user.email) || '';
    var pw = document.createElement('button'); pw.className = 'btn'; pw.type = 'button'; pw.textContent = 'Đổi mật khẩu'; pw.onclick = SBW.changePassword;
    var out = document.createElement('button'); out.className = 'btn'; out.type = 'button'; out.textContent = 'Đăng xuất'; out.onclick = SBW.signOut;
    var at = rl && rl.parentNode === top ? rl.nextSibling : null;
    [me, pw, out].forEach(function (n) { top.insertBefore(n, at); });
  }
  function start() {
    userBar();
    if (booted) { if (typeof buildNav === 'function') buildNav(); if (typeof render === 'function') render(); return; }
    booted = true;
    if (typeof pvtInit === 'function') pvtInit();
  }

  /** Recovery link lands here as #access_token=…&refresh_token=…&type=recovery (or #error=…). */
  function fromHash() {
    var h = String(location.hash || '').replace(/^#/, '');
    if (!/access_token=|error=/.test(h)) return null;
    var q = {}; h.split('&').forEach(function (kv) { var i = kv.indexOf('='); if (i > 0) q[decodeURIComponent(kv.slice(0, i))] = decodeURIComponent(kv.slice(i + 1).replace(/\+/g, ' ')); });
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { }
    return q;
  }
  SBW.fromHash = fromHash;

  function boot() {
    var q = fromHash();
    if (q && q.error) { showLogin(/expired/i.test(q.error_description || '') ? 'Liên kết đặt lại đã hết hạn. Gửi lại thư mới.' : viMsg(q.error_description || q.error)); return; }
    if (q && q.access_token && q.refresh_token) {
      wipeData();
      keep({ access_token: q.access_token, refresh_token: q.refresh_token, expires_in: q.expires_in, user: null });
      http('GET', '/auth/v1/user', undefined, q.access_token).then(function (u) {
        var s = lsGet(); s.uid = u.id; s.email = u.email; lsSet(s);
        SBW.user = { id: u.id, email: u.email };
        if (q.type === 'recovery' || q.type === 'invite') showSetPw('Đặt lại mật khẩu', 'Đặt mật khẩu mới cho ' + u.email + '.');
        else return afterLogin();
      }).catch(function (e) { signOutLocal(); showLogin(e.message); });
      return;
    }
    if (!lsGet()) { showLogin(); return; }
    afterLogin().catch(function (e) { showLogin(e.message); });
  }
  SBW.boot = boot;
  if (!window.SBW_NO_BOOT) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else setTimeout(boot, 0);
  }
})();

/* packMerge — copied from src/PackSplit.gs by tools/build-web.js */
var PACKSPLIT = { VER: 1 };
/* <packsplit> */
function packSplit_(P) {
  var d = P.dict || {};
  function groupBy(src, keys, sums) {
    var ix = {}, out = { n: [] }, len = src[keys[0]].length;
    keys.concat(sums).forEach(function (k) { out[k] = []; });
    for (var i = 0; i < len; i++) {
      var key = keys.map(function (k) { var v = src[k][i]; return v === null || v === undefined ? '' : v; }).join('|'), j = ix[key];
      if (j === undefined) {
        j = ix[key] = out.n.length; out.n.push(0);
        keys.forEach(function (k) { out[k].push(src[k][i] === undefined ? null : src[k][i]); });
        sums.forEach(function (k) { out[k].push(0); });
      }
      out.n[j]++;
      sums.forEach(function (k) { out[k][j] = Math.round((out[k][j] + (+src[k][i] || 0)) * 100) / 100; });
    }
    return out;
  }
  var head = { v: P.v, today: P.today, src: P.src, split: PACKSPLIT.VER };
  var vt = Object.assign({ part: 'vt' }, head, {
    dict: { xe: d.xe, xeInfo: d.xeInfo, lai: d.lai, route: d.route, loai: d.loai, ma: d.ma, ty: d.ty },
    vt: P.vt, vg: P.vg, cfg: P.cfg,
    sc: groupBy(P.sc, ['cn', 'loai', 'pb', 'ma'], ['cp'])
  });
  var kt = Object.assign({ part: 'kt' }, head, {
    dict: { loai: d.loai, ma: d.ma, pt: d.pt, ht: d.ht, ptInfo: d.ptInfo, ptList: d.ptList, hk: d.hk, htList: d.htList },
    sc: P.sc, sct: P.sct, cfg: P.cfg,
    vt: groupBy(P.vt, ['tra', 'end', 'f'], ['dt', 'dau', 'vetc', 'luong', 'khac', 'tk', 'upc'])
  });
  return { vt: vt, kt: kt };
}

/** Browser: merge the packs the user may read ({vt?, kt?}) into one object shaped like webBuildPack_. Full data wins over sums. */
function packMerge(parts) {
  var vt = parts && parts.vt, kt = parts && parts.kt, base = vt || kt;
  if (!base) return null;
  var dict = {};
  [kt, vt].forEach(function (p) { if (p) Object.keys(p.dict || {}).forEach(function (k) { dict[k] = p.dict[k]; }); });
  ['xe', 'xeInfo', 'lai', 'route', 'ty', 'pt', 'ht', 'ma', 'loai', 'hk', 'htList', 'ptList'].forEach(function (k) { if (!dict[k]) dict[k] = []; });
  if (!dict.ptInfo) dict.ptInfo = {};
  var empty = function (keys) { var o = {}; keys.forEach(function (k) { o[k] = []; }); return o; };
  return {
    v: base.v, today: base.today, src: base.src, dict: dict, cfg: base.cfg,
    parts: { vt: !!vt, kt: !!kt },
    vt: vt ? vt.vt : kt.vt,
    vg: vt ? vt.vg : empty(['xe', 'lai', 'ty', 'bd', 'end', 'dCK', 'dHD', 'f', 'dtd', 'cfd', 'dtv', 'cfv', 'row', 'dDi', 'dVe', 'note']),
    sc: kt ? kt.sc : vt.sc,
    sct: kt ? kt.sct : empty(['pt', 'hk', 'y', 'loai', 'pb', 'ma', 'm'])
  };
}
/* </packsplit> */
