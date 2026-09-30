/* 중개사 교재 — 폰 읽기 앱 */
(() => {
  'use strict';

  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const app = $('#app');

  const store = {
    get(k, d) {
      try { const v = localStorage.getItem('jk.' + k); return v == null ? d : JSON.parse(v); } catch { return d; }
    },
    set(k, v) {
      try { localStorage.setItem('jk.' + k, JSON.stringify(v)); } catch { /* 저장 불가 — 무시 */ }
    },
  };

  const ICON = {
    back: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>',
    list: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="18" r="1.2" fill="currentColor" stroke="none"/></svg>',
    more: '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg>',
    search: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>',
    chev: '<svg class="chev" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
  };

  let LIB = null;
  let CH = {};
  let ORDER = [];
  let SEARCH = null;
  let libLoadedAt = 0;
  let cleanup = () => {};
  let homeScroll = 0;
  let prevRoute = '';
  let curRoute = '';
  let navDepth = -1;

  // ------------------------------------------------------------ 데이터 접근
  // 서버 모드(메인PC server.py) / 정적 모드(GitHub Pages — 교재 파일은 AES-GCM 암호화, 이름은 HMAC으로 가림)
  const STATIC = !!window.JK_STATIC;
  const pageFile = (n) => `${String(n).padStart(3, '0')}.webp`;
  const te = new TextEncoder();
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  const b64 = (u8) => btoa(String.fromCharCode(...u8));
  const unb64 = (s) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
  const Data = {
    key: null,
    urls: new Map(),
    logical(c, file) {
      return file === 'reflow.json' || /^r\d+_/.test(file) ? `${c.key}/${c.rv}/${file}` : `${c.key}/${file}`;
    },
    async name(logical) {
      return hex(await crypto.subtle.sign('HMAC', this.key.mac, te.encode(logical))).slice(0, 24);
    },
    async bin(name, fresh) {
      const r = await fetch(`d/${name}.bin`, fresh ? { cache: 'no-cache' } : {});
      if (!r.ok) throw new Error('data ' + r.status);
      const b = new Uint8Array(await r.arrayBuffer());
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, this.key.enc, b.slice(12));
    },
    async json(name, fresh) {
      return JSON.parse(new TextDecoder().decode(await this.bin(name, fresh)));
    },
    async library() {
      if (STATIC) return this.json('lib', true);
      const r = await fetch('/api/library', { cache: 'no-cache' });
      if (r.status === 401) { location.replace('/'); throw new Error('auth'); }
      if (!r.ok) throw new Error('library ' + r.status);
      return r.json();
    },
    async search() {
      if (STATIC) return this.json('search', true);
      const r = await fetch('/api/search', { cache: 'no-cache' });
      if (!r.ok) throw new Error('search ' + r.status);
      return r.json();
    },
    async reflow(c) {
      if (STATIC) return this.json(await this.name(this.logical(c, 'reflow.json')));
      const r = await fetch(`/img/${c.id}/${c.key}/reflow.json`);
      if (!r.ok) throw new Error('reflow ' + r.status);
      return r.json();
    },
    async url(c, file) { // 오프라인 저장용 실제 주소
      return STATIC ? `d/${await this.name(this.logical(c, file))}.bin` : `/img/${c.id}/${c.key}/${file}`;
    },
    async img(c, file) { // <img>에 넣을 주소
      if (!STATIC) return `/img/${c.id}/${c.key}/${file}`;
      const lk = this.logical(c, file);
      if (!this.urls.has(lk)) {
        this.urls.set(lk, (async () => {
          const buf = await this.bin(await this.name(lk));
          return URL.createObjectURL(new Blob([buf], { type: 'image/webp' }));
        })());
      }
      try { return await this.urls.get(lk); } catch (e) { this.urls.delete(lk); throw e; }
    },
    pdf(c) { return STATIC ? null : `/pdf/${c.id}`; },
  };

  // 열쇠: 암호문 → PBKDF2(SHA-256, config.json의 salt·iter) → 64바이트(앞 32 = AES, 뒤 32 = HMAC)
  async function deriveBits(pass) {
    const cfg = await (await fetch('config.json', { cache: 'no-cache' })).json();
    const norm = String(pass).toLowerCase().replace(/[^a-z0-9]/g, '');
    const base = await crypto.subtle.importKey('raw', te.encode(norm), 'PBKDF2', false, ['deriveBits']);
    const salt = Uint8Array.from(cfg.salt.match(/../g), (h) => parseInt(h, 16));
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: cfg.iter }, base, 512));
  }
  async function useBits(bits) {
    Data.key = {
      enc: await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['decrypt']),
      mac: await crypto.subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    };
  }

  // 화면 안의 <img data-img="파일"> 채우기. 정적 모드는 화면 가까이 올 때 복호화.
  function hydrate(root, c, scrollRoot) {
    const imgs = $$('img[data-img]', root);
    if (!STATIC) {
      imgs.forEach((im) => { im.src = `/img/${c.id}/${c.key}/${im.dataset.img}`; });
      return () => {};
    }
    const load = (im) => Data.img(c, im.dataset.img).then((u) => { im.src = u; }).catch(() => { im.alt = '그림을 불러오지 못했어'; });
    if (!('IntersectionObserver' in window)) { imgs.forEach(load); return () => {}; }
    const io = new IntersectionObserver((ents) => {
      for (const e of ents) if (e.isIntersecting) { io.unobserve(e.target); load(e.target); }
    }, { root: scrollRoot || null, rootMargin: '1500px 0px' });
    imgs.forEach((im) => io.observe(im));
    return () => io.disconnect();
  }
  const secTitle = (t) => (t || '').replace(/\s*\(계속\)\s*$/, '');

  function fmtDate(sec) {
    const d = new Date(sec * 1000);
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const day = new Date(d); day.setHours(0, 0, 0, 0);
    const diff = Math.round((today - day) / 86400000);
    const hm = `${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
    if (diff === 0) return `오늘 ${hm}`;
    if (diff === 1) return `어제 ${hm}`;
    return `${d.getMonth() + 1}/${d.getDate()}`;
  }

  let toastTimer = 0;
  function toast(msg, ms = 2600) {
    const t = $('#toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, ms);
  }

  // ------------------------------------------------------------ 데이터
  async function loadLibrary(force) {
    if (LIB && !force && Date.now() - libLoadedAt < 30000) return;
    const lib = await Data.library();
    const changed = !LIB || lib.generated !== LIB.generated;
    LIB = lib;
    libLoadedAt = Date.now();
    CH = {};
    ORDER = [];
    for (const s of LIB.subjects) {
      for (const c of s.chapters) { c.subject = s; CH[c.id] = c; ORDER.push(c); }
    }
    let seen = store.get('seen', null);
    if (!seen) {
      seen = {};
      for (const id in CH) seen[id] = CH[id].key;
      store.set('seen', seen);
    }
    if (changed) SEARCH = null;
    return changed;
  }

  // ------------------------------------------------------------ 라우팅
  function parseHash() {
    const h = (location.hash || '#/').slice(1);
    const [path, qs] = h.split('?');
    return { parts: path.split('/').filter(Boolean), params: new URLSearchParams(qs || '') };
  }

  async function route() {
    const { parts, params } = parseHash();
    closeSheet();
    navDepth = parts.length ? navDepth + 1 : 0;
    prevRoute = curRoute;
    curRoute = parts[0] || '';
    if (prevRoute === '' && curRoute !== '') homeScroll = window.scrollY;
    try { await loadLibrary(); } catch (e) {
      if (STATIC && e && e.name === 'OperationError') { store.set('kb', null); return showKeyScreen('열쇠가 바뀌었어. 새 열쇠를 넣어 줘.'); }
      if (!LIB) { app.innerHTML = `<div class="home"><p class="muted">교재 목록을 불러오지 못했어.<br>${STATIC ? '인터넷 연결을 확인해 줘.' : '서버(메인PC)가 켜져 있는지 확인해 줘.'}</p></div>`; return; }
    }
    if (parts[0] === 'r' && CH[parts[1]]) return showReader(CH[parts[1]], parseInt(params.get('p'), 10) || null, params.get('q'));
    if (parts[0] === 's') return showSearch(params.get('q') || '');
    return showHome();
  }

  function go(hash) { location.hash = hash; }
  // 앱 안에서 이동해 온 경우만 history.back — 링크로 바로 들어왔으면 목록으로.
  function back() { if (navDepth > 0) history.back(); else location.replace('#/'); }

  // ------------------------------------------------------------ 홈
  function showHome() {
    cleanup(); cleanup = () => {};
    document.body.classList.remove('chrome-hidden');
    document.title = '중개사 교재';
    const prog = store.get('progress', {});
    const seen = store.get('seen', {});
    const collapsed = store.get('collapsed', {});
    const last = store.get('last', null);

    const exam = new Date(LIB.exam_date + 'T00:00:00');
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const d = Math.round((exam - today) / 86400000);
    const dtxt = d > 0 ? `D-${d}` : d === 0 ? 'D-DAY' : `D+${-d}`;
    const wk = '일월화수목금토'[exam.getDay()];

    let h = `<div class="home">
      <div class="home-head">
        <div><h1>중개사 교재</h1><div class="sub">제37회 · ${exam.getMonth() + 1}월 ${exam.getDate()}일(${wk}) · 교재 ${ORDER.length}개 장</div></div>
        <div class="dday"><b>${dtxt}</b><span>시험까지</span></div>
      </div>
      <button class="searchbar" data-go="#/s">${ICON.search}<span>교재 전체에서 찾기</span></button>`;
    if (STATIC && keyJustSet && /^#k=/.test(location.hash)) {
      h += `<div class="keytip"><b>열쇠를 이 기기에 저장했어.</b> 아이폰이면 <b>지금 이 화면에서</b> 공유(□↑) → ‘홈 화면에 추가’를 눌러 줘. 이 화면에서 추가해야 홈 화면 앱에도 열쇠가 들어가.</div>`;
    }

    if (last && CH[last] && prog[last]) {
      const c = CH[last], pr = prog[last];
      const p = clamp(pr.p || 1, 1, c.pages);
      const sec = secTitle(nearestTitle(c, p));
      h += `<a class="continue" href="#/r/${c.id}">
        <div class="eyebrow">이어 읽기</div>
        <div class="t">${esc(c.label)} ${esc(c.title)}</div>
        <div class="s">${esc(c.subject.name)} · ${p}/${c.pages}쪽${sec ? ' · ' + esc(sec) : ''}</div>
        <div class="bar"><i style="width:${Math.round((p / c.pages) * 100)}%"></i></div>
        <span class="go">계속 ›</span></a>`;
    }

    const recent = ORDER.filter((c) => Date.now() / 1000 - c.mtime < 3 * 86400).sort((a, b) => b.mtime - a.mtime).slice(0, 10);
    if (recent.length) {
      h += `<div class="section-title">최근 3일 새로 나오거나 고친 장</div><div class="recent">`;
      for (const c of recent) {
        const badge = badgeFor(c, seen);
        h += `<a class="chip" href="#/r/${c.id}"><b>${esc(shortSubject(c.subject))} ${esc(c.label)} ${esc(c.title)}</b><span>${esc(c.version)} · ${fmtDate(c.mtime)}${badge ? ' · ' + badge.replace(/<[^>]+>/g, '') : ''}</span></a>`;
      }
      h += `</div>`;
    }

    h += `<div class="section-title">과목</div>`;
    for (const s of LIB.subjects) {
      const pend = (LIB.pending || []).filter((p) => p.subject === s.key);
      if (!s.chapters.length && !pend.length) continue;
      const pages = s.chapters.reduce((a, c) => a + c.pages, 0);
      h += `<section class="subject${collapsed[s.key] ? ' closed' : ''}" data-s="${s.key}">
        <button class="subject-head" data-toggle="${s.key}"><span class="name">${esc(s.name)}</span><span class="meta">${s.chapters.length}개 장 · ${pages}쪽</span>${ICON.chev}</button>
        <div class="chapters">`;
      for (const c of s.chapters) {
        const pr = prog[c.id];
        let right = '';
        if (pr) {
          const m = clamp(pr.m || pr.p || 1, 1, c.pages);
          right = m >= c.pages ? `<div class="pct done">완독</div>` : `<div class="pct">${Math.round((m / c.pages) * 100)}%</div><div>${pr.p}쪽</div>`;
        }
        h += `<a class="ch" href="#/r/${c.id}">
          <span class="no">${esc(c.label)}</span>
          <span class="t">${esc(c.title)}${badgeFor(c, seen)}</span>
          <span class="s">${c.subtitle ? esc(c.subtitle) + ' · ' : ''}${c.pages}쪽 · ${esc(c.version)} · ${fmtDate(c.mtime)}</span>
          <span class="right">${right}</span></a>`;
      }
      for (const p of pend) {
        h += `<div class="ch pending"><span class="no">${esc(p.label)}</span><span class="t">준비 중</span><span class="s">페이지 이미지를 만드는 중이야</span><span class="right"></span></div>`;
      }
      h += `</div></section>`;
    }
    h += `<div class="foot">목록 갱신 ${fmtDate(LIB.generated)} · ${STATIC ? '새 판은 메인PC에서 올리면 반영돼' : '새 판은 몇 분 안에 자동 반영돼'}<br><button data-act="settings">설정</button></div></div>`;
    app.innerHTML = h;
    requestAnimationFrame(() => window.scrollTo(0, homeScroll));

    app.onclick = (e) => {
      const g = e.target.closest('[data-go]');
      if (g) { go(g.dataset.go); return; }
      const t = e.target.closest('[data-toggle]');
      if (t) {
        const k = t.dataset.toggle;
        const col = store.get('collapsed', {});
        col[k] = !col[k];
        store.set('collapsed', col);
        t.parentElement.classList.toggle('closed', col[k]);
        return;
      }
      if (e.target.closest('[data-act=settings]')) openSettings();
    };
  }

  function shortSubject(s) {
    return { intro: '학개론', civil: '민법', agent: '중개사법', public: '공법', registry: '공시법', tax: '세법' }[s.key] || s.name;
  }

  function badgeFor(c, seen) {
    if (!(c.id in seen)) return '<span class="badge">새 장</span>';
    if (seen[c.id] !== c.key) return '<span class="badge">새 판</span>';
    return '';
  }

  function nearestTitle(c, p) {
    for (let i = p - 1; i >= 0; i--) if (c.titles[i]) return c.titles[i];
    return '';
  }

  // ------------------------------------------------------------ 리더
  // 기본 = 본문 리더(폰에 맞춰 다시 흘린 글). 본문이 없는 장이거나 '원본 쪽'을 고르면 쪽 그림 리더.
  function showReader(c, startPage, q) {
    if (c.reflow && store.get('mode', 'reflow') === 'reflow') return showReflow(c, startPage, q);
    return showPages(c, startPage, q);
  }

  function showPages(c, startPage, q) {
    cleanup();
    document.title = `${c.label} ${c.title}`;
    const prog = store.get('progress', {});
    const pr = prog[c.id];
    let p0 = clamp(startPage || (pr && pr.p) || 1, 1, c.pages);

    const seen = store.get('seen', {});
    const wasNew = seen[c.id] !== undefined && seen[c.id] !== c.key;
    seen[c.id] = c.key;
    store.set('seen', seen);
    store.set('last', c.id);

    app.innerHTML = `<div class="reader">
      <header class="topbar"><div class="topbar-in">
        <button class="iconbtn" id="btn-back" aria-label="뒤로">${ICON.back}</button>
        <div class="tb-title"><b>${esc(c.label)} ${esc(c.title)}</b><span id="sec"></span></div>
        <button class="iconbtn" id="btn-toc" aria-label="목차">${ICON.list}</button>
        <button class="iconbtn" id="btn-more" aria-label="더보기">${ICON.more}</button>
      </div></header>
      <div class="scroller" id="scroller"><div class="pages" id="pages"></div></div>
      <footer class="botbar"><div class="botbar-in">
        <div class="pgno" id="pgno"></div>
        <input type="range" id="slider" min="1" max="${c.pages}" value="${p0}" aria-label="쪽 이동">
        <button class="zoombtn" id="btn-zoom"></button>
      </div></footer></div>`;

    const pagesEl = $('#pages'), sc = $('#scroller');
    const parts = [];
    for (let i = 1; i <= c.pages; i++) {
      parts.push(`<div class="pg" data-p="${i}" style="aspect-ratio:${c.w}/${c.h}"><span class="ph">${i}</span><img alt="${i}쪽" ${Math.abs(i - p0) <= 1 ? '' : 'loading="lazy"'} decoding="async" data-img="${pageFile(i)}"></div>`);
    }
    pagesEl.innerHTML = parts.join('');
    const unhydrate = hydrate(pagesEl, c, sc);
    const pgs = $$('.pg', pagesEl);
    const pgnoEl = $('#pgno'), slider = $('#slider'), secEl = $('#sec'), zoomBtn = $('#btn-zoom');

    const ZOOMS = [1, 1.5, 2];
    let zoom = store.get('zoom', 1);
    if (!ZOOMS.includes(zoom)) zoom = 1;
    const anchorY = () => Math.min(window.innerHeight * 0.35, 260);

    function layout() {
      const base = Math.min(sc.clientWidth, 1400);
      pagesEl.style.width = Math.round(base * zoom) + 'px';
      zoomBtn.textContent = Math.round(zoom * 100) + '%';
    }

    function currentPage() {
      const y = anchorY();
      let lo = 0, hi = pgs.length - 1, ans = 0;
      while (lo <= hi) {
        const m = (lo + hi) >> 1;
        if (pgs[m].getBoundingClientRect().top <= y) { ans = m; lo = m + 1; } else hi = m - 1;
      }
      return ans + 1;
    }

    let quietUntil = 0;  // 코드가 스크롤한 직후엔 바를 숨기지 않는다(슬라이더·확대·목차 이동)
    function jumpTo(p, smooth) {
      quietUntil = Date.now() + (smooth ? 900 : 350);
      const el = pgs[clamp(p, 1, c.pages) - 1];
      const top = el.getBoundingClientRect().top - sc.getBoundingClientRect().top + sc.scrollTop - parseFloat(getComputedStyle(el).scrollMarginTop || 0);
      sc.scrollTo({ top, left: sc.scrollLeft, behavior: smooth ? 'smooth' : 'auto' });
    }

    let cur = p0, dragging = false, saveTimer = 0;
    function update() {
      const p = currentPage();
      if (p !== cur || !pgnoEl.textContent) {
        cur = p;
        pgnoEl.innerHTML = `${p} <small>/ ${c.pages}</small>`;
        if (!dragging) slider.value = p;
        secEl.textContent = secTitle(nearestTitle(c, p));
        clearTimeout(saveTimer);
        saveTimer = setTimeout(() => saveProgress(c, p), 400);
      }
    }

    let lastY = 0, ticking = false;
    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        update();
        const y = sc.scrollTop, dy = y - lastY;
        if (dragging || Date.now() < quietUntil) { lastY = y; return; }
        if (Math.abs(dy) > 24) {
          if (dy > 0 && y > 80) document.body.classList.add('chrome-hidden');
          else if (dy < 0) document.body.classList.remove('chrome-hidden');
          lastY = y;
        }
      });
    }

    function setZoom(z) {
      const p = currentPage();
      const el = pgs[p - 1];
      const r = el.getBoundingClientRect();
      const frac = (anchorY() - r.top) / r.height;
      const fracX = (sc.scrollLeft + sc.clientWidth / 2) / sc.scrollWidth;
      zoom = z;
      store.set('zoom', z);
      quietUntil = Date.now() + 350;
      layout();
      const r2 = el.getBoundingClientRect();
      sc.scrollTo(Math.max(0, fracX * sc.scrollWidth - sc.clientWidth / 2), sc.scrollTop + r2.top + frac * r2.height - anchorY());
      update();
    }

    let resizeTimer = 0;
    function onResize() {
      clearTimeout(resizeTimer);
      const p = cur;
      resizeTimer = setTimeout(() => { layout(); jumpTo(p); update(); }, 120);
    }

    function onKey(e) {
      if (e.target.closest && e.target.closest('input')) return;
      if (e.key === 'ArrowRight' || e.key === 'PageDown') { jumpTo(cur + 1); e.preventDefault(); }
      else if (e.key === 'ArrowLeft' || e.key === 'PageUp') { jumpTo(cur - 1); e.preventDefault(); }
    }

    slider.addEventListener('input', () => { dragging = true; const p = +slider.value; pgnoEl.innerHTML = `${p} <small>/ ${c.pages}</small>`; jumpTo(p); });
    slider.addEventListener('change', () => { dragging = false; jumpTo(+slider.value); update(); });
    zoomBtn.addEventListener('click', () => setZoom(ZOOMS[(ZOOMS.indexOf(zoom) + 1) % ZOOMS.length]));
    $('#btn-back').addEventListener('click', back);
    $('#btn-toc').addEventListener('click', () => openToc(c, cur, jumpTo));
    $('#btn-more').addEventListener('click', () => openReaderMenu(c, 'pages'));
    pagesEl.addEventListener('click', () => document.body.classList.toggle('chrome-hidden'));

    sc.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize);
    window.addEventListener('keydown', onKey);
    cleanup = () => {
      window.removeEventListener('resize', onResize);
      window.removeEventListener('keydown', onKey);
      clearTimeout(saveTimer);
      saveProgress(c, cur);
      unhydrate();
      document.body.classList.remove('chrome-hidden');
      app.onclick = null;
    };
    app.onclick = null;

    layout();
    jumpTo(p0);
    update();
    setTimeout(() => { jumpTo(p0); update(); }, 60);

    if (q) toast(`‘${q}’ — ${p0}쪽에 있어`);
    else if (wasNew) toast(`새 판(${c.version})이야 — 고친 곳이 있을 수 있어`);
    else if (!store.get('hint.rotate', false) && window.innerHeight > window.innerWidth) {
      store.set('hint.rotate', true);
      toast('폰을 가로로 돌리면 글자가 커져. 두 손가락으로 확대하거나 아래 % 버튼도 돼.', 4500);
    }
  }

  function saveProgress(c, p, f) {
    const prog = store.get('progress', {});
    const old = prog[c.id] || {};
    prog[c.id] = { p, f: f || 0, m: Math.max(p, old.m || 0), n: c.pages, k: c.key, t: Date.now() };
    store.set('progress', prog);
  }

  // ------------------------------------------------------------ 본문 리더(폰 화면에 맞춰 다시 흘린 글)
  const RF = {};
  let renderSeq = 0;
  const FS = [13, 14, 15, 16, 17, 18, 20];
  const FS_DEFAULT = 15;
  // 기본 = 소설처럼 글만(표·그림·쪽 구분 숨김). 설정에서 '표·그림도 보기'를 켜면 전부 보인다.
  const rich = () => store.get('rich', false);

  async function loadReflow(c) {
    const k = c.id + ':' + c.key;
    if (RF[k]) return RF[k];
    RF[k] = await Data.reflow(c);
    return RF[k];
  }

  // 본문 안의 'N쪽'을 그 쪽으로 가는 링크로
  function linkPages(h, n) {
    if (!rich()) return h || '';
    return (h || '').replace(/(\d{1,3})쪽/g, (m, d) => (+d >= 1 && +d <= n ? `<a class="pr" data-p="${+d}">${m}</a>` : m));
  }

  function blockHtml(c, b, id) {
    const L = (x) => linkPages(x, c.pages);
    switch (b.t) {
      case 'h':
        return b.lv === 2 ? `<h2 class="big">${L(b.x)}</h2>` : `<h3>${L(b.x)}</h3>`;
      case 'p':
        return `<p${b.cls ? ` class="${esc(b.cls)}"` : ''}>${L(b.x)}</p>`;
      case 'col':
        return b.side === 'R' && rich() ? '<div class="colgap"></div>' : '';
      case 'box':
        return `<div class="bx bx-${esc(b.k)}">${b.items.map((x) => blockHtml(c, x)).join('')}</div>`;
      case 'cards':
        return `<div class="cards">${b.items.map((i) => `<div class="card">${L(i.x)}</div>`).join('')}</div>`;
      case 'key':
        return `<div class="keybox"><div class="kt">${esc(b.title)}</div><ol>${b.items.map((i) => `<li${i.n ? ` data-n="${esc(i.n)}"` : ''}>${L(i.x)}</li>`).join('')}</ol></div>`;
      case 'table': {
        if (!rich()) return '';
        const title = b.title || b.summary || '표';
        return `<button class="tcard" data-blk="${id}"><span class="ti">표</span><span class="tt">${esc(title)}</span><span class="tm">${b.nrows}행 ›</span></button>`;
      }
      case 'fig':
        if (!rich()) return '';
        return `<figure class="fig" data-blk="${id}"><img loading="lazy" decoding="async" alt="${esc(b.title || '도해')}" data-img="${b.img}.webp" style="aspect-ratio:${b.iw}/${b.ih}">`
          + `<figcaption>${b.title ? esc(b.title) + ' · ' : ''}<span>눌러서 크게</span></figcaption></figure>`;
      default:
        return '';
    }
  }

  function applyFont() {
    document.documentElement.style.setProperty('--fs', store.get('fs', FS_DEFAULT) + 'px');
  }

  async function showReflow(c, startPage, q) {
    cleanup();
    const seq = ++renderSeq;
    document.title = `${c.label} ${c.title}`;
    const prog = store.get('progress', {});
    const pr = prog[c.id];
    const p0 = clamp(startPage || (pr && pr.p) || 1, 1, c.pages);
    const f0 = !startPage && pr && pr.p === p0 ? (pr.f || 0) : 0;

    const seen = store.get('seen', {});
    const wasNew = seen[c.id] !== undefined && seen[c.id] !== c.key;
    seen[c.id] = c.key;
    store.set('seen', seen);
    store.set('last', c.id);

    app.onclick = null;
    app.innerHTML = `<div class="rreader">
      <header class="topbar"><div class="topbar-in">
        <button class="iconbtn" id="btn-back" aria-label="뒤로">${ICON.back}</button>
        <div class="tb-title"><b>${esc(c.label)} ${esc(c.title)}</b><span id="sec"></span></div>
        <button class="iconbtn" id="btn-toc" aria-label="목차">${ICON.list}</button>
        <button class="iconbtn" id="btn-more" aria-label="더보기">${ICON.more}</button>
      </div><div class="rprog"><i id="rprog"></i></div></header>
      <article class="rf${rich() ? '' : ' novel'}" id="rf"><p class="muted">불러오는 중…</p></article>
      <footer class="botbar"><div class="botbar-in">
        <div class="pgno" id="pgno"></div>
        <input type="range" id="slider" min="1" max="${c.pages}" value="${p0}" aria-label="쪽 이동">
        <button class="zoombtn" id="btn-font" aria-label="글자 크기">가<small>가</small></button>
      </div></footer></div>`;
    applyFont();
    $('#btn-back').addEventListener('click', back);

    let data;
    try { data = await loadReflow(c); } catch (e) {
      if (seq !== renderSeq) return;
      toast('본문을 불러오지 못해 원본 쪽으로 보여 줄게');
      return showPages(c, startPage, q);
    }
    if (seq !== renderSeq) return;

    const rf = $('#rf');
    let h = '';
    let prevKey = '';
    for (const pg of data.pages) {
      h += `<section class="rp" data-p="${pg.p}">${rich() ? `<div class="pdiv"><span>${pg.p}쪽</span><button class="orig" data-orig="${pg.p}">원본 쪽</button></div>` : ''}`;
      const hd = pg.head;
      if (hd && (hd.title || hd.no)) {
        const t = (hd.title || '').replace(/\s*\(계속\)\s*$/, '');
        const key = (hd.no || '') + '|' + t;
        if (pg.p === 1) {
          h += `<div class="part">${esc(hd.title)}</div>${hd.tag ? `<div class="tag">${esc(hd.tag)}</div>` : ''}`;
        } else if (key === prevKey) {
          if (rich()) h += `<div class="hcont">${hd.no ? `<b>${esc(hd.no)}</b> ` : ''}${esc(t)} — 이어서</div>`;
        } else {
          h += `<h2 class="sec">${hd.no ? `<span class="no">${esc(hd.no)}</span>` : ''}<span>${esc(t)}</span></h2>${hd.tag ? `<div class="tag">${linkPages(esc(hd.tag), c.pages)}</div>` : ''}`;
        }
        prevKey = key;
      }
      pg.blocks.forEach((b, i) => { h += blockHtml(c, b, `${pg.p}:${i}`); });
      h += `</section>`;
    }
    h += `<div class="rend">${esc(c.label)} ${esc(c.title)} 끝 · ${esc(c.version)}<br><button class="linkbtn" id="btn-top">처음으로</button></div>`;
    rf.innerHTML = h;
    const unhydrate = hydrate(rf, c, null);
    const secs = $$('.rp', rf);
    const pgnoEl = $('#pgno'), slider = $('#slider'), secEl = $('#sec'), progEl = $('#rprog');
    const topOff = () => $('.topbar').getBoundingClientRect().height + 8;
    const block = (id) => { const [p, i] = id.split(':').map(Number); return data.pages[p - 1].blocks[i]; };

    function currentPage() {
      const y = topOff() + 40;
      let lo = 0, hi = secs.length - 1, ans = 0;
      while (lo <= hi) {
        const m = (lo + hi) >> 1;
        if (secs[m].getBoundingClientRect().top <= y) { ans = m; lo = m + 1; } else hi = m - 1;
      }
      return ans + 1;
    }
    function fracIn(p) {
      const r = secs[p - 1].getBoundingClientRect();
      return clamp((topOff() + 40 - r.top) / Math.max(1, r.height), 0, 1);
    }

    let quietUntil = 0;
    function jumpTo(p, frac = 0, el = null) {
      quietUntil = Date.now() + 400;
      document.body.classList.remove('chrome-hidden');
      const target = el || secs[clamp(p, 1, c.pages) - 1];
      const r = target.getBoundingClientRect();
      const y = r.top + window.scrollY + (el ? 0 : frac * r.height) - topOff() - (el ? 60 : 0);
      window.scrollTo(0, Math.max(0, y));
    }

    let cur = 0, dragging = false, saveTimer = 0;
    function update() {
      const p = currentPage();
      const docH = document.documentElement.scrollHeight - window.innerHeight;
      progEl.style.width = (docH > 0 ? (window.scrollY / docH) * 100 : 0) + '%';
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => saveProgress(c, p, fracIn(p)), 500);
      if (p !== cur) {
        cur = p;
        pgnoEl.innerHTML = `${p} <small>/ ${c.pages}쪽</small>`;
        if (!dragging) slider.value = p;
        secEl.textContent = secTitle(nearestTitle(c, p));
      }
    }

    let lastY = window.scrollY, ticking = false;
    function onScroll() {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        update();
        const y = window.scrollY, dy = y - lastY;
        if (dragging || Date.now() < quietUntil || modalOpen) { lastY = y; return; }
        if (Math.abs(dy) > 30) {
          if (dy > 0 && y > 120) document.body.classList.add('chrome-hidden');
          else if (dy < 0) document.body.classList.remove('chrome-hidden');
          lastY = y;
        }
      });
    }

    rf.addEventListener('click', (e) => {
      const a = e.target.closest('.pr');
      if (a) { e.preventDefault(); jumpTo(+a.dataset.p); return; }
      const t = e.target.closest('.tcard');
      if (t) { openTable(c, block(t.dataset.blk), jumpTo); return; }
      const f = e.target.closest('.fig');
      if (f) { const b = block(f.dataset.blk); openImage(b.title || '도해', c, `${b.img}.webp`, b.iw); return; }
      const o = e.target.closest('.orig');
      if (o) { openImage(`${o.dataset.orig}쪽 원본`, c, pageFile(+o.dataset.orig), c.w, true); return; }
      if (e.target.closest('#btn-top')) { jumpTo(1); return; }
      if (!String(window.getSelection() || '')) document.body.classList.toggle('chrome-hidden');
    });
    slider.addEventListener('input', () => { dragging = true; const p = +slider.value; pgnoEl.innerHTML = `${p} <small>/ ${c.pages}쪽</small>`; jumpTo(p); });
    slider.addEventListener('change', () => { dragging = false; jumpTo(+slider.value); update(); });
    $('#btn-font').addEventListener('click', () => openFontSheet(
      () => { const p = cur, f = fracIn(cur); applyFont(); jumpTo(p, f); },
      () => { closeSheet(); saveProgress(c, cur, fracIn(cur)); showReflow(c); }));
    $('#btn-toc').addEventListener('click', () => openToc(c, cur, (p) => jumpTo(p)));
    $('#btn-more').addEventListener('click', () => openReaderMenu(c, 'reflow'));

    let resizeTimer = 0;
    function onResize() {
      clearTimeout(resizeTimer);
      const p = cur, f = fracIn(cur || 1);
      resizeTimer = setTimeout(() => { jumpTo(p, f); update(); }, 150);
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize);
    cleanup = () => {
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onResize);
      clearTimeout(saveTimer);
      if (cur) saveProgress(c, cur, fracIn(cur));
      unhydrate();
      document.body.classList.remove('chrome-hidden');
      closeModal(true);
      renderSeq++;
    };

    let hit = null;
    if (q) hit = highlight(secs[p0 - 1], q, data.pages[p0 - 1], c);
    if (hit) jumpTo(p0, 0, hit); else jumpTo(p0, f0);
    update();

    if (q) toast(hit ? `‘${q}’ — ${p0}쪽` : `‘${q}’ — ${p0}쪽 (표·도해 안에 있을 수 있어)`);
    else if (wasNew) toast(`새 판(${c.version})이야 — 고친 곳이 있을 수 있어`);
  }

  // 검색어를 그 쪽 글에서 찾아 표시(띄어쓰기 무시). 표 안에만 있으면 표 카드를 표시.
  function highlight(sec, q, pg, c) {
    const qn = q.replace(/\s+/g, '').toLowerCase();
    if (!qn) return null;
    const walker = document.createTreeWalker(sec, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let s = '';
    const map = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n.parentElement.closest('.pdiv, .tcard, figcaption')) continue;
      const t = n.nodeValue;
      for (let i = 0; i < t.length; i++) {
        if (/\s/.test(t[i])) continue;
        s += t[i].toLowerCase();
        map.push([nodes.length, i]);
      }
      nodes.push(n);
    }
    let first = null;
    let at = s.indexOf(qn);
    const found = [];
    while (at >= 0 && found.length < 20) { found.push(at); at = s.indexOf(qn, at + qn.length); }
    for (const a of found.reverse()) {
      const [n0, i0] = map[a];
      const [n1, i1] = map[a + qn.length - 1];
      try {
        const range = document.createRange();
        range.setStart(nodes[n0], i0);
        range.setEnd(nodes[n1], i1 + 1);
        const mk = document.createElement('mark');
        mk.appendChild(range.extractContents());
        range.insertNode(mk);
        first = mk;
      } catch { /* 여러 요소에 걸친 경우 — 건너뜀 */ }
    }
    if (first) return first;
    const cards = $$('.tcard', sec);
    for (const card of cards) {
      const [p, i] = card.dataset.blk.split(':').map(Number);
      const b = pg.blocks[i];
      if (b && (b.text || '').replace(/\s+/g, '').toLowerCase().includes(qn)) { card.classList.add('hit'); return card; }
    }
    return null;
  }

  // ------------------------------------------------------------ 팝업(표·그림)
  let modalOpen = false;
  function openModal(title, body, foot) {
    const m = $('#modal');
    $('#mtitle').textContent = title;
    $('#mbody').innerHTML = body;
    $('#mfoot').innerHTML = foot || '';
    $('#mfoot').hidden = !foot;
    m.hidden = false;
    $('#mbody').scrollTop = 0; $('#mbody').scrollLeft = 0;
    document.body.classList.add('modal-on');
    if (!modalOpen) history.pushState({ modal: 1 }, '');
    modalOpen = true;
  }
  function closeModal(fromPop) {
    if (!modalOpen) return;
    modalOpen = false;
    $('#modal').hidden = true;
    $('#mbody').innerHTML = '';
    document.body.classList.remove('modal-on');
    if (!fromPop) history.back();
  }
  window.addEventListener('popstate', () => { if (modalOpen) closeModal(true); });

  function tableHtml(c, b) {
    const L = (x) => linkPages(x, c.pages);
    const span = (cell) => (cell.rs ? ` rowspan="${cell.rs}"` : '') + (cell.cs ? ` colspan="${cell.cs}"` : '');
    const head = b.head.map((r) => `<tr>${r.map((cell) => `<th${span(cell)}>${L(cell.x)}</th>`).join('')}</tr>`).join('');
    const body = b.rows.map((r) => `<tr>${r.map((cell) => `<td${span(cell)}>${L(cell.x)}</td>`).join('')}</tr>`).join('');
    return `<div class="twrap"><table class="rt">${head ? `<thead>${head}</thead>` : ''}<tbody>${body}</tbody></table></div>`;
  }

  function openTable(c, b, jumpTo) {
    const title = b.title || b.summary || '표';
    const foot = `<button class="mbtn" data-m="img">원본 그림으로 보기</button><button class="mbtn primary" data-m="close">닫기</button>`;
    openModal(title, tableHtml(c, b), foot);
    let img = false;
    $('#modal').onclick = (e) => {
      const a = e.target.closest('.pr');
      if (a) { e.preventDefault(); closeModal(); setTimeout(() => jumpTo(+a.dataset.p), 60); return; }
      const btn = e.target.closest('[data-m]');
      if (!btn) { if (e.target.id === 'modal') closeModal(); return; }
      if (btn.dataset.m === 'close') closeModal();
      else if (btn.dataset.m === 'img') {
        img = !img;
        $('#mbody').innerHTML = img ? imageHtml(`${b.img}.webp`, b.iw, false) : tableHtml(c, b);
        if (img) hydrate($('#mbody'), c);
        btn.textContent = img ? '표로 보기' : '원본 그림으로 보기';
      } else if (btn.dataset.m === 'big') toggleBig(btn);
    };
  }

  function imageHtml(file, iw, big) {
    // 도해 글자(7pt)가 폰에서 약 13px이 되는 크기 = 원본 픽셀 × 0.62
    const w = big ? `${Math.round(iw * 0.62)}px` : '100%';
    return `<div class="iwrap"><img data-img="${file}" alt="" style="width:${w};max-width:none" data-iw="${iw}"></div>`;
  }
  function toggleBig(btn) {
    const im = $('#mbody img');
    if (!im) return;
    const big = im.style.width === '100%';
    im.style.width = big ? `${Math.round(+im.dataset.iw * 0.62)}px` : '100%';
    btn.textContent = big ? '화면에 맞추기' : '크게 보기';
  }
  function openImage(title, c, file, iw, isPage) {
    // 넓은 그림은 처음부터 글자가 읽히는 크기로(좌우로 밀어 봄). 쪽 전체 그림은 화면 맞춤부터.
    const needBig = iw * 0.62 > window.innerWidth + 40;
    const big = needBig && !isPage;
    const foot = `${needBig ? `<button class="mbtn" data-m="big">${big ? '화면에 맞추기' : '크게 보기'}</button>` : ''}<button class="mbtn primary" data-m="close">닫기</button>`;
    openModal(title, imageHtml(file, iw, big), foot);
    hydrate($('#mbody'), c);
    if (big) toast('좌우로 밀어서 봐', 1600);
    $('#modal').onclick = (e) => {
      const btn = e.target.closest('[data-m]');
      if (!btn) { if (e.target.id === 'modal') closeModal(); return; }
      if (btn.dataset.m === 'close') closeModal();
      else if (btn.dataset.m === 'big') toggleBig(btn);
    };
    if (isPage && window.innerHeight > window.innerWidth) toast('가로로 돌리거나 “크게 보기”를 눌러 봐', 2200);
  }

  function openFontSheet(onChange, onRich) {
    const cur = store.get('fs', FS_DEFAULT);
    let h = `<div class="sheet-title">글자 크기</div><div class="fsrow">`;
    for (const s of FS) h += `<button class="fsbtn${s === cur ? ' on' : ''}" data-fs="${s}" style="font-size:${s}px">가</button>`;
    h += `</div><div class="sheet-title" style="padding-top:14px">화면</div>`;
    const th = store.get('theme', 'auto');
    h += `<div class="fsrow">${[['auto', '자동'], ['light', '밝게'], ['dark', '어둡게']].map(([k, l]) => `<button class="fsbtn wide${k === th ? ' on' : ''}" data-th="${k}">${l}</button>`).join('')}</div>`;
    if (onRich) h += `<button class="sheet-item" data-rich="1" style="margin-top:8px"><span>표·그림도 보기<br><small style="color:var(--ink-3)">끄면 소설처럼 글만 이어서 읽어</small></span><span class="switch${rich() ? ' on' : ''}"></span></button>`;
    openSheet(h, (e) => {
      if (e.target.closest('[data-rich]')) { store.set('rich', !rich()); onRich && onRich(); return; }
      const b = e.target.closest('[data-fs]');
      if (b) {
        store.set('fs', +b.dataset.fs);
        $$('.fsbtn[data-fs]').forEach((x) => x.classList.toggle('on', x === b));
        onChange && onChange();
        return;
      }
      const t = e.target.closest('[data-th]');
      if (t) {
        store.set('theme', t.dataset.th);
        applyTheme();
        $$('.fsbtn[data-th]').forEach((x) => x.classList.toggle('on', x === t));
      }
    });
  }

  function applyTheme() {
    const th = store.get('theme', 'auto');
    if (th === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', th);
  }

  // ------------------------------------------------------------ 시트
  function openSheet(html, onClick) {
    const sh = $('#sheet'), bd = $('#sheet-backdrop');
    sh.innerHTML = `<div class="sheet-grip"></div>${html}`;
    sh.hidden = false; bd.hidden = false;
    sh.scrollTop = 0;
    sh.onclick = onClick || null;
    bd.onclick = closeSheet;
    const curEl = $('.sheet-item.cur', sh);
    if (curEl) curEl.scrollIntoView({ block: 'center' });
  }
  function closeSheet() {
    $('#sheet').hidden = true;
    $('#sheet-backdrop').hidden = true;
  }

  function openToc(c, curPage, jumpTo) {
    const items = c.toc.filter((t) => !/\(계속\)\s*$/.test(t.t));
    let curIdx = 0;
    items.forEach((t, i) => { if (t.p <= curPage) curIdx = i; });
    let h = `<div class="sheet-title">${esc(c.label)} ${esc(c.title)} — 목차</div>`;
    items.forEach((t, i) => {
      const head = /^제\d+장/.test(t.t) ? ' head' : '';
      h += `<button class="sheet-item${i === curIdx ? ' cur' : ''}${head}" data-p="${t.p}"><span>${esc(t.t)}</span><span class="p">${t.p}쪽</span></button>`;
    });
    openSheet(h, (e) => {
      const b = e.target.closest('[data-p]');
      if (!b) return;
      closeSheet();
      jumpTo(+b.dataset.p);
    });
  }

  function openReaderMenu(c, mode) {
    const night = document.documentElement.classList.contains('night');
    const canCache = 'caches' in window;
    let h = `<div class="sheet-title">${esc(c.label)} ${esc(c.title)}</div>`;
    if (mode === 'reflow') h += `<button class="sheet-item" data-act="mode-pages"><span>원본 쪽 그대로 보기</span><span class="p">PDF 지면</span></button>`;
    else if (c.reflow) h += `<button class="sheet-item" data-act="mode-reflow"><span>폰 읽기 화면으로 보기</span><span class="p">본문</span></button>`;
    if (mode === 'pages') h += `<button class="sheet-item" data-act="night"><span>야간 모드 (쪽 색 반전)</span><span class="switch${night ? ' on' : ''}"></span></button>`;
    if (Data.pdf(c)) h += `<a class="sheet-item" href="${Data.pdf(c)}" target="_blank" rel="noopener"><span>원본 PDF 열기</span><span class="p">${esc(c.file)}</span></a>`;
    if (canCache) h += `<button class="sheet-item" data-act="offline"><span>이 장 오프라인 저장</span><span class="p" id="off-st"></span></button>`;
    h += `<div class="sheet-note">${esc(c.subject.name)} · ${esc(c.version)} · ${c.pages}쪽 · 파일 갱신 ${fmtDate(c.mtime)}<br>교재 원본은 매번 최신 판으로 자동 교체돼.</div>`;
    openSheet(h, async (e) => {
      const b = e.target.closest('[data-act]');
      if (!b) return;
      if (b.dataset.act === 'night') {
        const on = document.documentElement.classList.toggle('night');
        store.set('night', on);
        $('.switch', b).classList.toggle('on', on);
      } else if (b.dataset.act === 'offline') {
        await saveOffline([c], $('#off-st'));
      } else if (b.dataset.act === 'mode-pages' || b.dataset.act === 'mode-reflow') {
        const pr = store.get('progress', {})[c.id];
        store.set('mode', b.dataset.act === 'mode-pages' ? 'pages' : 'reflow');
        closeSheet();
        showReader(c, pr ? pr.p : 1);
      }
    });
  }

  function openSettings() {
    const night = document.documentElement.classList.contains('night');
    const canCache = 'caches' in window;
    let h = `<div class="sheet-title">설정</div>
      <button class="sheet-item" data-act="night"><span>야간 모드 (쪽 색 반전)</span><span class="switch${night ? ' on' : ''}"></span></button>`;
    if (canCache) h += `<button class="sheet-item" data-act="all"><span>전체 오프라인 저장</span><span class="p" id="off-st"></span></button>`;
    h += `<button class="sheet-item" data-act="reload"><span>목록 새로고침</span></button>
      <button class="sheet-item" data-act="reset"><span>읽은 위치 기록 지우기</span></button>
      <div class="sheet-note">${canCache ? '오프라인 저장은 이 기기에만 남아. 새 판이 나오면 그 장은 다시 받아야 해.' : '지금 접속 방식(https 아님)에서는 오프라인 저장을 쓸 수 없어.'}</div>`;
    openSheet(h, async (e) => {
      const b = e.target.closest('[data-act]');
      if (!b) return;
      const act = b.dataset.act;
      if (act === 'night') {
        const on = document.documentElement.classList.toggle('night');
        store.set('night', on);
        $('.switch', b).classList.toggle('on', on);
      } else if (act === 'all') {
        await saveOffline(ORDER, $('#off-st'));
      } else if (act === 'reload') {
        closeSheet();
        await loadLibrary(true);
        showHome();
        toast('목록을 새로 받았어');
      } else if (act === 'reset') {
        if (confirm('모든 장의 읽은 위치·진도를 지울까?')) {
          store.set('progress', {}); store.set('last', null);
          closeSheet(); showHome();
        }
      }
    });
  }

  async function saveOffline(chs, label) {
    try {
      const cache = await caches.open('jk-img-v1');
      const urls = [];
      if (label) label.textContent = '준비 중';
      for (const c of chs) {
        for (let i = 1; i <= c.pages; i++) urls.push(await Data.url(c, pageFile(i)));
        if (!c.reflow) continue;
        urls.push(await Data.url(c, 'reflow.json'));
        const d = await loadReflow(c);
        for (const pg of d.pages) for (const b of pg.blocks) if (b.img) urls.push(await Data.url(c, `${b.img}.webp`));
      }
      let done = 0, fail = 0;
      for (const u of urls) {
        if (!(await cache.match(u))) {
          try { const r = await fetch(u); if (r.ok) await cache.put(u, r); else fail++; } catch { fail++; }
        }
        done++;
        if (label && (done % 3 === 0 || done === urls.length)) label.textContent = `${done}/${urls.length}`;
      }
      if (label) label.textContent = fail ? `실패 ${fail}` : '저장됨';
      toast(fail ? `${fail}개를 받지 못했어 — 다시 눌러 줘` : `${chs.length}개 장 저장 완료 — 오프라인에서도 열려`);
    } catch (e) {
      toast('오프라인 저장 실패: ' + e.message);
    }
  }

  // ------------------------------------------------------------ 검색
  async function ensureSearch() {
    if (SEARCH) return SEARCH;
    const data = await Data.search();
    SEARCH = [];
    for (const c of ORDER) {
      const d = data[c.id];
      if (!d || d.k !== c.key) continue;
      d.p.forEach((t, i) => SEARCH.push({ c, n: i + 1, t, norm: null, map: null }));
    }
    return SEARCH;
  }

  function normEntry(e) {
    if (e.norm !== null) return;
    const t = e.t, map = [];
    let s = '';
    for (let i = 0; i < t.length; i++) {
      const ch = t.charCodeAt(i);
      if (ch === 32 || ch === 10 || ch === 13 || ch === 9 || ch === 160 || ch === 12288) continue;
      map.push(i);
      s += t[i];
    }
    e.norm = s.toLowerCase();
    e.map = map;
  }

  function showSearch(q0) {
    cleanup();
    document.title = '찾기 — 중개사 교재';
    app.innerHTML = `<header class="topbar"><div class="topbar-in">
        <button class="iconbtn" id="btn-back" aria-label="뒤로">${ICON.back}</button>
        <input class="search-input" id="q" type="search" enterkeyhint="search" placeholder="낱말·조문·회차 (띄어쓰기 무시)" value="${esc(q0)}" autocomplete="off">
      </div></header>
      <div class="search" id="res"><p class="muted">교재 전체(현행 판)에서 찾아. 예: 부기등기, 제52조, 34회</p></div>`;
    const input = $('#q'), res = $('#res');
    $('#btn-back').addEventListener('click', back);
    app.onclick = null;
    let timer = 0, seq = 0;

    async function run() {
      const q = input.value;
      const qn = q.replace(/\s+/g, '').toLowerCase();
      history.replaceState(null, '', '#/s' + (q ? '?q=' + encodeURIComponent(q) : ''));
      if (!qn) { res.innerHTML = `<p class="muted">교재 전체(현행 판)에서 찾아. 예: 부기등기, 제52조, 34회</p>`; return; }
      const my = ++seq;
      if (!SEARCH) res.innerHTML = `<p class="muted">색인 받는 중…</p>`;
      let idx;
      try { idx = await ensureSearch(); } catch { res.innerHTML = `<p class="muted">검색 색인을 받지 못했어.</p>`; return; }
      if (my !== seq) return;
      const LIMIT = 300;
      const groups = new Map();
      let total = 0;
      for (const e of idx) {
        normEntry(e);
        let at = e.norm.indexOf(qn);
        if (at < 0) continue;
        let count = 0, first = at;
        while (at >= 0) { count++; at = e.norm.indexOf(qn, at + qn.length); }
        const a = e.map[first], b = e.map[first + qn.length - 1] + 1;
        const s0 = Math.max(0, a - 36), s1 = Math.min(e.t.length, b + 70);
        const snip = (s0 > 0 ? '…' : '') + esc(e.t.slice(s0, a)) + '<mark>' + esc(e.t.slice(a, b)) + '</mark>' + esc(e.t.slice(b, s1)) + (s1 < e.t.length ? '…' : '');
        if (!groups.has(e.c)) groups.set(e.c, []);
        groups.get(e.c).push({ n: e.n, count, snip: snip.replace(/\n/g, ' ') });
        if (++total >= LIMIT) break;
      }
      if (!total) { res.innerHTML = `<p class="muted">‘${esc(q)}’ — 찾는 글자가 없어.</p>`; return; }
      let h = `<p class="muted" style="padding:8px 0 0;text-align:left">${total >= LIMIT ? LIMIT + '쪽 이상' : total + '쪽'}에서 찾았어</p>`;
      for (const [c, list] of groups) {
        h += `<div class="res-group">${esc(c.subject.name)} · ${esc(c.label)} ${esc(c.title)} (${list.length})</div>`;
        for (const r of list) {
          const sec = secTitle(nearestTitle(c, r.n));
          h += `<a class="res" href="#/r/${c.id}?p=${r.n}&q=${encodeURIComponent(q)}"><div class="h"><b>${r.n}쪽</b>${sec ? ' · ' + esc(sec) : ''}${r.count > 1 ? ` · ${r.count}곳` : ''}</div><div class="snip">${r.snip}</div></a>`;
        }
      }
      res.innerHTML = h;
    }

    input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 250); });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { clearTimeout(timer); run(); input.blur(); } });
    cleanup = () => clearTimeout(timer);
    if (q0) run(); else setTimeout(() => input.focus(), 50);
    window.scrollTo(0, 0);
  }

  // ------------------------------------------------------------ 열쇠(정적 모드)
  let keyJustSet = false;
  let routing = false;
  function startRouting() {
    if (!routing) { window.addEventListener('hashchange', route); routing = true; }
    route();
  }
  function showKeyScreen(msg) {
    cleanup(); cleanup = () => {};
    app.onclick = null;
    app.innerHTML = `<div class="home"><div class="keyscreen">
      <h1>중개사 교재</h1>
      <p>처음 한 번만 열쇠가 필요해. 받은 <b>열쇠 링크</b>를 이 기기에서 열거나, 열쇠를 붙여 넣어 줘.</p>
      <input id="kin" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="xxxxx-xxxxx-xxxxx-xxxxx">
      <button id="kbtn" class="kbtn">열기</button>
      <p class="kerr" id="kerr">${msg ? esc(msg) : ''}</p>
    </div></div>`;
    const submit = () => {
      const v = $('#kin').value.trim();
      const m = v.match(/#k=([A-Za-z0-9-]+)/);
      tryKey(m ? m[1] : v, false);
    };
    $('#kbtn').onclick = submit;
    $('#kin').onkeydown = (e) => { if (e.key === 'Enter') submit(); };
  }
  async function tryKey(pass, fromLink) {
    const err = $('#kerr');
    if (err) err.textContent = '확인 중…';
    try {
      const bits = await deriveBits(pass);
      await useBits(bits);
      LIB = null;
      await loadLibrary(true);
      store.set('kb', b64(bits));
      keyJustSet = true;
      startRouting();
    } catch (e) {
      Data.key = null;
      if (fromLink || !err) return showKeyScreen('열쇠가 맞지 않아. 다시 확인해 줘.');
      err.textContent = '열쇠가 맞지 않아.';
    }
  }
  async function boot() {
    if (!STATIC) return startRouting();
    // 열쇠 화면에 있는 동안 열쇠 링크(#k=…)로 바뀌면 바로 받는다
    window.addEventListener('hashchange', () => {
      const m = location.hash.match(/^#k=([A-Za-z0-9-]+)/);
      if (m && !routing) tryKey(m[1], true);
    });
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      app.innerHTML = '<div class="home"><p class="muted">이 브라우저에서는 열 수 없어(https 필요).</p></div>';
      return;
    }
    const m = location.hash.match(/^#k=([A-Za-z0-9-]+)/);
    if (m) return tryKey(m[1], true);
    const kb = store.get('kb', null);
    if (!kb) return showKeyScreen();
    try { await useBits(unb64(kb)); } catch { return showKeyScreen(); }
    startRouting();
  }

  // ------------------------------------------------------------ 시작
  if (store.get('night', false)) document.documentElement.classList.add('night');
  applyTheme();
  applyFont();

  document.addEventListener('visibilitychange', async () => {
    if (document.visibilityState !== 'visible' || !LIB) return;
    if (Date.now() - libLoadedAt < 60000) return;
    try {
      const changed = await loadLibrary(true);
      if (changed && curRoute === '') showHome();
    } catch { /* 오프라인 — 그대로 */ }
  });

  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
  boot();
})();
