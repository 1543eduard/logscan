let DATASET_ID = null;
let CURRENT_SUMMARY = null;
let REDACT = false;          // export/copy cu IP-uri pseudonimizate (share)
let LIVE_TIMER = null;       // reimprospatare automata, oprita implicit
let IN_INTERVAL_VIEW = false;  // true cat timp dashboard-ul arata statistici pentru un interval (nu o zi/ALL)
// Parametrii EXACTI ai intervalului activ (hour/minute/span SAU second/
// window_seconds, plus day) -- setati cand IN_INTERVAL_VIEW devine true,
// goliti la iesirea din vizualizarea de interval. Folositi de Path Explorer
// (loadPathExplorer) si de orice drill-down pe linii brute (drillDown) ca sa
// respecte ora/minutul ales in widgetul "Vezi cererile dintr-un moment
// exact" -- altfel exploreaza/vezi-cereri scanau mereu ZIUA INTREAGA, chiar
// daca userul bifase o ora anume (bug raportat de Eduard: "am bifat ora 20,
// vad requesturi de la ora 15").
let CURRENT_INTERVAL_PARAMS = null;
// Heatmap COMPLET (day=ALL), independent de ce zi e aleasa momentan in
// #daySelect sau de o vizualizare de interval -- populat o singura data la
// upload si NICIODATA suprascris de renderSummary()/CURRENT_SUMMARY. Folosit
// EXCLUSIV de computeAvailableHours() ca sa afle orele reale cu trafic
// pentru ziua aleasa in #momentDay (care e un selector SEPARAT de
// #daySelect si poate arata spre o zi diferita de cea incarcata curent in
// dashboard). Vezi bug-ul rezolvat: inainte, computeAvailableHours() citea
// CURRENT_SUMMARY.heatmap, care era scopat la orice zi/interval avea
// #daySelect in acel moment -- daca #momentDay indica o alta zi, orele
// afisate erau pur si simplu gresite (dintr-o zi diferita sau un fallback
// stale), iar "Vezi cererile brute" parea sa nu functioneze.
let FULL_HEATMAP = null;
let timelineChart = null, statusChart = null;

const $ = (sel) => document.querySelector(sel);

function redactUrl(url) {
  if (!REDACT) return url;
  return url + (url.includes('?') ? '&' : '?') + 'redact=1';
}
function ipToken(ip) {
  let h = 2166136261;
  for (let i = 0; i < ip.length; i++) { h ^= ip.charCodeAt(i); h = Math.imul(h, 16777619); }
  return 'ip_' + ((h >>> 0).toString(16).padStart(8, '0'));
}
function isIPv6(s) {
  if (!/^[0-9a-fA-F:]+$/.test(s) || (s.match(/:/g) || []).length < 2 || !/\d/.test(s)) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  const parts = halves.flatMap(h => h ? h.split(':') : []);
  if (parts.some(g => g.length > 4)) return false;
  return halves.length === 2 ? parts.length < 8 : parts.length === 8;
}
function redactClientText(text) {
  return String(text == null ? '' : text)
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (ip) => {
      const parts = ip.split('.').map(Number);
      return parts.every(n => n <= 255) ? ipToken(ip) : ip;
    })
    .replace(/[0-9a-fA-F:]{2,}/g, (tok) => isIPv6(tok) ? ipToken(tok.toLowerCase()) : tok);
}
function liveStop() {
  if (LIVE_TIMER) { clearInterval(LIVE_TIMER); LIVE_TIMER = null; }
  const b = $('#ctxLive');
  if (b) { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); b.textContent = 'Live 10s'; }
}
function liveToggle() {
  if (LIVE_TIMER) { liveStop(); toast('Reîmprospătarea automată a fost oprită.'); return; }
  if (!DATASET_ID) return;
  LIVE_TIMER = setInterval(() => {
    if (!DATASET_ID || document.hidden) return;
    if (CURRENT_PAGE === 'raw' && typeof TRIAGE !== 'undefined' && TRIAGE.ready) triageReloadAll();
    else showPage(CURRENT_PAGE, true);
  }, 10000);
  const b = $('#ctxLive');
  if (b) { b.classList.add('active'); b.setAttribute('aria-pressed', 'true'); b.textContent = 'Live pornit'; }
  toast('Reîmprospătare automată la 10 secunde (oprește cu același buton).');
}

const dropzone = $('#dropzone'), fileInput = $('#fileInput');

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
});
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault(); dropzone.classList.remove('drag');
  if (e.dataTransfer.files.length) uploadFiles(Array.from(e.dataTransfer.files));
});
fileInput.addEventListener('change', () => { if (fileInput.files.length) uploadFiles(Array.from(fileInput.files)); });

$('#ctxRedact').addEventListener('click', () => {
  REDACT = !REDACT;
  const b = $('#ctxRedact');
  b.classList.toggle('active', REDACT);
  b.setAttribute('aria-pressed', REDACT ? 'true' : 'false');
  b.textContent = REDACT ? 'Redactat' : 'Redactează';
  toast(REDACT ? 'Exporturile și copierile vor pseudonimiza adresele IP.' : 'Redactarea a fost oprită.');
});
$('#ctxLive').addEventListener('click', liveToggle);

$('#closeBtn').addEventListener('click', async () => {
  if (!DATASET_ID) return;
  if (!confirm('Închizi analiza curentă? Datele temporare se șterg imediat.')) return;
  $('#newBtn').click();
});
$('#newBtn').addEventListener('click', async () => {
  liveStop();
  // Datele sunt efemere si nu exista TTL: la "Încarcă alt log" inchidem
  // analiza veche imediat, ca memoria/workdir-ul sa nu se acumuleze.
  if (DATASET_ID) {
    try { await fetch(`/api/dataset/${DATASET_ID}/close`, { method: 'POST' }); } catch (e) {}
  }
  DATASET_ID = null;
  FULL_HEATMAP = null;
  $('#dash').style.display = 'none';
  $('#ipOverviewPage').style.display = 'none';
  $('#pageTabs').style.display = 'none';
  $('#daySelect').style.display = 'none';
  $('#newBtn').style.display = 'none';
  $('#closeBtn').style.display = 'none';
  $('#expJson').style.display = 'none';
  $('#expCsvType').style.display = 'none';
  $('#expCsv').style.display = 'none';
  $('#fname').textContent = ''; $('#sbFile').style.display = 'none'; $('#tbSel').style.display = 'none';
  $('#modTitle').textContent = 'logscan'; $('#modDesc').textContent = 'Analiza jurnalelor de acces (Apache / LiteSpeed) pentru trafic și securitate.';
  dropzone.style.display = 'block';
  fileInput.value = '';
});

// --------------------------------------------------------------------------
// Navigare intre pagini (Eduard: "inca o rubrica, dedicata pe pagina
// principala (o pagina noua sus)") -- doua pagini simple, un singur tab activ
// odata; #dash ramane pagina completa (tot ce exista deja), #ipOverviewPage
// e pagina noua, STRICT focusata pe cifre de IP/subnet/UA (vezi mai jos).
// --------------------------------------------------------------------------
// Fiecare card de pe vechiul dashboard (copil direct al #dash) primeste un
// tab, identificat dupa un id pe care il contine. Primul match castiga.
const TAB_OF_ANCHOR = [
  ['quickNav', 'none'],
  ['copySummaryBtn', 'investigations'], ['reportsCard', 'investigations'], ['ruleGenCard', 'investigations'], ['exportCard', 'investigations'],
  ['momentCard', 'raw'], ['explorerCard', 'raw'],
  ['investigationQueueCard', 'security'], ['findingsCard', 'security'], ['tblPathsRisk', 'security'],
  ['tblScan', 'security'], ['compromiseTrailCard', 'security'], ['wordfenceCard', 'security'], ['anomaliesCard', 'security'],
  ['wordpressSection', 'wordpress'],
  ['kpis', 'traffic'], ['trafficCompositionCard', 'traffic'], ['burstCard', 'traffic'], ['burstsAllCard', 'traffic'],
  ['timelineChart', 'traffic'], ['heatmapCard', 'traffic'], ['crawlersCard', 'traffic'],
  ['roVsWorldCard', 'countries'], ['countryCard', 'countries'],
  ['errorChart', 'errors'], ['statusChart', 'errors'], ['path404Card', 'errors'],
  ['subnetCard', 'ip'], ['tblIps', 'ip'], ['tblBwIps', 'ip'],
  ['queryParamsCard', 'endpoints'], ['pathPrefixCard', 'endpoints'], ['pathExplorerCard', 'endpoints'],
  ['tblDist', 'endpoints'], ['tblPathsPopular', 'endpoints'],
];
function _tabForNode(node) {
  for (const [id, tab] of TAB_OF_ANCHOR) {
    if (node.id === id || (node.querySelector && node.querySelector('#' + CSS.escape(id)))) return tab;
  }
  return 'traffic';
}
let _BOTS_MOVED = false;
function assignDashTabs() {
  // "Boti & crawlere" statea in acelasi grid cu graficul de erori (tab
  // Trafic) -- il mutam langa cardul Crawlere, o singura data.
  if (!_BOTS_MOVED) {
    const botsCard = $('#tblBots') && $('#tblBots').closest('.card');
    const crawlers = $('#crawlersCard');
    if (botsCard && crawlers && crawlers.parentElement === $('#dash')) {
      const oldGrid = botsCard.parentElement;
      const wrap = document.createElement('div');
      wrap.dataset.tab = 'traffic';
      wrap.style.marginBottom = '14px';
      crawlers.after(wrap);
      wrap.appendChild(botsCard);
      if (oldGrid && oldGrid.classList.contains('grid2')) oldGrid.style.gridTemplateColumns = '1fr';
      _BOTS_MOVED = true;
    }
  }
  [...$('#dash').children].forEach(ch => { if (!ch.dataset.tab) ch.dataset.tab = _tabForNode(ch); });
}
// v46: aplicatia e impartita in MODULE (meniul lateral). Fiecare modul are
// containerele lui proprii (.modPage) + cardurile analizei detaliate (v42) din
// #dash marcate cu data-tab = cheia modulului. Cheile vechi raman ca alias.
const MODULES = {
  overview: { title: 'Overview', desc: 'Situația generală a selecției: volum, tendință, alerte și principalele surse de trafic.', pages: ['#overviewPage'] },
  traffic: { title: 'Traffic Analytics', desc: 'Volum în timp, compoziția traficului, bursturi, crawlere și distribuția pe ore.', pages: ['#trafficPage'] },
  countries: { title: 'Countries', desc: 'De unde vine traficul: cereri și IP-uri pe țară, România față de restul lumii.', pages: ['#countriesPage'] },
  endpoints: { title: 'Endpoints & URLs', desc: 'Cele mai accesate rute, structura path-urilor, parametri și rute cu comportament neobișnuit.', pages: ['#endpointsPage'] },
  errors: { title: 'HTTP Errors', desc: 'Coduri de răspuns, evoluția erorilor 4xx / 5xx și URL-urile sau IP-urile care le produc.', pages: ['#errorsPage'] },
  security: { title: 'Security & Triaj', desc: 'Alerte, cronologia evenimentelor de securitate, findings și coada de investigare.', pages: ['#triagePage'] },
  wordpress: { title: 'WordPress Security', desc: 'wp-login, wp-admin, xmlrpc, REST API, admin-ajax și rutele de plugin-uri, cu IP-urile și codurile lor.', pages: ['#wordpressPage'] },
  ip: { title: 'IP Explorer', desc: 'IP-uri, subrețele și User-Agent-uri: cine face cereri, cât de des și cu ce rezultat.', pages: ['#ipOverviewPage'] },
  workplace: { title: 'Workplace', desc: 'Filtrare combinata pe orice camp (IP, subnet, URL, User-Agent, cod, marime, ora, crawler, severitate...), cu numarul exact de cereri pe fiecare conditie si liniile brute.', pages: ['#workplacePage'] },
  raw: { title: 'Raw Logs', desc: 'Cererile individuale ale selecției, cu linia originală din fișier, plus exploratorul pe ferestre de timp.', pages: ['#rawModule'] },
  investigations: { title: 'Investigations', desc: 'Rapoarte gata de trimis, reguli de blocare și export.', pages: ['#invModule'] },
};
const PAGE_ALIAS = { wk: 'workplace', workspace: 'workplace', triaj: 'security', prezentare: 'ip', explorare: 'raw', securitate: 'security', trafic: 'traffic',
                     crawlere: 'traffic', path: 'endpoints', rapoarte: 'investigations', dash: 'traffic' };
let CURRENT_PAGE = 'overview';
const MOD_HOOKS = {};          // hook-uri la afisarea unui modul (completate mai jos, v46)
function showPage(page, force) {
  page = String(page || '').split('?')[0];
  page = PAGE_ALIAS[page] || page;
  if (!MODULES[page]) page = 'overview';
  const changed = CURRENT_PAGE !== page;
  CURRENT_PAGE = page;
  assignDashTabs();
  const mod = MODULES[page];
  document.querySelectorAll('.modPage').forEach(el => { el.style.display = mod.pages.includes('#' + el.id) ? 'block' : 'none'; });
  let anyDash = false;
  [...$('#dash').children].forEach(ch => {
    const on = ch.dataset.tab === page;
    anyDash = anyDash || on;
    ch.style.display = (on || ch.dataset.tab === 'all') ? '' : 'none';
  });
  $('#dash').style.display = anyDash && DATASET_ID ? 'block' : 'none';
  if (anyDash) {
    setTimeout(() => window.dispatchEvent(new Event('resize')), 30);
    // analiza detaliata (v42) a selectiei se recalculeaza DOAR cand deschizi
    // un modul care o afiseaza -- nu la fiecare click pe un filtru.
    if (typeof gfEnsureDetailedTabs === 'function') gfEnsureDetailedTabs();
  }
  $('#modTitle').textContent = mod.title;
  $('#modDesc').textContent = mod.desc;
  document.title = mod.title + ' · logscan';
  document.querySelectorAll('.pageTabBtn').forEach(b => {
    const active = b.dataset.page === page;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  if (page === 'ip' && typeof ipovEnsureFresh === 'function') ipovEnsureFresh();
  if (page === 'security' && typeof triageOnShow === 'function') triageOnShow();
  // sumarul modulului se calculeaza la intrarea in modul (sau la cerere); la o
  // schimbare de selectie il reface GF_LISTENERS, nu fiecare re-afisare.
  if (MOD_HOOKS[page] && (changed || force || page === 'raw')) { try { MOD_HOOKS[page](); } catch (e) { console.warn('modul ' + page, e); } }
  if (changed) window.scrollTo(0, 0);
  if (location.hash !== '#' + page) {
    // intrare noua in istoric la schimbarea modulului: butonul Inapoi al browserului revine la modulul anterior
    try { if (changed && location.hash) history.pushState(null, '', '#' + page); else history.replaceState(null, '', '#' + page); } catch (e) {}
  }
}
// Link-uri interne (#findingsCard etc.) catre un card aflat in alt tab ->
// comuta automat pe tab-ul lui, apoi deruleaza.
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[href^="#"]');
  if (!a || a.getAttribute('href').length < 2) return;     // href="#" = link de actiune, nu ancora
  let target = null;
  try { target = document.querySelector(a.getAttribute('href')); } catch (err) { return; }
  if (!target || !$('#dash').contains(target)) return;
  let node = target;
  while (node && node.parentElement !== $('#dash')) node = node.parentElement;
  if (node && node.dataset.tab && node.dataset.tab !== CURRENT_PAGE) {
    e.preventDefault();
    showPage(node.dataset.tab);
    setTimeout(() => target.scrollIntoView({ behavior: 'smooth' }), 50);
  }
});
$('#pageTabs').addEventListener('click', (e) => {
  const btn = e.target.closest('.pageTabBtn');
  if (!btn) return;
  showPage(btn.dataset.page);
});

function showError(msg) {
  const el = $('#topbarError');
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 8000);
}

(async function privacyBoot() {
  try {
    const v = await (await fetch('/api/version')).json();
    const bits = ['local'];
    if (v.ephemeral) bits.push('efemer');
    if (v.offline) bits.push('offline');
    if (v.work_root_ram) bits.push('RAM');
    $('#privacyBadge').textContent = bits.join(' · ');
    $('#privacyBadge').title = 'Datele rămân în acest proces; se șterg la oprirea aplicației.';
  } catch (e) {}
})();

function _onUploadSuccess(data) {
  DATASET_ID = data.dataset_id;
  $('#fname').textContent = data.filename; $('#sbFile').style.display = 'block';
  // Cache heatmap-ul COMPLET (day=ALL) o singura data, aici -- summary-ul
  // de la upload e mereu calculat fara day_filter (vezi api_upload in
  // app.py), deci heatmap-ul lui acopera TOATE zilele din dataset. Acesta
  // e sursa stabila pentru computeAvailableHours(), independenta de orice
  // schimbare ulterioara a #daySelect sau intrare in interval view.
  FULL_HEATMAP = (data.summary && data.summary.heatmap) || null;
  // IMPORTANT: renderSummary() INTAI -- seteaza CURRENT_SUMMARY (folosit
  // pentru tot restul dashboard-ului), apoi populateDaySelect()/
  // populateMomentSelects() populeaza dropdown-urile de zi/ora din "Vezi
  // cererile dintr-un moment exact" folosind FULL_HEATMAP (nu
  // CURRENT_SUMMARY.heatmap) ca sa arate DOAR orele care chiar au trafic
  // in log, indiferent de ziua aleasa in #daySelect -- altfel dropdown-ul
  // de ore putea arata ore gresite (dintr-o alta zi) sau toate cele 24 de
  // ore, usor de ales din greseala si confundat cu "nu merge".
  renderSummary(data.summary);
  populateDaySelect(data.days);
  $('#uploadProgress').style.display = 'none';
  _uploadUiEnd();
  $('#dash').style.display = 'block';
  $('#newBtn').style.display = 'inline-block';
  $('#closeBtn').style.display = 'inline-block';
  // v49: exporturile au UN singur punct de acces -- meniul "Export" al selectiei
  // (bara de filtre). Butoanele vechi din antet raman ascunse (aceleasi rute).
  $('#pageTabs').style.display = 'flex';
  // stare curata pentru noul log
  IPOV = null; IPOV_ACTIVE = null; IPOV_BLOCK = []; IPOV_EXPANDED = {};
  delete $('#ipovReportDomain').dataset.touched;
  $('#ipovReportOut').value = ''; $('#ipovCmpOut').innerHTML = '';
  $('#ipovStart').value = ''; $('#ipovEnd').value = '';
  $('#ipovBody').style.display = 'none';
  ipovRenderBlock();
  // v43: tab-ul de triaj (alerte + tabel virtualizat) e noua pagina
  // implicita dupa upload -- "prezentare" ramane disponibila din tab-bar.
  // v44: pagina Prezentare isi face scanarea DOAR cand e deschisa (inainte
  // pornea la fiecare upload si concura la CPU cu indexarea).
  IPOV_STALE = true;
  if (typeof triageOnDatasetLoaded === 'function') triageOnDatasetLoaded();
  showPage((location.hash || '').slice(1) || 'overview', true);
}

async function uploadFiles(fileList, force) {
  liveStop();
  dropzone.style.display = 'none';
  $('#uploadProgress').style.display = 'block';
  _uploadUiStart();
  if (!UPLOAD_CTRL) UPLOAD_CTRL = new AbortController();
  const names = fileList.map(f => f.name).join(', ');
  // v43: un singur fisier -> upload chunked (fara timeout pe fisiere mari,
  // cu progres real). Mai multe fisiere (combinare arhive) -> calea veche,
  // sincrona (deja rapida pentru cazul ala -- fisiere de obicei mai mici).
  if (fileList.length === 1 && !force) {
    try {
      await uploadFileChunked(fileList[0]);
    } catch (e) {
      _uploadUiEnd();
      $('#uploadProgress').style.display = 'none';
      dropzone.style.display = 'block';
      if (!UPLOAD_CANCELLED) showError('Eroare la incarcare/analiza: ' + e.message);
    }
    return;
  }
  $('#uploadMsg').textContent = (fileList.length > 1 ? ('Se incarca ' + fileList.length + ' fisiere (' + names + ')') : ('Se incarca "' + names + '"')) + ' si se analizeaza (poate dura cateva secunde pentru fisiere mari)...';
  const fd = new FormData();
  fileList.forEach(f => fd.append('files', f));
  if (force) fd.append('force', 'true');
  try {
    const resp = await fetch('/api/upload', { method: 'POST', body: fd, signal: UPLOAD_CTRL ? UPLOAD_CTRL.signal : undefined });
    const data = await resp.json();
    if (resp.status === 409 && data.domain_mismatch) {
      $('#uploadProgress').style.display = 'none';
      const detalii = (data.per_file || []).map(pf => '  - ' + pf.filename + ' → ' + (pf.domain || '(necunoscut)')).join('\n');
      const confirmMsg = data.message + '\n\n' + detalii + '\n\nVrei sa le incarci oricum, combinate intr-un singur dataset?';
      if (window.confirm(confirmMsg)) {
        return uploadFiles(fileList, true);
      }
      dropzone.style.display = 'block';
      return;
    }
    if (!resp.ok) { throw new Error(data.error || ('HTTP ' + resp.status)); }
    _onUploadSuccess(data);
  } catch (e) {
    _uploadUiEnd();
    $('#uploadProgress').style.display = 'none';
    dropzone.style.display = 'block';
    if (!UPLOAD_CANCELLED) showError('Eroare la incarcare/analiza: ' + e.message);
  }
}

function populateDaySelect(days) {
  const sel = $('#daySelect');
  sel.innerHTML = '';
  const optAll = document.createElement('option');
  optAll.value = 'ALL'; optAll.textContent = 'Toate zilele';
  sel.appendChild(optAll);
  (days || []).forEach(d => {
    const o = document.createElement('option');
    o.value = d; o.textContent = d;
    sel.appendChild(o);
  });
  sel.style.display = 'inline-block';
  sel.onchange = async () => {
    IN_INTERVAL_VIEW = false;
    CURRENT_INTERVAL_PARAMS = null;
    $('#intervalBanner').style.display = 'none';
    // v43.2: ziua e parte din FILTRUL GLOBAL -- aceeasi selectie pentru
    // taburile v42, tabelul RAW, histograma si sinteza (inainte, ziua
    // reincarca un sumar care ignora orice alt filtru activ, ex. tara).
    if (TRIAGE.ready) {
      TRIAGE.filters.day = sel.value === 'ALL' ? '' : sel.value;
      triageRenderActiveChips();
      triageReloadAll();
      return;
    }
    $('#uploadProgress').style.display = 'block';
    $('#dash').style.display = 'none';
    $('#uploadMsg').textContent = 'Se reincarca analiza pentru ziua selectata...';
    try {
      const resp = await fetch(`/api/dataset/${DATASET_ID}/summary?day=${encodeURIComponent(sel.value)}`);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
      renderSummary(data);
    } catch (e) {
      showError('Eroare: ' + e.message);
    } finally {
      $('#uploadProgress').style.display = 'none';
      showPage(CURRENT_PAGE);
    }
  };
  populateMomentSelects(days);
}

function populateMomentSelects(days) {
  const daySel = $('#momentDay');
  daySel.innerHTML = '';
  const optAll = document.createElement('option');
  optAll.value = ''; optAll.textContent = 'Toate zilele';
  daySel.appendChild(optAll);
  (days || []).forEach(d => {
    const o = document.createElement('option');
    o.value = d; o.textContent = d;
    daySel.appendChild(o);
  });
  daySel.onchange = refreshMomentHourOptions;
  refreshMomentHourOptions();

  // Explorator de loguri (#expDay) -- selector de zi SEPARAT, acelasi tipar
  // ca #momentDay mai sus (populat o singura data la upload din lista de
  // zile disponibile din dataset).
  const expDaySel = $('#expDay');
  if (expDaySel) {
    expDaySel.innerHTML = '';
    const expOptAll = document.createElement('option');
    expOptAll.value = ''; expOptAll.textContent = 'Toate zilele (tot fisierul)';
    expDaySel.appendChild(expOptAll);
    (days || []).forEach(d => {
      const o = document.createElement('option');
      o.value = d; o.textContent = d;
      expDaySel.appendChild(o);
    });
  }

  // Prezentare IP (#ipovDay) -- acelasi tipar, selector propriu de zi pentru
  // pagina noua "Prezentare IP".
  const cmpDaySel = $('#ipovCmpDay');
  if (cmpDaySel) {
    cmpDaySel.innerHTML = '<option value="">Toate zilele</option>' + (days || []).map(d => `<option value="${esc(d)}">${esc(d)}</option>`).join('');
  }
  const ipovDaySel = $('#ipovDay');
  if (ipovDaySel) {
    ipovDaySel.innerHTML = '';
    const ipovOptAll = document.createElement('option');
    ipovOptAll.value = ''; ipovOptAll.textContent = 'Toate zilele (tot fisierul)';
    ipovDaySel.appendChild(ipovOptAll);
    (days || []).forEach(d => {
      const o = document.createElement('option');
      o.value = d; o.textContent = d;
      ipovDaySel.appendChild(o);
    });
  }
}

// Orele care chiar au trafic (pentru ziua aleasa in #momentDay, sau in tot
// dataset-ul daca "Toate zilele") -- din FULL_HEATMAP (heatmap-ul COMPLET,
// day=ALL, cache-uit o singura data la upload -- vezi definitia FULL_HEATMAP
// mai sus), NICIODATA din CURRENT_SUMMARY.heatmap. #momentDay e un selector
// SEPARAT de #daySelect (poate indica o zi diferita de cea incarcata curent
// in dashboard), deci sursa de adevar pentru "ce ore au trafic in ziua X"
// trebuie sa acopere mereu TOATE zilele, indiferent ce e incarcat curent.
// Fara niciun request nou la server. Daca FULL_HEATMAP lipseste dintr-un
// motiv oarecare, intoarce null si dropdown-ul arata toate cele 24 de ore
// (fallback sigur).
function computeAvailableHours() {
  const hm = FULL_HEATMAP;
  if (!hm || !hm.hours || !hm.hours.length || !hm.rows) return null;
  const selDay = $('#momentDay') ? $('#momentDay').value : '';
  if (!selDay) {
    return hm.hours.filter(h => hm.rows.some(r => (r.hours[h] || 0) > 0));
  }
  const row = hm.rows.find(r => r.day === selDay);
  if (!row) return [];
  return hm.hours.filter(h => (row.hours[h] || 0) > 0);
}

// Reconstruieste dropdown-ul de ore din "Vezi cererile dintr-un moment
// exact" ca sa arate DOAR orele cu trafic real -- raspunde direct la
// confuzia "am ales o ora si nu gaseste nimic" cand ora aleasa pur si
// simplu nu are nicio cerere in log. Pastreaza selectia curenta daca
// ramane valida dupa schimbarea zilei.
function refreshMomentHourOptions() {
  const hourSel = $('#momentHour');
  if (!hourSel) return;
  const prevVal = hourSel.value;
  const avail = computeAvailableHours();
  hourSel.innerHTML = '<option value="">Toate orele</option>';
  for (let h = 0; h < 24; h++) {
    const hs = String(h).padStart(2, '0');
    if (avail && !avail.includes(hs)) continue;
    const o = document.createElement('option');
    o.value = hs; o.textContent = hs + ':00';
    hourSel.appendChild(o);
  }
  hourSel.value = Array.from(hourSel.options).some(o => o.value === prevVal) ? prevVal : '';
  populateMomentMinuteOptions();
}

function populateMomentMinuteOptions() {
  const span = parseInt($('#momentGranularity').value, 10) || 0;
  const minSel = $('#momentMinute');
  minSel.innerHTML = '';
  if (span === 0) {
    // "Toata ora" -- minutul nu se aplica deloc
    minSel.innerHTML = '<option value="">(toata ora)</option>';
    minSel.disabled = true;
    return;
  }
  minSel.disabled = false;
  for (let m = 0; m < 60; m += span) {
    const ms = String(m).padStart(2, '0');
    const o = document.createElement('option');
    o.value = ms;
    o.textContent = span === 1 ? (':' + ms) : (':' + ms + ' - :' + String(Math.min(59, m + span - 1)).padStart(2, '0'));
    minSel.appendChild(o);
  }
}

$('#momentGranularity').addEventListener('change', populateMomentMinuteOptions);

function buildMomentParams() {
  const day = $('#momentDay').value;
  const hour = $('#momentHour').value;
  const span = parseInt($('#momentGranularity').value, 10) || 0;
  const minute = span > 0 ? $('#momentMinute').value : '';
  const params = {};
  if (day) params.day = day;
  if (hour) params.hour = hour;
  if (hour && span > 0 && minute !== '') { params.minute = minute; params.span = span; }
  let label = day || 'toate zilele';
  if (hour) {
    label += ' ' + hour + ':00';
    if (span > 0 && minute !== '') {
      const mEnd = String(Math.min(59, parseInt(minute, 10) + span - 1)).padStart(2, '0');
      label = (day || 'toate zilele') + ' ' + hour + ':' + minute + (span > 1 ? ('-' + hour + ':' + mEnd) : '');
    }
  }
  return { params, label };
}

$('#momentGo').addEventListener('click', () => {
  const { params, label } = buildMomentParams();
  drillDownRaw(params, 'Moment: ' + label);
});

// --- Cautare pe ora exacta (HH:MM:SS) +/- fereastra, alternativa/rafinare
// fata de selectoarele de ora+minut de mai sus -- vezi second_filter in
// app.py (_scan_chunk_raw/api_raw). Cand e completata, are prioritate:
// trimitem doar day (daca a fost ales) + second + window_seconds, backend-ul
// ignora hour/minute in acel caz.
$('#momentSecondGo').addEventListener('click', () => {
  const sec = $('#momentSecond').value; // "HH:MM:SS" sau "HH:MM" din inputul <input type=time step=1>
  if (!sec) { showError('Completeaza ora exacta (HH:MM:SS) mai intai.'); return; }
  const secFull = sec.length === 5 ? sec + ':00' : sec;
  const day = $('#momentDay').value;
  const win = parseInt($('#momentWindow').value, 10);
  const windowSeconds = Number.isFinite(win) && win >= 0 ? win : 30;
  const params = { second: secFull, window_seconds: windowSeconds };
  if (day) params.day = day;
  drillDownRaw(params, 'Moment exact: ' + (day || 'toate zilele') + ' ' + secFull + ' ±' + windowSeconds + 's');
});
$('#momentSecondClear').addEventListener('click', () => { $('#momentSecond').value = ''; });

$('#momentStats').addEventListener('click', async () => {
  // v45: "statistici pentru interval" = SETEAZA PERIOADA GLOBALA (aceeasi
  // stare pentru toate componentele si drilldown-urile). Inainte se incarca
  // un sumar separat (summary_range), iar drilldown-urile deschise din el
  // nu stiau de interval.
  const { params, label } = buildMomentParams();
  if (!params.day) { showError('Selecteaza mai intai o zi (statisticile pe interval au nevoie de o zi exacta).'); return; }
  if (!DATASET_ID || !TRIAGE.ready) { showError('Indexarea nu e gata inca -- reincearca in cateva secunde.'); return; }
  let a, b;
  if (!params.hour) { a = _dayHmsToEpoch(params.day, '00:00:00'); b = _dayHmsToEpoch(params.day, '23:59:59'); }
  else if (params.minute == null) { a = _dayHmsToEpoch(params.day, params.hour + ':00:00'); b = a + 3599; }
  else { a = _dayHmsToEpoch(params.day, params.hour + ':' + params.minute + ':00'); b = a + 60 * (parseInt(params.span, 10) || 1) - 1; }
  triageSetRange(a, b);
  toast('Perioada globala: ' + label);
  showPage('traffic');
});

$('#expJson').addEventListener('click', () => {
  if (!DATASET_ID) return;
  const day = $('#daySelect').value || 'ALL';
  window.open(redactUrl(gfUrl(`/api/dataset/${DATASET_ID}/export.json?day=${encodeURIComponent(day)}`)), '_blank');
});
$('#expCsv').addEventListener('click', () => {
  if (!DATASET_ID) return;
  const day = $('#daySelect').value || 'ALL';
  const type = $('#expCsvType') ? $('#expCsvType').value : 'findings';
  window.open(redactUrl(gfUrl(`/api/dataset/${DATASET_ID}/export.csv?day=${encodeURIComponent(day)}&type=${encodeURIComponent(type)}`)), '_blank');
});

function fmtBytes(n) {
  if (!n) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}
function fmtNum(n) { return (n || 0).toLocaleString('ro-RO'); }
// v44: escapeaza si ghilimelele -- esc() e folosit si in atribute HTML
// (data-ip="...", title="..."), unde un UA/URL din log cu " putea iesi din
// atribut (date neincredere, spec §8).
function esc(s) { return (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
// v50: steaguri SVG servite local (/static/flags, flag-icons MIT) -- emoji-urile
// de steag nu apar in Chrome/Edge pe Windows (se vad doar doua litere).
function flagHtml(cc) {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return '';
  const c = cc.toLowerCase();
  return `<img class="flag" src="/static/flags/${c}.svg" alt="" width="16" height="12" loading="lazy" decoding="async" onerror="this.remove()">`;
}
function flagEmoji(cc) { return flagHtml(cc); }
function countryCell(cc) {
  if (!cc) return '<td class="reasons">-</td>';
  return `<td title="${esc(cc)}">${flagEmoji(cc)} ${esc(cc)}</td>`;
}
// Cand dataset-ul e combinat din mai multe fisiere (upload multiplu), fiecare
// IP/eveniment poate avea unul sau mai multe domenii/subdomenii asociate
// (vezi file_segments din app.py) -- le afisam intre paranteze, langa IP,
// ca sa stii DIRECT pe ce domeniu s-a intamplat compromiterea, fara sa
// deschizi fiecare eveniment din traseu ca sa afli.
function domainSuffix(domains) {
  if (!domains || !domains.length) return '';
  return ` <span class="reasons">(${domains.map(esc).join(', ')})</span>`;
}
// Celula "Sursa" din tabelul de Findings -- majoritatea findings au un IP
// concret (brute force, enumerare, webshell etc.), caz in care refolosim
// exact acelasi mecanism de drill-down pe IP ca peste tot in dashboard.
// Cateva findings (ex: wp-cron.php stacking/volum) sunt semnale pe o
// FEREASTRA de timp, nu pe un IP anume -- pentru alea folosim path (+
// zi/ora/minut, cand exista) prin data-fpath, vezi attachDrillHandlers.
function findingDrillCell(r) {
  if (r.ip) {
    return `<span class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</span>`;
  }
  if (r.path) {
    let attrs = `data-fpath="${esc(r.path)}"`;
    if (r.day) attrs += ` data-fday="${esc(r.day)}"`;
    if (r.hour) attrs += ` data-fhour="${esc(r.hour)}"`;
    if (r.minute) attrs += ` data-fminute="${esc(r.minute)}"`;
    return `<span class="mono clickable" ${attrs}>${esc(r.path)}</span>`;
  }
  // Anomalii (Faza 2) pot avea sursa pe subnet (fara IP/path concret) sau
  // pe un burst anume (fereastra de 30s) -- refolosim mecanismele deja
  // existente de drill-down pe subnet/burst.
  if (r.subnet) {
    return `<span class="mono clickable" data-subnet="${esc(r.subnet)}">${esc(r.subnet)}</span>`;
  }
  if (r.burst_key) {
    return `<span class="mono clickable" data-anomaly-burst="${esc(r.burst_key)}" data-anomaly-burst-label="${esc(r.time || r.burst_key)}">${esc(r.time || 'burst')}</span>`;
  }
  return '-';
}

// --- Findings/Anomalii: panou de "explicatie" expandabil in acelasi rand,
// la click pe chevron -- arata DOUA lucruri, niciodata un JSON brut:
// 1) `reason` -- o propozitie in limba romana, scrisa per-tip de
//    finding/anomalie (vezi app.py), care spune DE CE a aparut semnalul;
// 2) `evidence` -- numerele concrete din spatele lui, ca tabel structurat
//    (campul 'evidence' adaugat in app.py pe fiecare finding/anomalie).
function humanizeEvidenceKey(k) {
  return k.replace(/_/g, ' ');
}
function buildEvidenceHtml(item) {
  const reasonHtml = item && item.reason
    ? `<div class="reasonText"><strong>De ce a aparut:</strong> ${esc(item.reason)}</div>` : '';
  const ev = item && item.evidence;
  if (!ev || typeof ev !== 'object') {
    return reasonHtml || '<div class="note" style="margin-top:6px">Fara date structurate suplimentare.</div>';
  }
  const rows = Object.entries(ev)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => {
      const val = (typeof v === 'object') ? JSON.stringify(v) : String(v);
      return `<tr><td class="evKey">${esc(humanizeEvidenceKey(k))}</td><td class="evVal">${esc(val)}</td></tr>`;
    }).join('');
  const tableHtml = rows ? `<table class="evidenceTable">${rows}</table>` : '';
  return reasonHtml + tableHtml || '<div class="note" style="margin-top:6px">Fara date structurate suplimentare.</div>';
}
document.addEventListener('click', (e) => {
  const tog = e.target.closest('.findingToggle');
  if (!tog) return;
  e.stopPropagation();
  const idx = parseInt(tog.dataset.findingIdx, 10);
  const source = tog.dataset.findingSource || 'findings';
  const td = tog.closest('.findingDetailCell');
  if (!td) return;
  const item = (CURRENT_SUMMARY && CURRENT_SUMMARY[source] || [])[idx];
  const expanded = td.dataset.expanded === '1';
  if (expanded) {
    td.dataset.expanded = '0';
    tog.innerHTML = '&#9656;';
    const panel = td.querySelector('.evidencePanel');
    if (panel) panel.remove();
  } else {
    td.dataset.expanded = '1';
    tog.innerHTML = '&#9662;';
    const panel = document.createElement('div');
    panel.className = 'evidencePanel';
    panel.innerHTML = buildEvidenceHtml(item);
    td.appendChild(panel);
  }
});

// --- Parametri de query (Faza 2) -- un singur tabel plat, cu o coloana
// "Categorie" (badge colorat) in loc de 3 tabele separate; usor de cautat/
// sortat cu acelasi mecanism (renderTableEnh) ca restul dashboard-ului.
// Feature #4 (Eduard) -- pragul care marcheaza un path ca avand "semnatura de
// enumerare": ambele semnale (fara referer + raport IP/cereri) ridicate.
function pathHasEnumSignal(r) {
  return (r.no_referer_pct || 0) >= 80 && (r.ip_request_ratio || 0) >= 0.7;
}

// Task 3 (Eduard): badge "acest path/prefix are un semnal REAL de atac/abuz"
// -- backend a facut deja cross-referince-ul (has_signal/signal_summary in
// top_path_prefixes, vezi build_summary). Click deruleaza spre tabelul
// "Abuz parametri / filtre" (sursa cea mai probabila) si il ilumineaza
// scurt -- doar navigare + flash CSS, nicio cerere noua catre server.
function attackSignalBadgeHtml(r) {
  if (!r || !r.has_signal) return '';
  const summary = r.signal_summary || 'Semnal concret asociat acestui prefix (vezi Abuz parametri / Findings).';
  return `<span class="attackSignalBadge" data-signal-jump="1" title="${esc(summary)}">&#9888; atac real</span>`;
}
// "Path-uri populare" tine path-uri EXACTE (cu query), nu prefixe -- backend
// nu calculeaza has_signal pentru ele direct (doar pentru top_path_prefixes).
// Reutilizam aceeasi lista (deja in summary, zero cerere noua) client-side:
// un path popular "are semnal" daca INCEPE cu un prefix marcat has_signal.
function findSignalForPath(path, s) {
  if (!path || !s || !s.top_path_prefixes) return null;
  for (const row of s.top_path_prefixes) {
    if (row.has_signal && path.startsWith(row.path)) return row;
  }
  return null;
}
function jumpToSignalSource() {
  const target = $('#paramAbuseCard');
  if (!target) return;
  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  target.classList.add('rowFlash');
  setTimeout(() => target.classList.remove('rowFlash'), 1650);
}

// --------------------------------------------------------------------------
// Bug #1 fix (Eduard) -- afisarea revendicarii de identitate crawler
// (crawler_claim, calculat in build_summary) pe randurile de IP-uri
// suspecte/subnete, cu re-adnotare LIVE dupa ce verificarea DNS Tier 2 se
// termina (CRAWLER_VERIFY_RESULTS, populat de pollCrawlerVerification --
// vezi mai jos). `ips` = lista de IP-uri de verificat pentru acest rand (un
// singur IP pentru tblSusp; omis pentru tblSubnet, unde nu trimitem lista
// completa de IP-uri per subnet catre client -- acolo badge-ul ramane
// generic "revendica X", fara breakdown verificat/nesigur per-IP).
function crawlerClaimBadge(claim, ips) {
  if (!claim) return '';
  if (!ips || !ips.length || !CRAWLER_VERIFY_RESULTS) {
    return ` <span class="crawlerClaimBadge pending" title="Revendica identitatea ${esc(claim)} (UA) -- verificare DNS asincrona in sectiunea Crawlere">revendica ${esc(claim)}</span>`;
  }
  let ok = 0, bad = 0, nc = 0;
  ips.forEach(ip => {
    const r = CRAWLER_VERIFY_RESULTS[ip];
    if (!r) { nc++; return; }
    if (r.verified === true) ok++; else if (r.verified === false) bad++; else nc++;
  });
  if (bad > 0) {
    return ` <span class="crawlerClaimBadge bad" title="Pretinde ${esc(claim)} dar verificarea DNS a esuat -- posibil spoofing">&#9888; pretinde ${esc(claim)}, DNS esuat</span>`;
  }
  if (ok > 0 && nc === 0) {
    return ` <span class="crawlerClaimBadge ok" title="Revendica ${esc(claim)}, confirmat prin verificare DNS (PTR)">&#10003; crawler verificat (DNS)</span>`;
  }
  return ` <span class="crawlerClaimBadge pending" title="Revendica identitatea ${esc(claim)} -- verificare DNS in curs">revendica ${esc(claim)}</span>`;
}

function crawlerClaimRowClass(claim, ips) {
  if (!claim || !ips || !ips.length || !CRAWLER_VERIFY_RESULTS) return '';
  let ok = 0, bad = 0;
  ips.forEach(ip => {
    const r = CRAWLER_VERIFY_RESULTS[ip];
    if (r && r.verified === true) ok++;
    if (r && r.verified === false) bad++;
  });
  if (bad > 0) return 'crawlerSpoofRow';
  if (ok > 0) return 'crawlerVerifiedRow';
  return '';
}

const QP_CAT_LABEL = { tracking: 'Tracking', functional: 'Functional', suspicious: 'Suspect', cache_busting: 'Cache-busting', other: 'Altele' };
const QP_CAT_CLASS = { tracking: 'INFO', functional: 'LOW', suspicious: 'MEDIUM', cache_busting: 'INFO', other: 'INFO' };
function renderQueryParams(qp) {
  const rows = [];
  ['suspicious', 'functional', 'tracking', 'cache_busting', 'other'].forEach(cat => {
    (qp[cat] || []).forEach(item => rows.push({ cat, key: item.key, requests: item.requests }));
  });
  rows.sort((a, b) => b.requests - a.requests);
  // Feature #2 (Eduard): fiecare nume de parametru e acum clickable (data-qkey)
  // -- deschide acelasi modal de drill-down ca IP/path/UA, filtrat pe cereri
  // a caror query string contine acel parametru ca si cheie (vezi qkey in
  // /api/dataset/{id}/raw). Randurile "Suspect" primesc aceeasi culoare
  // portocalie/suspicioasa ca in restul dashboard-ului; restul raman neutre.
  renderTableEnh('#tblQueryParams', '#cQueryParams', rows, r => [
    `<td><span class="tag ${QP_CAT_CLASS[r.cat] || 'INFO'}">${esc(QP_CAT_LABEL[r.cat] || r.cat)}</span></td>`,
    `<td class="mono clickable" data-qkey="${esc(r.key)}">${esc(r.key)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`
  ], null, r => r.cat === 'suspicious' ? 'qpSuspectRow' : '');
}

// --- Coada de investigare (Faza 3) -- randare simpla a listei deja
// sortate/agregate de server (build_summary._build_investigation_queue),
// fara nicio logica de prioritizare suplimentara aici.
const INV_SEV_TAG = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', INFO: 'INFO' };
function renderInvestigationQueue(s) {
  const q = s.investigation_queue || { items: [], total: 0, more: 0 };
  const tbody = document.querySelector('#tblInvQueue tbody');
  if (!q.items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Fara findings/anomalii -- nimic de prioritizat.</td></tr>';
  } else {
    tbody.innerHTML = q.items.map((it, i) => {
      const sevTag = `<span class="tag ${INV_SEV_TAG[it.severity] || 'INFO'}">${esc(it.severity || '?')}</span>`;
      const srcLabel = it.source === 'finding' ? 'Finding' : 'Anomalie';
      const drillAttrs = it.ip ? `data-ip="${esc(it.ip)}"` :
        (it.path ? `data-path="${esc(it.path)}"` : (it.subnet ? `data-subnet="${esc(it.subnet)}"` : ''));
      const whoCell = drillAttrs ? `<span class="mono clickable" ${drillAttrs}>${esc(it.ip || it.path || it.subnet || '-')}</span>` : '-';
      return `<tr><td class="num">${i + 1}</td><td>${sevTag}</td><td>${esc(srcLabel)}</td>` +
        `<td>${esc(it.rule)}</td><td style="max-width:420px">${esc(it.detail)} ${whoCell}</td>` +
        `<td class="mono">${esc(it.time || '-')}</td></tr>`;
    }).join('');
  }
  $('#cInvQueue').textContent = q.items.length + ' din ' + fmtNum(q.total) + ' semnale';
  $('#invQueueMore').textContent = q.more > 0
    ? `... si inca ${fmtNum(q.more)} semnale (vezi Findings/Anomalii mai jos pentru lista completa).`
    : '';
  attachDrillHandlers();
}

// ==========================================================================
// Task 4 (Eduard): RO vs restul lumii -- donut (2 felii, click = selectie)
// + doua bar-chart-uri orizontale de compozitie pentru partea selectata.
// Inline SVG/HTML desenat manual (fara librarie externa), conform skill-ului
// de dataviz. Donutul reutilizeaza country_totals (deja calculat, insumat
// client-side aici -- nicio schimbare de backend pt. felii). Bar chart-ul de
// identitate foloseste campul nou s.ro_vs_world (o singura trecere in plus
// peste ip_counter deja existent in build_summary, zero trecere noua prin
// log). Bar chart-ul de tari reutilizeaza country_totals (filtrat client-side).
// ==========================================================================
let RVW_SELECTED = 'non_ro'; // default: non-RO, "de obicei partea de investigat"

function rvwFmtPct(v) { return (Math.round((v || 0) * 10) / 10) + '%'; }

// v44: trei felii -- RO, NON-RO (tara CUNOSCUTA, alta decat RO) si
// "nedeterminata" (GeoIP fara tara pentru IP). Inainte, nedeterminatele erau
// adunate la NON-RO aici, dar NU si in filtrul global / drill-down -> cifre
// diferite pentru aceeasi selectie.
const RVW_SIDES = [
  { side: 'ro', label: 'RO', color: 'var(--rvw-ro)', scope: 'RO' },
  { side: 'non_ro', label: 'NON-RO', color: 'var(--rvw-nonro)', scope: '__non_ro__' },
  { side: 'unknown', label: 'Nedeterminata (??)', color: '#8A96A6', scope: '??' },
];
function renderRoVsWorldDonut(vals) {
  const svg = $('#roVsWorldDonut');
  if (!svg) return;
  const total = vals.ro + vals.non_ro + vals.unknown;
  const cx = 60, cy = 60, r = 42, sw = 20;
  const circ = 2 * Math.PI * r;
  const sides = RVW_SIDES.filter(x => x.side !== 'unknown' || vals.unknown > 0);
  const nz = sides.filter(x => vals[x.side] > 0).length;
  const gap = total > 0 && nz > 1 ? 2.5 : 0;
  let html = `<g transform="rotate(-90 ${cx} ${cy})">`;
  let off = 0;
  sides.forEach(x => {
    const v = vals[x.side];
    const len = Math.max(0, circ * (v / (total || 1)) - gap);
    const pct = total ? 100 * v / total : 0;
    html += `<circle class="rvwSlice" data-rvw-side="${x.side}" cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${x.color}" stroke-width="${sw}" `
      + `stroke-dasharray="${len} ${circ - len}" stroke-dashoffset="${-off}" opacity="${RVW_SELECTED === x.side ? 1 : .55}"><title>${x.label}: ${fmtNum(v)} cereri (${rvwFmtPct(pct)})</title></circle>`;
    off += len + gap;
  });
  html += `</g>`;
  const sel = RVW_SIDES.find(x => x.side === RVW_SELECTED) || RVW_SIDES[1];
  html += `<text x="${cx}" y="${cy - 3}" text-anchor="middle" class="roVsWorldDonutCenter" style="fill:var(--text);font-size:15px;font-weight:600">${rvwFmtPct(total ? 100 * vals[sel.side] / total : 0)}</text>`;
  html += `<text x="${cx}" y="${cy + 12}" text-anchor="middle" class="roVsWorldDonutCenter">${sel.side === 'unknown' ? '??' : sel.label}</text>`;
  svg.innerHTML = html;
  svg.querySelectorAll('[data-rvw-side]').forEach(el => {
    el.onclick = () => { RVW_SELECTED = el.dataset.rvwSide; renderRoVsWorld(CURRENT_SUMMARY); };
  });
  const legend = $('#roVsWorldLegend');
  if (legend) {
    legend.innerHTML = sides.map(it => `<div class="rvwLegendItem${RVW_SELECTED === it.side ? ' selected' : ''}" data-rvw-side="${it.side}">`
      + `<span class="rvwSwatch" style="background:${it.color}"></span>${it.label}`
      + `<span class="rvwLegendVal">${fmtNum(vals[it.side])} (${rvwFmtPct(total ? 100 * vals[it.side] / total : 0)})</span></div>`).join('');
    legend.querySelectorAll('[data-rvw-side]').forEach(el => {
      el.onclick = () => { RVW_SELECTED = el.dataset.rvwSide; renderRoVsWorld(CURRENT_SUMMARY); };
    });
  }
}

// Bar chart orizontal generic, o singura culoare (categorii nominale, nu
// serii -- vezi color-formula.md), etichete directe la capatul barei
// (valoare + %), tooltip pe hover/focus prin <title>, plus un target de
// focus (tabindex) ca sa fie accesibil de la tastatura (interaction.md:
// "same details on keyboard focus as on hover").
// Eduard: "aici nu era bine sa pot da click, chiar daca nu e tara /
// valabil pentru toate" -- fiecare bara (identitate SAU tara) trebuie sa
// deschida acelasi drilldown brut ca restul aplicatiei. Randul foldat
// "Altele" (vezi rvwFoldTop) nu are un `key` -- nu reprezinta o singura
// valoare filtrabila, deci ramane neclickabil (cursor default, fara
// data-attribute).
function renderRvwBarChart(containerSel, rows, opts) {
  const el = $(containerSel);
  if (!el) return;
  opts = opts || {};
  if (!rows || !rows.length) {
    el.innerHTML = '<div class="rvwEmpty">Fara date pentru aceasta selectie.</div>';
    return;
  }
  const max = Math.max(...rows.map(r => r.value), 1);
  el.innerHTML = rows.map(r => {
    const widthPct = Math.max(1, (100 * r.value / max));
    const valTxt = `${fmtNum(r.value)}${r.pct != null ? ' (' + rvwFmtPct(r.pct) + ')' : ''}`;
    const clickable = r.key != null;
    let dataAttrs = '';
    if (clickable) {
      if (opts.kind === 'identity') {
        dataAttrs = ` data-rvw-identity="${esc(r.key)}" data-rvw-scope="${esc(opts.scopeCountry || '')}"`;
      } else if (opts.kind === 'country') {
        dataAttrs = ` data-country="${esc(r.key)}"`;
      }
    }
    // Pentru barele de TARA, adaugam si un buton mic "subnete" langa
    // valoare (Eduard: "Sa vad subneturile ? care il alcatuiesc?") --
    // separat de clickul pe bara insasi, la fel ca in tabelul "Cereri
    // totale pe tara" (aceeasi functie showCountrySubnets, refolosita).
    const subnetBtn = (opts.kind === 'country' && clickable)
      ? `<button type="button" class="miniBtn rvwSubnetBtn" data-country-subnets="${esc(r.key)}" title="Vezi subnetele /24 care alcatuiesc aceasta tara">&#128269;</button>`
      : '';
    return `<div class="rvwBarRow${clickable ? ' clickable' : ''}" tabindex="0"${dataAttrs} title="${esc(r.label)}: ${esc(valTxt)}${clickable ? ' -- click pentru cererile brute' : ''}">`
      + `<span class="rvwBarLabel">${esc(r.label)}</span>`
      + `<span class="rvwBarTrack"><span class="rvwBarFill" style="width:${widthPct}%"></span></span>`
      + `<span class="rvwBarVal">${esc(valTxt)}${subnetBtn}</span></div>`;
  }).join('');
  attachDrillHandlers();
}

// Multe identitati/tari posibile -- pastram maxim 8 randuri (acelasi prag
// ca "series-count ladder" din choosing-a-form.md pt. cazul cand AR fi fost
// colorate separat) si strangem restul intr-un rand "Altele", ca sa nu
// transformam bar chart-ul intr-o lista nesfarsita greu de citit. Randul
// "Altele" nu primeste `key` -- ramane neclickabil (nu e o valoare unica
// filtrabila).
function rvwFoldTop(items, max) {
  if (items.length <= max) return items;
  const head = items.slice(0, max - 1);
  const restReq = items.slice(max - 1).reduce((a, b) => a + b.value, 0);
  const restPct = items.slice(max - 1).reduce((a, b) => a + (b.pct || 0), 0);
  head.push({ label: 'Altele', value: restReq, pct: restPct });
  return head;
}

function renderRoVsWorld(s) {
  if (!s) return;
  const ct = s.country_totals || [];
  const vals = { ro: 0, non_ro: 0, unknown: 0 };
  let allReq = 0;
  ct.forEach(r => {
    allReq += r.requests;
    const c = (r.country || '??').toUpperCase();
    if (c === 'RO') vals.ro += r.requests; else if (c === '??') vals.unknown += r.requests; else vals.non_ro += r.requests;
  });
  if (RVW_SELECTED === 'unknown' && !vals.unknown) RVW_SELECTED = 'non_ro';
  $('#cRoVsWorld').textContent = fmtNum(allReq) + ' cereri totale';

  renderRoVsWorldDonut(vals);

  const rvw = s.ro_vs_world || {};
  const bucket = rvw[RVW_SELECTED] || {};
  // key: sentinela __none__ ptr. randul fara identitate cunoscuta (asa cum
  // asteapta filtrul `identity` din /api/dataset/{id}/raw), altfel numele
  // identitatii ca atare. scopeCountry duce clickul pe partea corecta
  // (RO sau __non_ro__), la fel ca selectia curenta a donutului.
  const scopeCountry = (RVW_SIDES.find(x => x.side === RVW_SELECTED) || RVW_SIDES[1]).scope;
  const identityRows = rvwFoldTop(
    (bucket.by_identity || []).map(x => ({
      label: x.identity, value: x.requests, pct: x.pct,
      key: x.identity === 'Fara identitate cunoscuta' ? '__none__' : x.identity,
    })),
    8
  );
  $('#rvwIdentityHead').textContent = 'Compus din (' + ({ ro: 'RO', non_ro: 'NON-RO', unknown: 'tara nedeterminata' }[RVW_SELECTED] || 'NON-RO') + ') -- identitate cunoscuta';
  renderRvwBarChart('#rvwIdentityBars', identityRows, { kind: 'identity', scopeCountry });

  const countryBlock = $('#rvwCountryBlock');
  if (RVW_SELECTED === 'non_ro') {
    countryBlock.style.display = '';
    const nonRoCountries = ct.filter(r => { const c = (r.country || '??').toUpperCase(); return c !== 'RO' && c !== '??'; });
    const nonRoTotal = nonRoCountries.reduce((a, b) => a + b.requests, 0) || 1;
    const countryRows = rvwFoldTop(
      nonRoCountries
        .map(r => ({ label: r.country || '??', value: r.requests, pct: round1(100 * r.requests / nonRoTotal), key: r.country || '??' }))
        .sort((a, b) => b.value - a.value),
      8
    );
    renderRvwBarChart('#rvwCountryBars', countryRows, { kind: 'country' });
  } else {
    // RO prin definitie e doar RO -- cardul de "tari care il alcatuiesc"
    // nu are sens aici (Eduard: "doar pentru NON-RO").
    countryBlock.style.display = 'none';
  }
}
function round1(v) { return Math.round(v * 10) / 10; }

function renderSummary(s) {
  CURRENT_SUMMARY = s;
  renderKpis(s);
  refreshReport();
  renderRoVsWorld(s);
  renderInvestigationQueue(s);
  renderTimeline(s.timeline, s.timeline_granularity);
  renderStatusChart(s.status);
  renderErrorChart(s.error_timeline || []);
  renderHeatmap(s.heatmap);

  renderTableEnh('#tblBwIps', '#cBwIps', s.top_bandwidth_ips || [], r => [
    `<td class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtBytes(r.bandwidth)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`
  ], 'ip');
  $('#cBwIps').textContent = (s.top_bandwidth_ips || []).length + ' afisate';

  const totalReq = s.total || 1;
  renderTableEnh('#tblBots', '#cBots', s.bot_breakdown || [], r => [
    `<td class="mono clickable" data-bot-cat="${esc(r.category)}">${esc(r.category)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${(100 * r.requests / totalReq).toFixed(1)}%</td>`,
    `<td class="num">${fmtNum(r.unique_uas)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ]);
  $('#cBots').textContent = (s.bot_breakdown || []).length + ' categorii -- click pe o categorie pentru User-Agents exacte';

  renderTrafficComposition(s);
  renderCrawlers(s);
  pollCrawlerVerification();

  renderTableEnh('#tblIps', '#cIp', s.top_ips, r => [
    `<td class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.requests)}</td>`
  ], 'ip');

  renderTableEnh('#tblPathsRisk', '#cPathsRisk', s.top_paths_risk || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ], 'path');

  renderTableEnh('#tblPathsPopular', '#cPathsPopular', s.top_paths_popular || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}` +
      (pathHasEnumSignal(r) ? '<span class="pathSignalBadge" title="No-referer% si raport IP/cereri ambele ridicate -- semnatura de enumerare/bot">&#9888; semnal</span>' : '') +
      (() => { const sig = findSignalForPath(r.path, s); return sig ? `<span class="attackSignalBadge" data-signal-jump="1" title="${esc(sig.signal_summary || '')}">&#9888; atac real</span>` : ''; })() + `</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td class="num">${r.no_referer_pct != null ? r.no_referer_pct + '%' : '-'}</td>`,
    `<td class="num">${r.ip_request_ratio != null ? r.ip_request_ratio : '-'}</td>`
  ], 'path', r => pathHasEnumSignal(r) ? 'pathSignalRow' : '');

  renderTableEnh('#tblPathsStatic', '#cPathsStatic', s.top_paths_static || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ], 'path');

  renderBursts((s.top_bursts || []).slice(0, 3));
  renderBurstsAllTable(s.top_bursts || []);

  renderTableEnh('#tblUa', '#cUa', s.top_ua, r => [
    `<td class="clickable" data-ua="${esc(r.ua)}" style="word-break:break-all">${esc(r.ua)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ]);

  renderTableEnh('#tblSusp', '#cSusp', s.suspicious_ips, r => [
    `<td class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td><span class="tag ${r.risk}">${r.risk}</span>${crawlerClaimBadge(r.crawler_claim, [r.ip])}</td>`,
    `<td class="reasons">${r.reasons.map(esc).join('; ')}</td>`
  ], 'ip', r => crawlerClaimRowClass(r.crawler_claim, [r.ip]), 'ip', r => r.ip);

  renderTableEnh('#tblDist', '#cDist', s.distributed_enum, r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td class="num">${r.ratio}</td>`
  ], 'path');

  renderTableEnh('#tblDistPath', '#cDistPath', s.distributed_path_enum || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td class="num">${r.ratio}</td>`
  ], 'path');

  // Eduard: "da, vreau sa-l separam" -- aceeasi lista (s.top_path_prefixes,
  // cu is_static_prefix calculat in backend) e randata in DOUA tabele
  // separate, filtrata aici in JS (backend NU intoarce doua liste separate).
  // rowFn identic pentru amandoua -- doar sursa de randuri difera.
  const _pathPrefixRowFn = r => {
    const lv = r.depth_levels || [];
    const lv2 = lv[0] ? fmtNum(lv[0].requests) : '-';
    const lv3 = lv[1] ? fmtNum(lv[1].requests) : '-';
    const lv4 = lv[2] ? fmtNum(lv[2].requests) : '-';
    return [
      `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}${attackSignalBadgeHtml(r)}</td>`,
      `<td class="num">${fmtNum(r.requests)}</td>`,
      `<td class="num">${fmtNum(r.unique_ips)}</td>`,
      `<td class="num">${fmtBytes(r.bandwidth || 0)}</td>`,
      `<td class="num">${lv2}</td>`,
      `<td class="num">${lv3}</td>`,
      `<td class="num">${lv4}</td>`,
      `<td><button class="pathExploreBtn" data-explore-path="${esc(r.path)}" title="Exploreaza ierarhic sub-segmentele acestui prefix">&#128269; exploreaza</button></td>`
    ];
  };
  const _allPathPrefixes = s.top_path_prefixes || [];
  const _contentPrefixes = _allPathPrefixes.filter(r => !r.is_static_prefix);
  const _staticPrefixes = _allPathPrefixes.filter(r => r.is_static_prefix);
  renderTableEnh('#tblPathPrefix', '#cPathPrefix', _contentPrefixes, _pathPrefixRowFn, 'path', null, 'path', r => r.path);
  $('#cPathPrefixNote').textContent = 'Grupat pe primul segment de path (nu pe URL exact) -- prinde cataloage mari unde fiecare pagina are URL unic. Prag: minim 20 cereri pe prefix. Coloana Trafic arata bandwidth-ul agregat pe categorie -- util pentru "cine consuma cel mai mult trafic" la un nivel pe care poti actiona (nu 1000 de URL-uri aproape-identice). Doar prefixe de CONTINUT (nu static/infrastructura, vezi cardul separat). Bifeaza un prefix ca sa-l adaugi in regulile de blocare (coloana „Blochează”, regulile în Investigations). Badge-ul portocaliu "atac real" = acest prefix se suprapune cu un finding sau un pattern de abuz parametri CONCRET (nu doar volum mare) -- click pe el sare la tabelul sursa.';

  renderTableEnh('#tblPathPrefixStatic', '#cPathPrefixStatic', _staticPrefixes, _pathPrefixRowFn, 'path', null, 'path', r => r.path);
  $('#cPathPrefixStaticNote').textContent = 'Acelasi criteriu de grupare (prefix = primul segment de path) si acelasi prag (minim 20 cereri), dar aici doar prefixele unde cel putin 70% din cereri merg catre path-uri clasificate statice (JS/CSS/imagini/fonturi/favicon) sau echivalent -- vezi is_static_prefix.';

  // Feature #5 (audit clickability): "pattern" e path?param1=*&param2=*
  // (normalizat) -- extragem partea de path (dinainte de "?") ca sa putem
  // deschide acelasi drill-down de path ca restul tabelelor (aproximativ --
  // grupeaza toate valorile de parametri sub acelasi path, dar tot arata
  // cererile reale, mai util decat zero click behavior).
  renderTableEnh('#tblParam', '#cParam', s.param_abuse, r => [
    `<td class="mono clickable" data-path="${esc(r.pattern.split('?')[0])}" style="word-break:break-all">${esc(r.pattern)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td class="num">${r.ip_request_ratio != null ? r.ip_request_ratio : '-'}</td>`
  ], 'path');

  renderTableEnh('#tblSubnet', '#cSubnet', s.subnets, r => [
    `<td class="mono clickable" data-subnet="${esc(r.subnet)}">${esc(r.subnet)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.ips)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="reasons">${r.reasons.map(esc).join(', ')}${crawlerClaimBadge(r.crawler_claim, null)}</td>`
  ], 'subnet', null, 'subnet', r => r.subnet);

  renderTableEnh('#tblAllSubnet', '#cAllSubnet', s.all_subnets || [], r => [
    `<td class="mono clickable" data-subnet="${esc(r.subnet)}">${esc(r.subnet)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.ips)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`
  ], 'subnet', null, 'subnet', r => r.subnet);
  $('#cAllSubnetNote').textContent = 'Lista completa (nu doar cele marcate suspicious mai sus) -- prag: minim '
    + fmtNum(s.all_subnets_min_requests || 20) + ' cereri si minim ' + fmtNum(s.all_subnets_min_ips || 3) + ' IP-uri unice pe /24. Bifeaza un subnet ca sa-l adaugi in regulile de blocare (coloana „Blochează”, regulile în Investigations).';

  renderTableEnh('#tblScan', '#cScan', Object.entries(s.scan_hits).map(([k,v]) => ({sig:k, count:v})), r => [
    `<td class="mono clickable" data-sig="${esc(r.sig)}">${esc(r.sig)}</td>`, `<td class="num">${fmtNum(r.count)}</td>`
  ]);

  $('#wpAdmin').textContent = fmtNum(s.wp.wp_admin);
  $('#wpXmlrpc').textContent = fmtNum(s.wp.xmlrpc);
  $('#wpLoginPost').textContent = fmtNum(s.wp.wp_login_post);
  $('#wpCron').textContent = fmtNum(s.wp.wp_cron);
  renderTableEnh('#tblWp', '#cWp', s.wp.top_login_ips, r => [
    `<td class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.attempts)}</td>`
  ], 'ip');

  renderTableEnh('#tblWpSuccess', '#cWpSuccess', s.wp.successful_logins, r => [
    `<td class="mono clickable" data-ip="${esc(r.ip)}">${esc(r.ip)}</td>`,
    countryCell(r.country),
    `<td class="mono">${esc(r.time)}</td>`,
    `<td><span class="tag ${r.confidence === 'HIGH' ? 'HIGH' : 'LOW'}">${r.confidence === 'HIGH' ? 'CONFIRMAT' : 'NECONFIRMAT (doar 302)'}</span></td>`,
    `<td class="mono">${r.confirmed_access_at ? esc(r.confirmed_access_at) : '-'}</td>`
  ], 'ip');
  $('#cWpSuccess').textContent = (s.wp.successful_logins_confirmed != null ? `${fmtNum(s.wp.successful_logins_confirmed)} confirmate · ${fmtNum(s.wp.successful_logins_unconfirmed)} neconfirmate` : fmtNum(s.wp.successful_logins_count)) +
    (s.wp.successful_logins_count > s.wp.successful_logins.length ? ' (afisate primele ' + s.wp.successful_logins.length + ')' : '');

  const adminActivitySorted = (s.admin_activity || []).slice().sort((a, b) => {
    const aNonRo = a.country && a.country !== 'RO' ? 1 : 0;
    const bNonRo = b.country && b.country !== 'RO' ? 1 : 0;
    if (aNonRo !== bNonRo) return bNonRo - aNonRo;  // non-RO primele
    return (b.total_actions || 0) - (a.total_actions || 0);
  });
  renderTableEnh('#tblAdminActivity', '#cAdminActivity', adminActivitySorted, r => [
    `<td class="mono clickable" data-admin-ip="${esc(r.ip)}">${esc(r.ip)}${domainSuffix(r.domains)}</td>`,
    countryCell(r.country),
    `<td class="num">${fmtNum(r.total_actions)}</td>`,
    `<td>${Object.entries(r.actions).map(([k,v]) => esc(k) + ' (' + fmtNum(v) + ')').join(', ')}</td>`,
    `<td class="mono">${esc(r.first_seen)}</td>`,
    `<td class="mono">${esc(r.last_seen)}</td>`
  ], null, r => (r.country && r.country !== 'RO') ? 'nonRoRow' : '');
  const nonRoCount = adminActivitySorted.filter(r => r.country && r.country !== 'RO').length;
  $('#cAdminActivity').textContent = adminActivitySorted.length + ' IP-uri' + (nonRoCount ? (' (' + nonRoCount + ' non-RO)') : '');
  applyAdminActivityFilter();

  renderTableEnh('#tblCompromiseTrail', '#cCompromiseTrail', s.compromise_trail || [], r => [
    `<td class="mono clickable" data-trail-ip="${esc(r.ip)}">${esc(r.ip)}${domainSuffix(r.domains)}</td>`,
    countryCell(r.country),
    `<td><span class="catTag ${esc(r.dominant_category || '')}">${esc(r.dominant_category_label || '-')}</span></td>`,
    `<td class="num">${esc(String(r.risk_score))}</td>`,
    `<td style="max-width:420px">${(r.summary || []).map(esc).join('<br>')}</td>`,
    `<td class="num">${fmtNum(r.total_events)}</td>`,
    `<td class="mono">${esc(r.first_seen)}</td>`,
    `<td class="mono">${esc(r.last_seen)}</td>`
  ], null, r => (r.country && r.country !== 'RO') ? 'nonRoRow' : '');
  $('#cCompromiseTrail').textContent = (s.compromise_trail || []).length + ' IP-uri';

  const wfStatus = s.wordfence_status || {};
  const wfNote = $('#wordfenceNote');
  if (wfStatus.available) {
    wfNote.textContent = 'Cross-referentiere OPTIONALA cu baza publica de vulnerabilitati Wordfence (' + fmtNum(wfStatus.slug_count) + ' plugin-uri/teme cunoscute in cache). Un rand aici inseamna ca acel plugin/tema ARE vulnerabilitati cunoscute -- NU inseamna ca versiunea instalata e neaparat afectata (access log-ul nu arata versiunea) si NU inseamna exploatare confirmata.';
  } else {
    wfNote.textContent = 'Indisponibil momentan (' + (wfStatus.last_error ? ('eroare: ' + wfStatus.last_error) : 'nu s-a descarcat inca baza de date') + '). Optional si best-effort -- restul dashboard-ului nu e afectat.';
  }
  renderTableEnh('#tblWordfence', '#cWordfence', s.wordfence_matches || [], r => [
    `<td class="mono clickable" data-path="wp-content/${esc(r.type)}s/${esc(r.slug)}/">${esc(r.slug)}</td>`,
    `<td>${esc(r.type)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td>${(r.known_vuln_titles || []).map(esc).join('; ')}</td>`
  ]);
  $('#cWordfence').textContent = (s.wordfence_matches || []).length + ' plugin-uri/teme';

  (s.findings || []).forEach((f, i) => { f._idx = i; });
  renderTableEnh('#tblFindings', null, s.findings, r => [
    `<td><span class="tag ${r.severity}">${r.severity}</span></td>`,
    `<td>${esc(r.rule)}</td>`,
    `<td class="findingDetailCell" data-finding-idx="${r._idx}" style="word-break:break-all">` +
      `<span class="findingToggle" data-finding-idx="${r._idx}" data-finding-source="findings" title="Arata/ascunde explicatia (de ce a aparut + evidence)">&#9656;</span> ${esc(r.detail)}</td>`,
    `<td class="mono">${esc(r.time || '')}</td>`,
    `<td>${findingDrillCell(r)}</td>`
  ]);
  {
    const fst = TBL_STATE['#tblFindings'];
    const shownN = fst && fst.limit !== 'all' ? Math.min(fst.limit, s.findings.length) : s.findings.length;
    $('#cFindings').textContent = fmtNum(s.findings_count) + (s.findings_count > shownN ? ' (afisate ' + fmtNum(shownN) + ')' : '');
  }

  // --- Anomalii (Faza 2) -- semnal mai slab/statistic, sectiune separata
  // JOS pe pagina (vezi #anomaliesCard), stil mai discret (fara CRITICAL/
  // HIGH -- vezi backend: anomaliile sunt plafonate la MEDIUM in jos).
  (s.anomalies || []).forEach((a, i) => { a._idx = i; });
  renderTableEnh('#tblAnomalies', null, s.anomalies || [], r => [
    `<td><span class="tag ${r.severity}">${r.severity}</span></td>`,
    `<td>${esc(r.rule)}</td>`,
    `<td class="findingDetailCell" data-finding-idx="${r._idx}" style="word-break:break-all">` +
      `<span class="findingToggle" data-finding-idx="${r._idx}" data-finding-source="anomalies" title="Arata/ascunde explicatia (de ce a aparut + evidence)">&#9656;</span> ${esc(r.detail)}</td>`,
    `<td><span class="confidencePill">${esc(r.confidence || '-')}</span></td>`,
    `<td>${findingDrillCell(r)}</td>`
  ]);
  {
    const anomalies = s.anomalies || [];
    const ast = TBL_STATE['#tblAnomalies'];
    const shownN = ast && ast.limit !== 'all' ? Math.min(ast.limit, anomalies.length) : anomalies.length;
    $('#cAnomalies').textContent = fmtNum(s.anomalies_count || anomalies.length) +
      ((s.anomalies_count || anomalies.length) > shownN ? ' (afisate ' + fmtNum(shownN) + ')' : '');
  }

  renderQueryParams(s.query_params || {});

  renderTableEnh('#tblPathsDynamic', '#cPathsDynamic', s.top_paths_dynamic || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ], 'path');

  renderTableEnh('#tblPath404', '#cPath404', s.top_paths_404 || [], r => [
    `<td class="mono clickable" data-path="${esc(r.path)}" style="word-break:break-all">${esc(r.path)}</td>`,
    `<td class="num">${fmtNum(r.count_404)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${r.rate_404}%</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`
  ], 'path');

  // Feature (Eduard): fiecare tara e acum clickable -- deschide cererile
  // BRUTE facute din acea tara (vezi filtrul "country" din
  // /api/dataset/{id}/raw, care recalculeaza country_of(ip) per linie in
  // scanarea on-demand deja existenta -- acelasi tipar ca ip/path/ua/qkey).
  renderTableEnh('#tblCountry', '#cCountry', s.country_totals || [], r => [
    r.country ? `<td class="clickable" data-country="${esc(r.country)}" title="${esc(r.country)}">${flagEmoji(r.country)} ${esc(r.country)}</td>` : '<td class="reasons">-</td>',
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${r.pct}%</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td><button type="button" class="miniBtn" data-country-subnets="${esc(r.country || '??')}" title="Vezi subnetele /24 care alcatuiesc aceasta tara">&#128269; subnete</button></td>`
  ]);

  attachDrillHandlers();

  // Daca Path Explorer-ul era deja deschis pe un prefix (zi/interval
  // schimbate de sub el), reincarca-l pentru noua selectie -- altfel ar
  // ramane sa arate date stale de la ziua anterioara.
  if ($('#pathExplorerTableWrap') && $('#pathExplorerTableWrap').style.display === 'block') {
    loadPathExplorer();
  }
}

// KPI overview reorganizat (Faza 1): ordinea si setul cerut de Eduard --
// Total cereri, IP unice, Path-uri unice, Bandwidth, Bursturi (+ detaliu
// inline al celui mai mare burst), 4xx, 5xx, Findings. Stil NEUTRU pentru
// toate tile-urile de trafic -- coloram (cls 'warn') NUMAI tile-ul de
// Findings, si NUMAI cand findings_count > 0 (Eduard s-a plans explicit de
// supra-colorare -- vezi spec). Linii neparsabile ramane in nota de sub
// tabelul de findings, nu mai e KPI separat (zgomot pentru un numar de obicei 0).
function renderKpis(s) {
  const b0 = (s.top_bursts && s.top_bursts.length) ? s.top_bursts[0] : null;
  const burstSub = b0
    ? `${fmtNum(b0.requests)} cereri / ${fmtNum(b0.unique_ips)} IP / ${esc(b0.label)}`
    : 'Fara burst semnificativ';
  const items = [
    { lbl: 'Total cereri', val: fmtNum(s.total) },
    { lbl: 'IP-uri unice', val: fmtNum(s.unique_ips) },
    { lbl: 'Path-uri unice', val: fmtNum(s.unique_paths) },
    { lbl: 'Bandwidth', val: fmtBytes(s.bandwidth) },
    { lbl: 'Bursturi (30s, cel mai mare)', val: fmtNum(s.burst_window_count), sub: burstSub },
    { lbl: 'Erori 4xx', val: fmtNum(s.status['4xx']) },
    { lbl: 'Erori 5xx', val: fmtNum(s.status['5xx']) },
    { lbl: 'Findings', val: fmtNum(s.findings_count), cls: s.findings_count > 0 ? 'warn' : '' },
  ];
  $('#kpis').innerHTML = items.map(i =>
    `<div class="kpi ${i.cls||''}"><div class="val">${i.val}</div><div class="lbl">${i.lbl}</div>${i.sub ? `<div class="sub">${i.sub}</div>` : ''}</div>`
  ).join('');
}

function renderTimeline(timeline, granularity) {
  $('#timelineTitle').textContent = granularity === 'minute'
    ? 'Trafic in timp (pe minute -- interval scurt selectat)'
    : granularity === 'hour'
    ? 'Trafic in timp (pe ore -- o singura zi in log)'
    : 'Trafic in timp (pe zile)';
  const ctx = $('#timelineChart').getContext('2d');
  const labels = (timeline || []).map(t => t.day);
  const data = (timeline || []).map(t => t.requests);
  if (timelineChart) timelineChart.destroy();
  if (!timeline || !timeline.length) {
    // canvas gol -- fara date de trafic in timp (poate fisierul e prea mic
    // sau timestamp-urile nu s-au putut parsa)
    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
    return;
  }
  // un singur punct pe grafic de linie nu se vede -- fortam un punct vizibil
  const singlePoint = data.length === 1;
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{
      label: 'Cereri', data,
      borderColor: '#0B6E73', backgroundColor: 'rgba(11,110,115,.10)',
      fill: true, tension: .25,
      pointRadius: singlePoint ? 6 : 2, pointHoverRadius: 6,
    }] },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#5D6A79' }, grid: { color: '#E4E8EE' } },
        y: { ticks: { color: '#5D6A79' }, grid: { color: '#E4E8EE' }, beginAtZero: true },
      }
    }
  });
}

function renderStatusChart(status) {
  const ctx = $('#statusChart').getContext('2d');
  const labels = ['2xx', '3xx', '4xx', '5xx'];
  const data = [status['2xx'], status['3xx'], status['4xx'], status['5xx']];
  if (statusChart) statusChart.destroy();
  statusChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: ['#2E9E6B', '#3A6FD8', '#E08A1E', '#D2384C'] }] },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#15212E' } } }
    }
  });
}

let errorChart = null;
function renderErrorChart(errorTimeline) {
  const ctx = $('#errorChart').getContext('2d');
  const labels = (errorTimeline || []).map(t => t.day);
  const d4 = (errorTimeline || []).map(t => t['4xx']);
  const d5 = (errorTimeline || []).map(t => t['5xx']);
  if (errorChart) errorChart.destroy();
  if (!errorTimeline || !errorTimeline.length) {
    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
    return;
  }
  const singlePoint = labels.length === 1;
  errorChart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [
      { label: '4xx', data: d4, borderColor: '#E08A1E', backgroundColor: 'rgba(224,138,30,.10)', fill: true, tension: .25, pointRadius: singlePoint ? 6 : 2 },
      { label: '5xx', data: d5, borderColor: '#D2384C', backgroundColor: 'rgba(210,56,76,.10)', fill: true, tension: .25, pointRadius: singlePoint ? 6 : 2 },
    ] },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#15212E' } } },
      scales: {
        x: { ticks: { color: '#5D6A79' }, grid: { color: '#E4E8EE' } },
        y: { ticks: { color: '#5D6A79' }, grid: { color: '#E4E8EE' }, beginAtZero: true },
      }
    }
  });
}

function heatColor(v, max) {
  if (!v || !max) return 'transparent';
  const ratio = Math.min(1, v / max);
  // v46: scala secventiala luminoasa (de la gri-albastrui la petrol)
  const t = Math.sqrt(ratio);
  const mix = (a, b) => Math.round(a + (b - a) * t);
  return `rgb(${mix(236, 11)},${mix(242, 110)},${mix(243, 115)})`;
}

function renderHeatmap(hm) {
  const wrap = $('#heatmapWrap');
  if (!hm || !hm.rows || !hm.rows.length) { wrap.innerHTML = '<div class="empty">Fara date</div>'; return; }
  let max = 0;
  hm.rows.forEach(row => Object.values(row.hours).forEach(v => { if (v > max) max = v; }));
  let html = '<table class="heatmap-table"><thead><tr><th>Zi</th>';
  hm.hours.forEach(h => html += `<th>${h}</th>`);
  html += '</tr></thead><tbody>';
  hm.rows.forEach(row => {
    html += `<tr><td style="color:var(--text);text-align:left">${row.day}</td>`;
    hm.hours.forEach(h => {
      const v = row.hours[h] || 0;
      html += `<td style="background:${heatColor(v, max)}${v ? ';cursor:pointer' : ''}${max && Math.sqrt(v / max) > .55 ? ';color:#fff' : ''}" title="${row.day} ${h}:00 -> ${v}${v ? ' -- click: perioada globala = aceasta ora' : ''}"${v ? ` data-hm-day="${row.day}" data-hm-h="${h}"` : ''}>${v || ''}</td>`;
    });
    html += '</tr>';
  });
  html += '</tbody></table>';
  wrap.innerHTML = html;
}

// Clasificare de burst (Faza 2, vezi app.py: classify_burst) -> clasa CSS
// de badge restransa (neutru/albastru/galben/portocaliu/rosu -- niciodata
// totul rosu, vezi cerinta lui Eduard din spec).
const BURST_CLASS_CSS = {
  'Normal': 'bcNormal', 'Crawler': 'bcCrawler', 'Distributed crawl': 'bcDistributed',
  'Suspicious automation': 'bcSuspicious', 'Security scan': 'bcScan', 'Unknown': 'bcUnknown',
};
function renderBursts(bursts) {
  $('#cBurst').textContent = bursts.length ? bursts.length + ' gasite' : '';
  const grid = $('#burstGrid');
  if (!bursts.length) { grid.innerHTML = '<div class="empty">Fara date suficiente pentru detectia de bursturi.</div>'; return; }
  grid.innerHTML = bursts.map((b, i) => `
    <div class="burst-card">
      <div class="rank">#${i + 1}</div>
      <div class="label">${esc(b.label)}</div>
      <div class="big">${fmtNum(b.requests)} <span style="font-size:12px;color:var(--text-dim);font-weight:400">cereri / 30s</span></div>
      <div class="sub">${fmtNum(b.unique_ips)} IP-uri unice</div>
      ${b.classification ? `<div class="burstClass ${BURST_CLASS_CSS[b.classification] || 'bcUnknown'}" title="${esc(b.classification_reason || '')}">${esc(b.classification)}</div>` : ''}
      ${b.classification_reason ? `<div class="reasonText" style="margin-top:4px">${esc(b.classification_reason)}</div>` : ''}
      <div class="countries">${(b.top_countries || []).map(c => `<span>${flagEmoji(c.country)} ${esc(c.country)} (${fmtNum(c.count)})</span>`).join('') || '<span>Tara necunoscuta</span>'}</div>
      <button data-burst="${esc(b.burst_key)}" data-label="${esc(b.label)}">Vezi cererile complete din burst</button>
    </div>
  `).join('');
  grid.querySelectorAll('[data-burst]').forEach(btn => {
    btn.onclick = () => drillBurst(btn.dataset.burst, btn.dataset.label);
  });
}

// Feature #3 (Eduard): "vrea sa vada mai multe bursturi si detalii despre
// ele" -- tabel COMPLET (nu doar top 3), sortabil/cu limita de randuri ca
// restul dashboard-ului, sub cardul cu cele 3 carduri "la prima vedere"
// (care raman -- sunt utile ca rezumat rapid). Fiecare rand e clickable,
// deschide acelasi drill-down de linii brute ca butonul din carduri.
function renderBurstsAllTable(bursts) {
  renderTableEnh('#tblBurstAll', '#cBurstAll', bursts || [], r => [
    `<td class="mono clickable" data-burst-key="${esc(r.burst_key)}" data-burst-label="${esc(r.label)}">${esc(r.label)}</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td>${r.classification ? `<span class="burstClass ${BURST_CLASS_CSS[r.classification] || 'bcUnknown'}" title="${esc(r.classification_reason || '')}">${esc(r.classification)}</span>` : '-'}</td>`,
    `<td>${(r.top_countries || []).map(c => `${flagEmoji(c.country)} ${esc(c.country)} (${fmtNum(c.count)})`).join(', ') || '-'}</td>`
  ]);
}

// --- LAST_DRILL retine ULTIMUL drill-down brut (IP/path/subnet/moment/
// burst) ca sa poata fi reincarcat cu o alta limita din picker-ul din modal
// (#modalLimitSel + #modalRefetch), fara sa inchida modalul -- vezi
// showModalRawToolbar/hideModalRawToolbar mai jos.
let LAST_DRILL = null; // { kind: 'raw'|'burst', params/burstKey, title }

// v45: fereastra modala de drilldown e legata de selectia globala: afiseaza
// selectia aplicata, se reincarca singura cand selectia se schimba, iar un
// raspuns depasit (MODAL_SEQ) nu mai poate suprascrie unul mai nou.
let MODAL_SEQ = 0;
let MODAL_REFRESH = null;
function showModalRawToolbar() { $('#modalRawToolbar').style.display = 'flex'; MODAL_REFRESH = () => $('#modalRefetch').click(); }
function hideModalRawToolbar() { $('#modalRawToolbar').style.display = 'none'; LAST_DRILL = null; MODAL_REFRESH = null; }
function modalEmptyHtml() {
  return '<div class="empty">Nicio linie gasita' + (typeof gfIsActive === 'function' && gfIsActive()
    ? ' in selectia curenta (' + tEsc(gfDescribe()) + '). Fereastra NU revine la tot logul: largeste perioada sau scoate filtre.'
    : '.') + '</div>';
}
function modalIsOpen() { return $('#modalOverlay').style.display === 'flex'; }
function modalUpdateScope() {
  const el = $('#modalScope');
  if (!el) return;
  const d = (typeof gfDescribe === 'function' && typeof TRIAGE !== 'undefined' && TRIAGE.ready) ? gfDescribe() : 'tot logul';
  el.innerHTML = d === 'tot logul' ? 'Selectie globala: <b>tot logul</b>' : `Doar in selectia globala: <b>${esc(d)}</b> -- se actualizeaza automat cand o schimbi.`;
}

async function drillBurst(burstKey, label) {
  const mseq = ++MODAL_SEQ;
  if (!DATASET_ID) return;
  LAST_DRILL = { kind: 'burst', burstKey, title: label };
  showModalRawToolbar();
  $('#modalTitle').textContent = 'Burst: ' + label;
  $('#modalBody').innerHTML = '<div class="empty"><span class="spinner"></span> Se incarca liniile brute...</div>';
  $('#modalOverlay').style.display = 'flex';
  const limit = $('#modalLimitSel') ? $('#modalLimitSel').value : '2000';
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/burst_raw?burst_key=${encodeURIComponent(burstKey)}&limit=${encodeURIComponent(limit)}`));
    const data = await resp.json();
    if (mseq !== MODAL_SEQ) return;
    if (!resp.ok) throw new Error(data.error || 'eroare');
    if (!data.matches.length) {
      $('#modalBody').innerHTML = modalEmptyHtml();
      return;
    }
    let html = `<div class="note">${data.matches.length} linii${data.truncated ? (' (trunchiat la limita aleasa: ' + fmtNum(data.limit || limit) + ')') : ''}</div>`;
    html += data.matches.map(m => `<pre>${esc(m.raw)}</pre>`).join('');
    $('#modalBody').innerHTML = html;
  } catch (e) {
    $('#modalBody').innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
  }
}

$('#modalRefetch').addEventListener('click', () => {
  if (!LAST_DRILL) return;
  if (LAST_DRILL.kind === 'burst') { drillBurst(LAST_DRILL.burstKey, LAST_DRILL.title); }
  else if (LAST_DRILL.kind === 'window') { drillWindowRaw(LAST_DRILL.params, LAST_DRILL.title); }
  else if (LAST_DRILL.kind === 'ipov_extract') { const q = new URLSearchParams(LAST_DRILL.qs); q.set('limit', $('#modalLimitSel').value); ipovExtractFetch(q.toString(), LAST_DRILL.title); }
  else { drillDownRaw(LAST_DRILL.params, LAST_DRILL.title); }
});
$('#modalLimitSel').addEventListener('change', () => { if (LAST_DRILL) $('#modalRefetch').click(); });

// ==========================================================================
// Explorator de loguri (Eduard): panou separat -- alege o zi + marime de
// fereastra (30s/60s/10min), combina oricate din cele ~11 filtre din
// #explorerCard, "Analizeaza" scaneaza O SINGURA DATA (vezi /api/dataset/
// {id}/windows, backend app.py) si intoarce TOATE ferestrele cu cel putin o
// cerere care trece de filtre -- sortarea/"Arata N" de mai jos se aplica
// DOAR pe rezultatul deja incarcat (EXP_STATE.windows), fara sa mai
// re-interogheze serverul, exact ca sa poti trece instant intre "cel mai
// concentrat" / "top IP-uri unice" / "primele" / "ultimele" (cerinta lui
// Eduard) fara sa astepti un scan nou de fiecare data.
// ==========================================================================
let EXP_STATE = null; // { windows, day, window_seconds, filters, filtersLabel }

function _expGatherFilters() {
  const val = id => { const el = $(id); return el ? el.value.trim() : ''; };
  const params = {};
  const ip = val('#expFIp'); if (ip) params.ip = ip;
  const subnet = val('#expFSubnet'); if (subnet) params.subnet = subnet;
  const path = val('#expFPath'); if (path) params.path = path;
  const method = val('#expFMethod'); if (method) params.method = method;
  const statusClass = val('#expFStatusClass'); if (statusClass) params.status_class = statusClass;
  const status = val('#expFStatus'); if (status) params.status = status;
  const ua = val('#expFUa'); if (ua) params.ua = ua;
  const hasQuery = val('#expFHasQuery'); if (hasQuery) params.has_query = hasQuery;
  const refEmpty = val('#expFRefererEmpty'); if (refEmpty) params.referer_empty = refEmpty;
  const country = val('#expFCountry'); if (country) params.country = country;
  const identity = val('#expFIdentity'); if (identity) params.identity = identity;
  const pattern = val('#expFPattern'); if (pattern) params.pattern = pattern;
  const qkey = val('#expFQkey'); if (qkey) params.qkey = qkey;
  return params;
}

function _expFiltersSummaryLabel(filters) {
  const parts = Object.entries(filters).map(([k, v]) => `${k}=${v}`);
  return parts.length ? parts.join(', ') : 'fara filtre (tot traficul)';
}

// Rubricile de procentaj (Eduard: "o rubrica cu procentaj user agent /
// crawler" + "o rubrica cu procentaje subnets") -- backend-ul (vezi
// ua_breakdown/subnet16_breakdown in /api/dataset/{id}/windows) intoarce
// lista COMPLETA sortata descrescator; aici o transformam in randurile
// asteptate de renderRvwBarChart (acelasi bar-chart deja folosit la "RO vs
// restul lumii") si strangem top 8 + "Altele", ca sa nu umplem panoul cu
// zeci de randuri marunte.
function _breakdownToRows(items, labelKey) {
  return (items || []).map(x => ({ label: x[labelKey], value: x.requests, pct: x.pct }));
}

function renderExpBreakdowns(data) {
  const box = $('#expBreakdowns');
  if (!data || !data.total_matching_requests) { box.style.display = 'none'; return; }
  box.style.display = 'grid';
  renderRvwBarChart('#expUaBars', rvwFoldTop(_breakdownToRows(data.ua_breakdown, 'category'), 8), {});
  renderRvwBarChart('#expSubnetBars', rvwFoldTop(_breakdownToRows(data.subnet16_breakdown, 'subnet'), 8), {});
}

$('#expClearBtn').addEventListener('click', () => {
  ['#expFIp', '#expFSubnet', '#expFPath', '#expFStatus', '#expFUa', '#expFCountry', '#expFIdentity', '#expFQkey']
    .forEach(sel => { const el = $(sel); if (el) el.value = ''; });
  ['#expFMethod', '#expFStatusClass', '#expFHasQuery', '#expFRefererEmpty', '#expFPattern']
    .forEach(sel => { const el = $(sel); if (el) el.value = ''; });
});

$('#expAnalyzeBtn').addEventListener('click', async () => {
  if (!DATASET_ID) return;
  const day = $('#expDay').value;
  const windowSeconds = $('#expWindowSeconds').value;
  const filters = _expGatherFilters();
  const qs = new URLSearchParams({ window_seconds: windowSeconds, ...filters });
  if (day) qs.set('day', day);
  const resultsEl = $('#expResults');
  const summaryEl = $('#expResultsSummary');
  resultsEl.innerHTML = '<div class="empty"><span class="spinner"></span> Se scaneaza logul cu filtrele alese...</div>';
  summaryEl.style.display = 'none';
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/windows?${qs.toString()}`));
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'eroare');
    EXP_STATE = {
      windows: data.windows || [], day, window_seconds: parseInt(windowSeconds, 10), filters,
      filtersLabel: _expFiltersSummaryLabel(filters),
    };
    summaryEl.style.display = 'block';
    summaryEl.textContent = `${fmtNum(data.total_matching_requests)} cereri potrivite, in ${fmtNum(data.total_windows)} ferestre de ${windowSeconds === '600' ? '10 min' : windowSeconds + ' sec'} (${day || 'tot fisierul'}) -- filtre: ${EXP_STATE.filtersLabel}`;
    renderExpResults();
    renderExpBreakdowns(data);
  } catch (e) {
    resultsEl.innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
    $('#expBreakdowns').style.display = 'none';
  }
});

$('#expSort').addEventListener('change', renderExpResults);
$('#expRowLimit').addEventListener('change', renderExpResults);

function renderExpResults() {
  const resultsEl = $('#expResults');
  if (!EXP_STATE || !EXP_STATE.windows.length) {
    resultsEl.innerHTML = EXP_STATE ? '<div class="empty">Nicio fereastra nu se potriveste cu filtrele alese.</div>' : '';
    return;
  }
  const sortMode = $('#expSort').value;
  const sorted = EXP_STATE.windows.slice();
  if (sortMode === 'requests') sorted.sort((a, b) => b.requests - a.requests);
  else if (sortMode === 'unique_ips') sorted.sort((a, b) => b.unique_ips - a.unique_ips || b.unique_ip_ratio - a.unique_ip_ratio);
  else if (sortMode === 'time_asc') sorted.sort((a, b) => a.bucket_start_seconds - b.bucket_start_seconds);
  else if (sortMode === 'time_desc') sorted.sort((a, b) => b.bucket_start_seconds - a.bucket_start_seconds);
  const limitVal = $('#expRowLimit').value;
  const shown = limitVal === 'all' ? sorted : sorted.slice(0, parseInt(limitVal, 10));

  let html = '<div class="scroll-y" style="max-height:420px"><table><thead><tr>' +
    '<th>Interval</th><th class="num">Cereri</th><th class="num">IP unice</th><th class="num">Raport IP/cereri</th><th></th>' +
    '</tr></thead><tbody>';
  shown.forEach(w => {
    const ratioTag = w.unique_ip_ratio >= 0.7 ? 'HIGH' : (w.unique_ip_ratio <= 0.15 ? 'LOW' : 'INFO');
    html += `<tr class="clickableRow" data-bucket="${w.bucket_start_seconds}">` +
      `<td class="mono">${esc(EXP_STATE.day || 'toate zilele')} ${esc(w.start_label)} - ${esc(w.end_label)}</td>` +
      `<td class="num">${fmtNum(w.requests)}</td>` +
      `<td class="num">${fmtNum(w.unique_ips)}</td>` +
      `<td class="num"><span class="tag ${ratioTag}">${w.unique_ip_ratio}</span></td>` +
      `<td><button class="explorerActionBtn" data-bucket-open="${w.bucket_start_seconds}">&#128269; vezi tot</button></td>` +
      `</tr>`;
  });
  html += '</tbody></table></div>';
  if (limitVal !== 'all' && sorted.length > shown.length) {
    html += `<div class="note">Arata primele ${shown.length} din ${sorted.length} ferestre care se potrivesc -- schimba "Arata" ca sa vezi mai multe.</div>`;
  }
  resultsEl.innerHTML = html;
  resultsEl.querySelectorAll('[data-bucket-open]').forEach(el => {
    el.onclick = (e) => {
      e.stopPropagation();
      const w = EXP_STATE.windows.find(x => String(x.bucket_start_seconds) === el.dataset.bucketOpen);
      if (w) _expOpenWindow(w);
    };
  });
  resultsEl.querySelectorAll('tr[data-bucket]').forEach(tr => {
    tr.onclick = () => {
      const w = EXP_STATE.windows.find(x => String(x.bucket_start_seconds) === tr.dataset.bucket);
      if (w) _expOpenWindow(w);
    };
  });
}

function _expOpenWindow(w) {
  const label = `${EXP_STATE.day || 'toate zilele'} ${w.start_label} - ${w.end_label} (${EXP_STATE.filtersLabel})`;
  const params = { ...EXP_STATE.filters, window_seconds: EXP_STATE.window_seconds, bucket_start: w.bucket_start_seconds };
  if (EXP_STATE.day) params.day = EXP_STATE.day;
  drillWindowRaw(params, label);
}

async function drillWindowRaw(params, title) {
  const mseq = ++MODAL_SEQ;
  if (!DATASET_ID) return;
  LAST_DRILL = { kind: 'window', params: { ...params }, title };
  showModalRawToolbar();
  const limit = $('#modalLimitSel') ? $('#modalLimitSel').value : '2000';
  const qs = new URLSearchParams({ ...params, limit }).toString();
  $('#modalTitle').textContent = 'Explorator: ' + title;
  $('#modalBody').innerHTML = '<div class="empty"><span class="spinner"></span> Se incarca liniile brute...</div>';
  $('#modalOverlay').style.display = 'flex';
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/window_raw?${qs}`));
    const data = await resp.json();
    if (mseq !== MODAL_SEQ) return;
    if (!resp.ok) throw new Error(data.error || 'eroare');
    if (!data.matches.length) {
      $('#modalBody').innerHTML = modalEmptyHtml();
      return;
    }
    let html = `<div class="note">${data.matches.length} linii${data.truncated ? (' (trunchiat la limita aleasa: ' + fmtNum(data.limit || limit) + ')') : ''}</div>`;
    html += data.matches.map(m => `<pre>${esc(m.raw)}</pre>`).join('');
    $('#modalBody').innerHTML = html;
  } catch (e) {
    $('#modalBody').innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
  }
}

// ==========================================================================
// PREZENTARE (pagina principala, v42) -- verdict automat, KPI-uri, timeline,
// rubrici clickabile (linii brute / filtru / blocare), reguli de blocare
// (CSF / Imunify360 / .htaccess / Cloudflare), raport gata de trimis
// (client / tehnic / scurt, export txt/html/pdf), comparatie intre doua
// intervale, extractie linii brute. Date: /api/dataset/{id}/ip_overview
// (cache per zi+interval pe server), /ip_compare, /extract_raw.
// ==========================================================================
let IPOV = null;
let IPOV_SCOPE = { day: '', start: '', end: '' };
let IPOV_ACTIVE = null;          // { type, key, label }
let IPOV_BLOCK = [];             // [{ type, key, label, ips? }]
let IPOV_TL_CHART = null;
let IPOV_POLL_T = null;
let IPOV_EXPANDED = {};          // rubrica -> arata toate randurile
const IPOV_FOLD = 8;
let IPOV_STALE = true;           // v44: de recalculat la urmatoarea afisare a paginii
let IPOV_SEQ = 0;                // v44: raspunsurile depasite de o cerere noua sunt ignorate
let IPOV_GF_KEY = '';            // filtrele globale cu care s-a calculat IPOV

// v44: pagina Prezentare foloseste propriul interval (zi + ora), dar aplica
// filtrele globale de CONTINUT (tara, IP, cod, URL, UA, severitate, actiune)
// -- aceeasi selectie ca panoul inferior si celelalte taburi.
// v45: Prezentare foloseste ACEEASI selectie (perioada inclusa) ca restul
// aplicatiei; campurile zi/ora de pe pagina sunt doar un alt mod de a seta
// perioada globala (si se sincronizeaza cu ea).
function gfContentParams() { return (typeof gfParams === 'function') ? gfParams() : new URLSearchParams(); }
function ipovEnsureFresh() {
  if (!DATASET_ID) return;
  if (IPOV_STALE || IPOV_GF_KEY !== gfContentParams().toString()) ipovAnalyze();
}
function _dayHmsToEpoch(day, hms) {
  const m = /^(\d{2})\/(\w{3})\/(\d{4})$/.exec(day || '');
  const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  if (!m || !(m[2] in MON)) return null;
  const [h, mi, se] = (hms || '00:00:00').split(':').map(x => parseInt(x, 10) || 0);
  return Math.floor(Date.UTC(+m[3], MON[m[2]], +m[1], h, mi, se) / 1000) - TRIAGE.tzOffset;
}
function ipovApplyInputs() {
  if (!TRIAGE.ready) { ipovAnalyze(); return; }
  const day = $('#ipovDay').value, st = $('#ipovStart').value, en = $('#ipovEnd').value;
  if (!day && !st && !en) { triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo); ipovEnsureFresh(); return; }
  if (!day) { $('#ipovSummary').style.display = 'block'; $('#ipovSummary').textContent = 'Alege o zi pentru un interval orar (sau foloseste histograma din Triaj / campurile de data din bara de filtre pentru intervale pe mai multe zile).'; return; }
  const a = _dayHmsToEpoch(day, st ? (st.length === 5 ? st + ':00' : st) : '00:00:00');
  const b = _dayHmsToEpoch(day, en ? (en.length === 5 ? en + ':59' : en) : '23:59:59');
  if (a == null || b == null || b < a) { $('#ipovSummary').textContent = 'Interval invalid.'; return; }
  triageSetRange(a, b);
  ipovEnsureFresh();
}
// campurile paginii reflecta perioada globala curenta
function ipovSyncInputs() {
  if (!TRIAGE.ready || TRIAGE.tsFrom == null) return;
  if (!gfTimeNarrowed()) { $('#ipovDay').value = ''; $('#ipovStart').value = ''; $('#ipovEnd').value = ''; return; }
  const A = epochToDtLocalStr(TRIAGE.tsFrom), B = epochToDtLocalStr(TRIAGE.tsTo);
  if (A.slice(0, 11) === B.slice(0, 11) && [...$('#ipovDay').options].some(o => o.value === A.slice(0, 11))) {
    $('#ipovDay').value = A.slice(0, 11); $('#ipovStart').value = A.slice(12, 20); $('#ipovEnd').value = B.slice(12, 20);
  } else { $('#ipovDay').value = ''; $('#ipovStart').value = ''; $('#ipovEnd').value = ''; }
}
function ipovRenderGfBanner(gfKey) {
  const el = $('#ipovGfBanner');
  if (!el) return;
  if (!gfKey) { el.style.display = 'none'; el.textContent = ''; return; }
  const d = (typeof gfDescribe === 'function') ? gfDescribe() : gfKey;
  el.style.display = 'block';
  el.innerHTML = `&#9881; Rubricile, verdictul si raportul de mai jos sunt calculate DOAR pentru selectia globala: <b>${esc(d)}</b>.` +
    ` <a href="#" id="ipovGfClear">Reseteaza filtrele globale</a>`;
  const a = $('#ipovGfClear');
  if (a) a.onclick = (e) => { e.preventDefault(); $('#triageResetBtn').click(); };
}

function ipovTs(t) { return t ? t.replace(/^(\d\d\/\w{3}\/\d{4}):/, '$1 ').replace(/ [+-]\d{4}$/, '') : '-'; }
function ipovDur(sec) {
  if (!sec) return '-';
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + 'z ' : '') + (d || h ? h + 'h ' : '') + m + 'min';
}
function ipovScopeParams(scope) {
  if (!scope) return {};   // v45: perioada paginii = selectia globala, trimisa in gf
  const s = scope, p = {};
  if (s.day) p.day = s.day;
  if (s.start) p.start = s.start;
  if (s.end) p.end = s.end;
  return p;
}
function downloadFile(name, content, mime) {
  if (REDACT && typeof content === 'string') {
    content = redactClientText(content);
    name = name.replace(/(\.[^.]+)$/, '_redactat$1');
  }
  const blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
function csvCell(v) { const s = v == null ? '' : String(v); return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }

$('#ipovClearBtn').addEventListener('click', () => { $('#ipovDay').value = ''; $('#ipovStart').value = ''; $('#ipovEnd').value = ''; ipovApplyInputs(); });
$('#ipovAnalyzeBtn').addEventListener('click', () => ipovApplyInputs());

function ipovSetScope(day, start, end) {
  if (day !== undefined) $('#ipovDay').value = day;
  $('#ipovStart').value = start || '';
  $('#ipovEnd').value = end || '';
  ipovApplyInputs();
}
function _secToHms(s) { s = Math.max(0, Math.min(86399, s)); return [Math.floor(s / 3600), Math.floor(s % 3600 / 60), s % 60].map(x => String(x).padStart(2, '0')).join(':'); }
function _hmsToSec(t) { const [h, m, s] = t.split(':').map(Number); return h * 3600 + m * 60 + (s || 0); }

document.addEventListener('click', (e) => {
  const b = e.target.closest('.ipovPreset');
  if (!b || !IPOV || !IPOV.last_seen) return;
  const preset = b.dataset.preset;
  if (preset === 'peak') {
    if (!IPOV.peak_minute) return;
    const day = IPOV.peak_minute.slice(0, 11), hm = IPOV.peak_minute.slice(12, 17);
    const sec = _hmsToSec(hm + ':00');
    ipovSetScope(day, _secToHms(sec - 300), _secToHms(sec + 359));
    return;
  }
  const day = IPOV.last_seen.slice(0, 11), t = IPOV.last_seen.slice(12, 20);
  const endSec = _hmsToSec(t), span = preset === 'last10' ? 600 : 3600;
  ipovSetScope(day, _secToHms(endSec - span + 1), _secToHms(endSec));
});

async function ipovAnalyze(isPoll) {
  if (!DATASET_ID) return;
  const seq = ++IPOV_SEQ;
  IPOV_STALE = false;
  ipovSyncInputs();
  IPOV_SCOPE = { day: '', start: '', end: '' };   // perioada vine din selectia globala (gf)
  const gfp = gfContentParams();
  const gfKey = gfp.toString();
  const qs = new URLSearchParams(gfp);
  const summaryEl = $('#ipovSummary');
  if (!isPoll) {
    summaryEl.style.display = 'block';
    summaryEl.innerHTML = '<span class="spinner"></span> Se scaneaza logul' + (gfKey ? ' (doar liniile selectiei globale)' : '') +
      ' -- prima analiza pe un interval nou dureaza cateva secunde pe fisiere mari; apoi e instanta...';
  }
  ipovRenderGfBanner(gfKey);
  clearTimeout(IPOV_POLL_T);
  try {
    const resp = await fetch(`/api/dataset/${DATASET_ID}/ip_overview?${qs.toString()}`);
    const data = await resp.json();
    if (seq !== IPOV_SEQ) return;   // o analiza mai noua a inlocuit-o
    if (resp.status === 202) {
      summaryEl.textContent = data.error || 'Se indexeaza...';
      IPOV_STALE = true;
      IPOV_POLL_T = setTimeout(() => { if (CURRENT_PAGE === 'ip') ipovAnalyze(); }, 1500);
      return;
    }
    if (!resp.ok) throw new Error(data.error || 'eroare');
    IPOV = data;
    IPOV_GF_KEY = gfKey;
    ipovRender(data);
    summaryEl.style.display = 'block';
    summaryEl.textContent = `Interval: ${data.label} -- date din log: ${ipovTs(data.first_seen)} -> ${ipovTs(data.last_seen)} (${ipovDur(data.duration_sec)})` +
      ` -- ${data.cached ? 'din cache' : 'calculat in ' + data.elapsed_sec + 's'}` +
      (data.crawler_verification_pending ? ' -- verificarea DNS a crawlerelor ruleaza inca, se actualizeaza automat' : '');
    if (data.crawler_verification_pending) {
      IPOV_POLL_T = setTimeout(() => { if (CURRENT_PAGE === 'ip') ipovAnalyze(true); }, 5000);
    }
  } catch (e) {
    if (seq !== IPOV_SEQ) return;
    IPOV_STALE = true;
    summaryEl.style.display = 'block';
    summaryEl.textContent = 'Eroare: ' + e.message;
  }
}

function ipovRender(d) {
  $('#ipovBody').style.display = 'block';
  $('#ipovScopeLbl').textContent = d.label;
  if (d.domain && !$('#ipovReportDomain').dataset.touched) $('#ipovReportDomain').value = d.domain;

  // --- verdict
  const v = d.verdict || {};
  const card = $('#ipovVerdictCard');
  card.className = 'card ipovVerdict lv-' + (v.level || 'info');
  const lvlTxt = { critical: 'CRITIC', high: 'RIDICAT', medium: 'MEDIU', info: 'INFO', ok: 'OK' }[v.level] || 'INFO';
  const lvlCls = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', info: 'INFO', ok: 'LOW' }[v.level] || 'INFO';
  $('#ipovVerdictLevel').className = 'tag ' + lvlCls;
  $('#ipovVerdictLevel').textContent = lvlTxt;
  $('#ipovVerdictHeadline').textContent = v.headline || '';
  $('#ipovVerdictLines').innerHTML = (v.lines || []).map(l => `<li>${esc(l)}</li>`).join('');
  $('#ipovVerdictRecsWrap').style.display = (v.recommendations || []).length ? '' : 'none';
  $('#ipovVerdictRecs').innerHTML = (v.recommendations || []).map(l => `<li>${esc(l)}</li>`).join('');

  // --- KPI
  const sc = {}; (d.status_breakdown || []).forEach(x => { sc[x.status] = x; });
  const kp = (lbl, val, sub, cls) => `<div class="kpi ${cls || ''}"><div class="val">${val}</div><div class="lbl">${lbl}</div>${sub ? `<div class="sub">${sub}</div>` : ''}</div>`;
  $('#ipovKpis').innerHTML = [
    kp('NR total accesari', fmtNum(d.total_requests)),
    kp('IP-uri unice', fmtNum(d.unique_ips), fmtNum(d.single_hit_ips) + ' cu o singura cerere' + (d.total_requests ? ' &middot; ' + Math.round(100 * d.unique_ips / d.total_requests) + ' IP / 100 cereri' : ''), d.total_requests >= 3000 && d.unique_ips / d.total_requests >= 0.25 ? 'warn' : ''),
    kp('Medie cereri / minut', fmtNum(d.per_min_avg), ipovDur(d.duration_sec) + ' acoperite'),
    kp('Varf / minut', fmtNum(d.peak_minute_requests), esc(ipovTs(d.peak_minute ? d.peak_minute + ':00' : ''))),
    kp('Erori 4xx', fmtNum((sc['4xx'] || {}).requests || 0), ((sc['4xx'] || {}).pct || 0) + '%'),
    kp('Erori 5xx', fmtNum((sc['5xx'] || {}).requests || 0), ((sc['5xx'] || {}).pct || 0) + '%', ((sc['5xx'] || {}).pct || 0) >= 3 ? 'warn' : ''),
    kp('Cereri cu semnatura de atac', fmtNum(d.attack_total), fmtNum(d.attack_2xx_total) + ' cu raspuns 2xx', d.attack_total ? 'warn' : ''),
    kp('Bandwidth', fmtBytes(d.bytes || 0)),
  ].join('');

  ipovRenderTimeline(d);
  ipovRenderRubrics(d);
  netLoad();

  // categorii UA in filtrul de extractie
  const catSel = $('#ipovFUaCat'), cur = catSel.value;
  catSel.innerHTML = '<option value="">Categorie UA: oricare</option>' +
    (d.ua_breakdown || []).map(x => `<option value="${esc(x.category)}">${esc(x.category)}</option>`).join('');
  catSel.value = cur;
  ipovRenderSel();
}

function ipovRenderTimeline(d) {
  const tl = d.timeline || [];
  $('#ipovTlGran').textContent = { day: 'pe zile', hour: 'pe ore', minute: 'pe minute' }[d.timeline_granularity] || '';
  const ctx = $('#ipovTimeline').getContext('2d');
  if (IPOV_TL_CHART) IPOV_TL_CHART.destroy();
  IPOV_TL_CHART = new Chart(ctx, {
    type: 'bar',
    data: { labels: tl.map(x => x.label), datasets: [{ label: 'Cereri', data: tl.map(x => x.requests), backgroundColor: '#0B6E73', borderRadius: 3, maxBarThickness: 28 }] },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => fmtNum(c.parsed.y) + ' cereri' } } },
      scales: {
        x: { ticks: { color: '#5D6A79', maxRotation: 45, autoSkip: true }, grid: { display: false } },
        y: { ticks: { color: '#5D6A79' }, grid: { color: 'rgba(21,33,46,.07)' }, beginAtZero: true },
      },
      interaction: { mode: 'index', intersect: false },
      onClick: (_evt, els) => {
        if (!els.length) return;
        const it = tl[els[0].index], g = d.timeline_granularity;
        if (g === 'day') ipovSetScope(it.day, '', '');
        else if (g === 'hour') ipovSetScope(it.day, it.hh + ':00:00', it.hh + ':59:59');
        else ipovSetScope(it.day, it.hm + ':00', it.hm + ':59');
      },
      onHover: (evt, els) => { evt.native.target.style.cursor = els.length ? 'pointer' : 'default'; },
    },
  });
}

// --- rubrici ---------------------------------------------------------------
function _cc(c) { return c && c !== '??' ? c : 'necunoscut'; }
const IPOV_RUBRICS = [
  { id: 's24', title: 'Subnete /24 (IPv6: /64)', rows: d => (d.subnet24_breakdown || []).map(x => ({ label: x.subnet, value: x.requests, pct: x.pct, type: 'subnet', key: x.subnet })) },
  { id: 's16', title: 'Subnete /16 (IPv6: /48)', rows: d => (d.subnet16_breakdown || []).map(x => ({ label: x.subnet, value: x.requests, pct: x.pct, type: 'subnet', key: x.subnet })) },
  { id: 'ips', title: 'Top IP-uri', rows: d => (d.top_ips || []).map(x => ({ label: x.ip, extra: _cc(x.country), value: x.requests, pct: x.pct, type: 'ip', key: x.ip })) },
  { id: 'cc', title: 'Tari', rows: d => (d.country_breakdown || []).map(x => ({ label: x.country === '??' ? '?? (necunoscut / IPv6)' : x.country, value: x.requests, pct: x.pct, type: 'country', key: x.country })) },
  { id: 'crawl', title: 'Crawlere (identitate revendicata, verificata DNS)', rows: d => {
      const out = [];
      (d.crawler_breakdown || []).forEach(x => {
        const badges = [];
        if (x.verified) badges.push(`<span class="ipovBadge ok" title="cereri de la IP-uri confirmate DNS / retea oficiala">&#10003; ${fmtNum(x.verified)}</span>`);
        if (x.fake) badges.push(`<span class="ipovBadge bad" title="cereri de la IP-uri care au PICAT verificarea DNS -- UA fals">FALS ${fmtNum(x.fake)}</span>`);
        if (x.unchecked) badges.push(`<span class="ipovBadge unk" title="${x.dns_verifiable ? 'verificare in curs sau timeout DNS' : 'furnizorul nu publica verificare prin DNS -- nu se poate confirma'}">? ${fmtNum(x.unchecked)}</span>`);
        out.push({ label: x.identity, badges: badges.join(''), value: x.requests, pct: x.pct, type: 'identity', key: x.identity });
        if (x.fake) out.push({ label: x.identity + ' -- FALS', value: x.fake, pct: d.total_requests ? Math.round(1000 * x.fake / d.total_requests) / 10 : 0, type: 'fake', key: x.identity, ips: x.fake_ip_list || [] });
      });
      return out;
    } },
  { id: 'uacat', title: 'User-Agent -- categorie', rows: d => (d.ua_breakdown || []).map(x => ({ label: x.category, value: x.requests, pct: x.pct, type: 'ua_category', key: x.category })) },
  { id: 'uaraw', title: 'User-Agent predominante', rows: d => (d.ua_raw_breakdown || []).map(x => ({ label: x.ua && x.ua !== '-' ? x.ua : '(gol / "-")', value: x.requests, pct: x.pct, type: 'ua', key: x.ua })) },
  { id: 'status', title: 'Coduri de status HTTP', rows: d => (d.status_codes || []).map(x => ({ label: x.code, value: x.requests, pct: x.pct, type: 'status', key: x.code })) },
  { id: 'paths', title: 'Top path-uri (fara query string)', rows: d => (d.top_paths || []).map(x => ({ label: x.path, value: x.requests, pct: x.pct, type: 'path', key: x.path })) },
  { id: 'pref', title: 'Prefixe URL (fara statice) -- URL-uri distincte', rows: d => (d.top_prefixes || []).map(x => ({ label: x.prefix, badges: `<span class="ipovBadge ${x.distinct_urls >= 1000 ? 'bad' : 'unk'}" title="URL-uri distincte (cu query string) cerute sub acest prefix">${fmtNum(x.distinct_urls)}${x.capped ? '+' : ''} URL-uri distincte</span>`, value: x.requests, pct: x.pct, type: 'path', key: x.prefix })) },
  { id: 'att', title: 'Semnaturi de atac', rows: d => (d.attacks || []).map(x => ({ label: x.label, badges: `<span class="ipovBadge ${x.served_2xx ? 'bad' : 'ok'}" title="cate au primit raspuns 2xx (procesate)">2xx: ${fmtNum(x.served_2xx)}</span>`, value: x.requests, pct: x.pct, type: 'pattern', key: x.pattern })), empty: 'Nicio semnatura de atac in interval.' },
  { id: 'attip', title: 'Surse atacuri (IP)', rows: d => (d.attack_ips || []).map(x => ({ label: x.ip, extra: _cc(x.country), value: x.requests, pct: d.attack_total ? Math.round(1000 * x.requests / d.attack_total) / 10 : 0, type: 'attack_ip', key: x.ip })), empty: 'Nicio sursa de atac.' },
];
let IPOV_ROWS = {};   // rubrica -> randuri (pt click/CSV)

function ipovRenderRubrics(d) {
  IPOV_ROWS = {};
  $('#ipovGrid').innerHTML = IPOV_RUBRICS.map(r => {
    const rows = r.rows(d);
    IPOV_ROWS[r.id] = rows;
    const all = !!IPOV_EXPANDED[r.id];
    let shown = rows, restV = 0, restP = 0;
    if (!all && rows.length > IPOV_FOLD) {
      shown = rows.slice(0, IPOV_FOLD);
      rows.slice(IPOV_FOLD).forEach(x => { restV += x.value; restP += x.pct || 0; });
    }
    const max = Math.max(1, ...shown.map(x => x.value), restV);
    const rowHtml = (x, i) => {
      const w = Math.max(1, 100 * x.value / max);
      const sel = IPOV_ACTIVE && IPOV_ACTIVE.rub === r.id && IPOV_ACTIVE.idx === i ? ' sel' : '';
      return `<div class="rvwBarRow clickable ipovRow${sel}" data-rub="${r.id}" data-idx="${i}" title="${esc(x.label)} -- click pentru actiuni">` +
        `<span class="rvwBarLabel">${esc(x.label)}${x.extra ? ' <span style="opacity:.6">' + esc(x.extra) + '</span>' : ''}</span>` +
        `<span class="rvwBarTrack"><span class="rvwBarFill" style="width:${w}%"></span></span>` +
        `<span class="rvwBarVal">${fmtNum(x.value)} (${rvwFmtPct(x.pct)})</span>` +
        (x.badges ? `<span class="ipovBadgeLine">${x.badges}</span>` : '') + `</div>`;
    };
    let body = rows.length ? shown.map(rowHtml).join('') : `<div class="rvwEmpty">${r.empty || 'Fara date.'}</div>`;
    if (restV) body += `<div class="rvwBarRow"><span class="rvwBarLabel">Altele (${rows.length - IPOV_FOLD})</span><span class="rvwBarTrack"><span class="rvwBarFill" style="width:${Math.max(1, 100 * restV / max)}%;opacity:.45"></span></span><span class="rvwBarVal">${fmtNum(restV)} (${rvwFmtPct(restP)})</span></div>`;
    const moreBtn = rows.length > IPOV_FOLD ? `<button class="ghost ipovMore" data-rub="${r.id}">${all ? 'top ' + IPOV_FOLD : 'toate ' + rows.length}</button>` : '';
    return `<div class="ipovRub"><div class="ipovRubHead"><div class="rvwBarsHead">${esc(r.title)}</div><div class="spacer"></div>${moreBtn}` +
      (rows.length ? `<button class="ghost ipovCsv" data-rub="${r.id}" title="Descarca CSV">CSV</button>` : '') + `</div>${body}</div>`;
  }).join('');
}

document.addEventListener('click', (e) => {
  const more = e.target.closest('.ipovMore');
  if (more) { IPOV_EXPANDED[more.dataset.rub] = !IPOV_EXPANDED[more.dataset.rub]; ipovRenderRubrics(IPOV); return; }
  const csv = e.target.closest('.ipovCsv');
  if (csv) {
    const r = IPOV_RUBRICS.find(x => x.id === csv.dataset.rub);
    const rows = IPOV_ROWS[csv.dataset.rub] || [];
    const lines = ['valoare;detaliu;cereri;procent'].concat(rows.map(x => [x.label, x.extra || '', x.value, x.pct].map(csvCell).join(';')));
    downloadFile(`logscan-${csv.dataset.rub}-${(IPOV.label || '').replace(/[^\w.-]+/g, '_')}.csv`, '﻿' + lines.join('\n'), 'text/csv;charset=utf-8');
    return;
  }
  const row = e.target.closest('.ipovRow');
  if (row) {
    const x = (IPOV_ROWS[row.dataset.rub] || [])[+row.dataset.idx];
    if (!x) return;
    IPOV_ACTIVE = { rub: row.dataset.rub, idx: +row.dataset.idx, ...x };
    document.querySelectorAll('.ipovRow.sel').forEach(el => el.classList.remove('sel'));
    row.classList.add('sel');
    ipovRenderSel();
  }
});

// entitate -> filtre pentru /extract_raw (null = nu se poate filtra)
function ipovEntityFilter(x) {
  switch (x.type) {
    case 'subnet': return /necunoscut|invalid/.test(x.key) ? null : { subnet: x.key };
    case 'ip': return { ip: x.key };
    case 'attack_ip': return { ip: x.key, pattern: 'any_attack' };
    case 'country': return { country: x.key };
    case 'identity': return { identity: x.key.toLowerCase() };
    case 'fake': return { identity: x.key.toLowerCase(), crawler_fake: '1' };
    case 'ua_category': return { ua_category: x.key };
    case 'ua': return x.key && x.key !== '-' ? { ua: x.key } : null;
    case 'status': return { status: x.key };
    case 'path': return { path: x.key };
    case 'pattern': return { pattern: x.key };
  }
  return null;
}
// v44: entitatile din rubrici care pot deveni filtru GLOBAL (spec §6)
const IPOV_GLOBAL_FIELD = { ip: 'ip', attack_ip: 'ip', country: 'country', status: 'status', path: 'path', ua: 'ua' };
function ipovBlockable(x) { return ['subnet', 'ip', 'attack_ip', 'country', 'ua', 'fake', 'path'].includes(x.type) && !/necunoscut|invalid/.test(x.key || ''); }
const IPOV_TYPE_LBL = { subnet: 'subnet', ip: 'IP', attack_ip: 'IP (atacuri)', country: 'tara', identity: 'crawler', fake: 'crawler FALS', ua_category: 'categorie UA', ua: 'User-Agent', status: 'status', path: 'path', pattern: 'semnatura' };

function ipovRenderSel() {
  const box = $('#ipovSel');
  const x = IPOV_ACTIVE;
  if (!x) { box.style.display = 'none'; return; }
  const f = ipovEntityFilter(x);
  const inBlock = IPOV_BLOCK.some(b => b.type === x.type && b.key === x.key);
  box.style.display = 'flex';
  box.innerHTML = `<span class="selLbl">${esc(IPOV_TYPE_LBL[x.type] || x.type)}: ${esc(x.label)} -- ${fmtNum(x.value)} cereri</span>` +
    (f ? `<button class="primary" data-ipov-act="last">Ultimele linii</button><button class="ghost" data-ipov-act="first">Primele linii</button><button class="ghost" data-ipov-act="filter">&#8595; Pune in filtrele de extractie</button>` : '<span class="note" style="margin:0">(nu se poate filtra pe aceasta valoare)</span>') +
    (x.type === 'ip' || x.type === 'attack_ip' ? `<button class="ghost" data-ipov-act="ipdetail">Detalii IP</button>` : '') +
    (IPOV_GLOBAL_FIELD[x.type] && x.key && !/necunoscut|invalid/.test(x.key) ? `<button class="primary" data-ipov-act="global" title="Aplica selectia pe toata aplicatia: toate modulele si Raw Logs">&#9881; Filtreaza toata aplicatia</button>` : '') +
    (ipovBlockable(x) ? `<button class="ghost" data-ipov-act="block" ${inBlock ? 'disabled' : ''}>${inBlock ? '&#10003; in lista de blocare' : '+ blocare'}</button>` : '') +
    `<div class="spacer"></div><button class="ghost" data-ipov-act="close">&times;</button>`;
}

document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-ipov-act]');
  if (!b || !IPOV_ACTIVE) return;
  const x = IPOV_ACTIVE, act = b.dataset.ipovAct, f = ipovEntityFilter(x);
  if (act === 'close') { IPOV_ACTIVE = null; document.querySelectorAll('.ipovRow.sel').forEach(el => el.classList.remove('sel')); ipovRenderSel(); return; }
  if ((act === 'last' || act === 'first') && f) {
    $('#ipovExtractOrder').value = act;
    const qs = new URLSearchParams({ limit: $('#ipovExtractLimit').value, ...ipovScopeParams(), ...f });
    ipovExtractFetch(qs.toString(), `${IPOV_TYPE_LBL[x.type] || x.type}: ${x.label} (${IPOV.label})`);
    return;
  }
  if (act === 'filter' && f) { ipovFillExtractFilters(f); $('#ipovExtractCard').scrollIntoView({ behavior: 'smooth' }); return; }
  if (act === 'ipdetail') { showIpDetail(x.key); return; }
  if (act === 'global' && IPOV_GLOBAL_FIELD[x.type]) {
    IPOV_ACTIVE = null; ipovRenderSel();
    triageSetSingleFilter(IPOV_GLOBAL_FIELD[x.type], x.key);
    return;
  }
  if (act === 'block') {
    IPOV_BLOCK.push({ type: x.type === 'attack_ip' ? 'ip' : x.type, key: x.key, label: x.label, ips: x.ips });
    ipovRenderBlock(); ipovRenderSel(); toast('Adaugat la regulile de blocare');
  }
});

// --- reguli de blocare -------------------------------------------------------
function _cfStr(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }
function _apacheRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\"]/g, '\\$&'); }

function ipovBuildRules(items) {
  const nets = [], countries = [], uas = [], fakes = [], paths = [];
  items.forEach(it => {
    if (it.type === 'ip' || it.type === 'subnet') nets.push(it.key);
    else if (it.type === 'country') countries.push(it.key);
    else if (it.type === 'ua') uas.push(it.key);
    else if (it.type === 'fake') fakes.push(it);
    else if (it.type === 'path') paths.push(it.key);
  });
  const fakeIps = [...new Set(fakes.flatMap(f => f.ips || []))];
  const reason = (k) => `logscan ${new Date().toISOString().slice(0, 10)}${k ? ' ' + k : ''}`;

  // CSF
  let csf = '# CSF -- ruleaza ca root. Verifica inainte ca IP-ul/subnetul nu e al unui crawler legitim sau al clientului.\n';
  nets.forEach(n => { csf += `csf -d ${n} "${reason()}"\n`; });
  fakeIps.forEach(ip => { csf += `csf -d ${ip} "${reason('crawler fals')}"\n`; });
  if (countries.length) csf += `# Tari: in /etc/csf/csf.conf adauga la CC_DENY = "${countries.filter(c => c !== '??').join(',')}" apoi: csf -r\n`;
  if (uas.length || paths.length) csf += '# User-Agent / path: nu se pot bloca din CSF -- foloseste .htaccess sau Cloudflare.\n';
  if (!nets.length && !fakeIps.length && !countries.length) csf += '# (nimic aplicabil in CSF pentru selectia curenta)\n';

  // Imunify360
  let imu = '# Imunify360 -- daca e activ, CSF ruleaza in mod integrare; blocheaza aici.\n';
  nets.forEach(n => { imu += `imunify360-agent blacklist ip add ${n} --comment "${reason()}"\n`; });
  fakeIps.forEach(ip => { imu += `imunify360-agent blacklist ip add ${ip} --comment "${reason('crawler fals')}"\n`; });
  if (countries.length) imu += `# Tari (${countries.join(', ')}): din interfata Imunify360 -> Firewall -> Black List -> Country.\n`;
  if (!nets.length && !fakeIps.length && !countries.length) imu += '# (nimic aplicabil in Imunify360 pentru selectia curenta)\n';

  // .htaccess
  let ht = '# .htaccess -- Apache 2.4 / LiteSpeed. Pune la inceputul fisierului din public_html.\n';
  const htNets = nets.concat(fakeIps);
  if (htNets.length) {
    ht += '<RequireAll>\n    Require all granted\n';
    for (let i = 0; i < htNets.length; i += 20) ht += '    Require not ip ' + htNets.slice(i, i + 20).join(' ') + '\n';
    ht += '</RequireAll>\n';
  }
  const conds = [];
  uas.forEach(u => conds.push(u && u !== '-' ? `RewriteCond %{HTTP_USER_AGENT} "${_apacheRe(u)}" [NC` : 'RewriteCond %{HTTP_USER_AGENT} ^-?$ [NC'));
  paths.forEach(p => conds.push(`RewriteCond %{REQUEST_URI} ^${_apacheRe(p)} [NC`));
  if (paths.length) ht += '\n# ATENTIE: regulile pe path de mai jos blocheaza sectiunea pentru TOTI vizitatorii (inclusiv clienti reali si Google).\n# Pentru enumerare de filtre prefera Cloudflare (Managed Challenge / rate limit) -- vezi caseta Cloudflare.\n';
  if (conds.length) {
    ht += '\nRewriteEngine On\n' + conds.map((c, i) => c + (i < conds.length - 1 ? ',OR]' : ']')).join('\n') + '\nRewriteRule .* - [F,L]\n';
  }
  if (countries.length) ht += `# Tari (${countries.join(', ')}): .htaccess nu are GeoIP nativ -- foloseste CSF CC_DENY sau Cloudflare.\n`;
  if (fakes.length) ht += '# Crawlerele false sunt blocate mai sus dupa IP (lista IP-urilor care au picat verificarea DNS in acest log).\n';

  // Cloudflare
  const cf = [];
  if (nets.length) cf.push(`(ip.src in {${nets.join(' ')}})`);
  if (countries.length) cf.push(`(ip.src.country in {${countries.filter(c => c !== '??').map(_cfStr).join(' ')}})`);
  uas.forEach(u => cf.push(u && u !== '-' ? `(http.user_agent eq ${_cfStr(u)})` : '(http.user_agent eq "")'));
  // path-urile sunt ale site-ului (vizitatorii reali le folosesc) -- regula doar pt. trafic
  // din afara RO si fara botii verificati; actiune recomandata Managed Challenge, nu Block
  paths.forEach(p => cf.push(`(starts_with(http.request.uri.path, ${_cfStr(p)}) and ip.src.country ne "RO" and not cf.client.bot)`));
  const fakeNames = [...new Set(fakes.map(f => f.key))];
  const CF_UA_TOKEN = { 'Googlebot': 'googlebot', 'AdsBot-Google': 'adsbot-google', 'Storebot-Google': 'storebot-google', 'Bingbot': 'bingbot',
    'Yandex': 'yandexbot', 'Meta crawler': 'facebookexternalhit', 'ClaudeBot': 'claudebot', 'GPTBot': 'gptbot', 'DuckDuckBot': 'duckduckbot' };
  if (fakeNames.length) cf.push('((' + fakeNames.map(n => `lower(http.user_agent) contains ${_cfStr(CF_UA_TOKEN[n] || n.toLowerCase())}`).join(' or ') + ') and not cf.client.bot)');
  const cfTxt = cf.length ? cf.join('\nor ') + '\n\n# Actiune recomandata: Block pentru IP/subnet/UA/crawlere false' +
    (paths.length ? '; pentru path-uri (sectiuni ale site-ului) foloseste Managed Challenge sau Rate limiting, NU Block -- sau fa o regula separata doar pentru ele' : '') +
    '. Tari: "??" nu are echivalent in Cloudflare si e omis.' : '# (nimic selectat)';
  return { csf, imu, ht, cf: cfTxt };
}

function ipovRenderBlock() {
  $('#ipovBlockCount').textContent = IPOV_BLOCK.length ? IPOV_BLOCK.length + ' intrari' : '';
  $('#ipovBlockChips').innerHTML = IPOV_BLOCK.map((b, i) => `<span>${esc(IPOV_TYPE_LBL[b.type] || b.type)}: ${esc(b.label)}<button class="ghost" data-ipov-unblock="${i}" title="scoate">&times;</button></span>`).join('');
  $('#ipovBlockEmpty').style.display = IPOV_BLOCK.length ? 'none' : 'block';
  $('#ipovBlockOut').style.display = IPOV_BLOCK.length ? 'block' : 'none';
  if (!IPOV_BLOCK.length) return;
  const r = ipovBuildRules(IPOV_BLOCK);
  $('#ipovRuleCsf').value = r.csf; $('#ipovRuleImunify').value = r.imu; $('#ipovRuleHt').value = r.ht; $('#ipovRuleCf').value = r.cf;
}
document.addEventListener('click', (e) => {
  const u = e.target.closest('[data-ipov-unblock]');
  if (u) { IPOV_BLOCK.splice(+u.dataset.ipovUnblock, 1); ipovRenderBlock(); ipovRenderSel(); return; }
  const c = e.target.closest('[data-copy-ta]');
  if (c) { copyText($(c.dataset.copyTa).value || ''); }
});
$('#ipovGoBlock').addEventListener('click', () => {
  // pre-populeaza cu sursele principale de atac, daca lista e goala
  if (!IPOV_BLOCK.length && IPOV && (IPOV.attack_ips || []).length) {
    IPOV.attack_ips.slice(0, 3).forEach(x => IPOV_BLOCK.push({ type: 'ip', key: x.ip, label: x.ip }));
    ipovRenderBlock();
  }
  $('#ipovBlockCard').scrollIntoView({ behavior: 'smooth' });
});

// --- raport --------------------------------------------------------------------
$('#ipovReportDomain').addEventListener('input', (e) => { e.target.dataset.touched = '1'; });
$('#ipovGoReport').addEventListener('click', () => { $('#ipovReportCard').scrollIntoView({ behavior: 'smooth' }); ipovGenReport(); });
$('#ipovReportGen').addEventListener('click', () => ipovGenReport());
$('#ipovReportType').addEventListener('change', () => ipovGenReport());

async function ipovFetchSamples(extra, n) {
  try {
    const qs = new URLSearchParams({ limit: n, ...ipovScopeParams(), ...extra });
    const r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/extract_raw?${qs}`));
    const d = await r.json();
    return r.ok ? (d.first || []).map(m => m.raw) : [];
  } catch (_) { return []; }
}

function _pctOf(n, t) { return t ? (Math.round(1000 * n / t) / 10) + '%' : '0%'; }

let IPOV_REPORT_SEQ = 0;
async function ipovGenReport() {
  const seq = ++IPOV_REPORT_SEQ;   // un raspuns intarziat al unei generari vechi nu suprascrie una noua
  const d = IPOV;
  const out = $('#ipovReportOut');
  if (!d) { out.value = 'Ruleaza intai analiza (Analizeaza).'; return; }
  const type = $('#ipovReportType').value;
  const dom = $('#ipovReportDomain').value.trim() || 'site-ul dumneavoastra';
  const v = d.verdict || {};
  const from = ipovTs(d.first_seen), to = ipovTs(d.last_seen);
  const sc = {}; (d.status_breakdown || []).forEach(x => { sc[x.status] = x.requests; });
  const topCc = (d.country_breakdown || []).slice(0, 5).map(x => `${x.country === '??' ? 'necunoscut' : x.country} ${x.pct}%`).join(', ');
  const att = d.attacks || [], srcs = d.attack_ips || [];
  const fakeTot = (d.crawler_breakdown || []).reduce((a, x) => a + (x.fake || 0), 0);
  const withSamples = $('#ipovReportSamples').checked;
  out.value = 'Se genereaza...';

  let samples = [];
  if (withSamples && type !== 'short') {
    if (d.attack_total && att.length) {
      // exemple din semnatura dominanta, de la sursa ei principala (cel mai relevant pt. client)
      const f = { pattern: att[0].pattern };
      if (srcs.length) f.ip = srcs[0].ip;
      samples = await ipovFetchSamples(f, type === 'client' ? 3 : 6);
      if (!samples.length) samples = await ipovFetchSamples({ pattern: att[0].pattern }, type === 'client' ? 3 : 6);
    } else if (ipovIsDistributed(d) && (d.top_prefixes || []).length) {
      // exemple din sectiunea atacata, fara crawlerele cu identitate revendicata (Bing/Google)
      samples = await ipovFetchSamples({ path: d.top_prefixes[0].prefix, identity: '__none__' }, type === 'client' ? 3 : 6);
    } else if (type === 'tech' && (d.top_ips || []).length) samples = await ipovFetchSamples({ ip: d.top_ips[0].ip }, 3);
  }
  if (seq !== IPOV_REPORT_SEQ) return;
  const L = [];
  if (type === 'short') {
    L.push(`[${({ critical: 'CRITIC', high: 'RIDICAT', medium: 'MEDIU', ok: 'OK', info: 'INFO' })[v.level] || 'INFO'}] ${dom} -- ${v.headline}`);
    L.push(`Interval: ${from} - ${to}. ${fmtNum(d.total_requests)} cereri, ${fmtNum(d.unique_ips)} IP-uri unice, varf ${fmtNum(d.peak_minute_requests)}/min.`);
    if (d.attack_total) L.push(`Atacuri: ${fmtNum(d.attack_total)} cereri (${att.slice(0, 2).map(a => a.label).join(', ')}), ${fmtNum(d.attack_2xx_total)} cu 2xx. Sursa: ${srcs.slice(0, 3).map(s => s.ip + ' (' + _cc(s.country) + ')').join(', ')}.`);
    if (sc['5xx']) L.push(`5xx: ${fmtNum(sc['5xx'])} (${_pctOf(sc['5xx'], d.total_requests)}).`);
    if (IPOV_BLOCK.length) L.push(`Blocat/de blocat: ${IPOV_BLOCK.map(b => b.label).join(', ')}.`);
    (v.recommendations || []).slice(0, 2).forEach(r => L.push('- ' + r));
  } else if (type === 'client') {
    L.push('Buna ziua,', '');
    L.push(`Am analizat logurile de acces pentru ${dom} in intervalul ${from} - ${to}.`, '');
    L.push('Pe scurt: ' + ipovClientHeadline(d) + '.', '');
    L.push('Ce am constatat:');
    L.push(`- In total ${fmtNum(d.total_requests)} accesari de la ${fmtNum(d.unique_ips)} adrese IP diferite (in medie ${fmtNum(d.per_min_avg)} pe minut; varful a fost de ${fmtNum(d.peak_minute_requests)} accesari intr-un singur minut, la ${ipovTs(d.peak_minute ? d.peak_minute + ':00' : '')}).`);
    if (d.attack_total) {
      L.push(`- ${fmtNum(d.attack_total)} dintre accesari au fost incercari automate de atac asupra site-ului (${att.slice(0, 2).map(a => a.label).join(', ')}). Principala sursa: ${srcs.slice(0, 2).map(s => s.ip + ' (' + _cc(s.country) + ')').join(', ')}.`);
      if (d.attack_2xx_total) L.push(`- O parte din aceste cereri au primit raspuns normal de la aplicatie; asta nu inseamna automat ca atacul a reusit, dar recomandam o verificare a site-ului.`);
      else L.push('- Toate aceste incercari au fost respinse de server.');
    }
    if (ipovIsDistributed(d)) {
      L.push(`- Traficul a venit de la un numar foarte mare de adrese IP diferite (${fmtNum(d.unique_ips)}), majoritatea cu o singura accesare -- tipic pentru retele de roboti care parcurg automat paginile site-ului, nu pentru vizitatori reali.`);
      const tp = (d.top_prefixes || [])[0];
      if (tp && tp.distinct_urls >= 1000 && tp.pct >= 15) L.push(`- ${tp.pct}% din accesari au vizat sectiunea ${tp.prefix}, cu peste ${fmtNum(tp.distinct_urls)} adrese diferite (combinatii de filtre/categorii).`);
    }
    if (sc['5xx'] && sc['5xx'] / d.total_requests >= 0.01) L.push(`- ${fmtNum(sc['5xx'])} accesari (${_pctOf(sc['5xx'], d.total_requests)}) au primit eroare de server -- in acele momente site-ul putea fi lent sau indisponibil.`);
    if (fakeTot) L.push(`- ${fmtNum(fakeTot)} accesari au venit de la roboti care se prezinta drept motoare de cautare (ex. Google), dar nu sunt${d.crawler_verification_pending ? ' (verificare inca in curs, cifra poate creste)' : ''}.`);
    const t1 = (d.top_ips || [])[0];
    if (t1 && t1.pct >= 20) L.push(`- O singura adresa IP (${t1.ip}, ${_cc(t1.country)}) a generat ${t1.pct}% din trafic.`);
    if (topCc) L.push(`- Provenienta traficului: ${topCc}.`);
    L.push('', 'Ce am facut / ce recomandam:');
    if (IPOV_BLOCK.length) L.push(`- Am aplicat masuri de protectie pentru: ${IPOV_BLOCK.map(ipovClientBlockLbl).join(', ')}.`);
    ipovClientRecs(d).forEach(r => L.push('- ' + r));
    if (samples.length) { L.push('', 'Exemple din log (pentru referinta):'); samples.forEach(s => L.push(s)); }
    L.push('', 'Va stam la dispozitie pentru orice detalii suplimentare.');
  } else {
    L.push(`RAPORT TEHNIC -- ${dom}`);
    L.push(`Interval analizat: ${d.label} | date: ${from} -> ${to} (${ipovDur(d.duration_sec)})`);
    L.push(`Nivel: ${({ critical: 'CRITIC', high: 'RIDICAT', medium: 'MEDIU', ok: 'OK', info: 'INFO' })[v.level] || 'INFO'} -- ${v.headline}`, '');
    L.push('== Constatari (automat) ==');
    (v.lines || []).forEach(l => L.push('- ' + l));
    L.push('', '== Cifre ==');
    L.push(`Total cereri: ${fmtNum(d.total_requests)} | IP-uri unice: ${fmtNum(d.unique_ips)} | medie ${fmtNum(d.per_min_avg)}/min | varf ${fmtNum(d.peak_minute_requests)}/min la ${d.peak_minute || '-'} | bandwidth ${fmtBytes(d.bytes || 0)}`);
    L.push('Status: ' + (d.status_breakdown || []).map(x => `${x.status} ${fmtNum(x.requests)} (${x.pct}%)`).join(', '));
    L.push('Coduri: ' + (d.status_codes || []).slice(0, 8).map(x => `${x.code}: ${fmtNum(x.requests)}`).join(', '));
    const tbl = (title, rows) => { if (!rows.length) return; L.push('', `== ${title} ==`); rows.forEach(r => L.push(r)); };
    tbl('Top subnete /24', (d.subnet24_breakdown || []).slice(0, 10).map(x => `${x.subnet.padEnd(24)} ${String(fmtNum(x.requests)).padStart(10)}  ${x.pct}%`));
    tbl('Top subnete /16', (d.subnet16_breakdown || []).slice(0, 8).map(x => `${x.subnet.padEnd(24)} ${String(fmtNum(x.requests)).padStart(10)}  ${x.pct}%`));
    tbl('Top IP-uri', (d.top_ips || []).slice(0, 10).map(x => `${x.ip.padEnd(40)} ${_cc(x.country).padEnd(10)} ${String(fmtNum(x.requests)).padStart(10)}  ${x.pct}%`));
    tbl('Tari', (d.country_breakdown || []).slice(0, 10).map(x => `${(x.country === '??' ? 'necunoscut' : x.country).padEnd(12)} ${String(fmtNum(x.requests)).padStart(10)}  ${x.pct}%`));
    tbl('Semnaturi de atac', att.map(a => `${a.label.padEnd(48)} ${String(fmtNum(a.requests)).padStart(9)}  (2xx: ${fmtNum(a.served_2xx)})`));
    tbl('Surse atacuri', srcs.slice(0, 10).map(s => `${s.ip.padEnd(40)} ${_cc(s.country).padEnd(10)} ${fmtNum(s.requests)}`));
    if (d.crawler_verification_pending) L.push('', '(verificarea DNS a crawlerelor era inca in curs la generare -- regenereaza raportul pentru cifrele finale)');
    tbl('Crawlere (revendicate / verificare DNS)', (d.crawler_breakdown || []).map(x => `${x.identity.padEnd(16)} ${String(fmtNum(x.requests)).padStart(8)} | verificat ${fmtNum(x.verified)} | FALS ${fmtNum(x.fake)} | neverificat ${fmtNum(x.unchecked)}${x.dns_verifiable ? '' : ' (fara verificare DNS oficiala)'}`));
    tbl('User-Agent predominante', (d.ua_raw_breakdown || []).slice(0, 8).map(x => `${String(fmtNum(x.requests)).padStart(9)}  ${x.ua || '-'}`));
    tbl('Top path-uri', (d.top_paths || []).slice(0, 10).map(x => `${String(fmtNum(x.requests)).padStart(9)}  ${x.path}`));
    tbl('Prefixe URL (fara statice)', (d.top_prefixes || []).slice(0, 8).map(x => `${String(fmtNum(x.requests)).padStart(9)}  ${x.pct}%  ${fmtNum(x.distinct_urls)}${x.capped ? '+' : ''} URL-uri distincte  ${x.prefix}`));
    L.push('', `IP-uri cu o singura cerere: ${fmtNum(d.single_hit_ips)} | cereri pentru fisiere statice: ${fmtNum(d.static_requests)} (${_pctOf(d.static_requests, d.total_requests)})`);
    if ((v.recommendations || []).length) { L.push('', '== Recomandari =='); v.recommendations.forEach(r => L.push('- ' + r)); }
    if (IPOV_BLOCK.length) {
      // in raport: regulile pe retele/tari/UA + Cloudflare; listele lungi de IP-uri
      // de crawlere false raman doar in panoul de blocare (pot fi sute)
      const compact = IPOV_BLOCK.map(b => b.type === 'fake' ? { ...b, ips: [] } : b);
      const r = ipovBuildRules(compact);
      L.push('', '== Reguli de blocare propuse ==', r.csf.trim(), '', r.cf.trim());
      IPOV_BLOCK.filter(b => b.type === 'fake').forEach(b => L.push(`# + ${(b.ips || []).length} IP-uri care se dau drept ${b.key} (lista completa in panoul de blocare din logscan)`));
    }
    if (samples.length) { L.push('', '== Exemple linii log =='); samples.forEach(s => L.push(s)); }
    L.push('', `Generat de logscan, ${new Date().toLocaleString('ro-RO')}.`);
  }
  if (seq !== IPOV_REPORT_SEQ) return;
  out.value = L.join('\n');
}

function ipovClientBlockLbl(b) {
  if (b.type === 'fake') return `robotii care se prezinta fals drept ${b.key} (${(b.ips || []).length} adrese IP)`;
  if (b.type === 'country') return 'traficul din ' + b.key;
  if (b.type === 'ua') return `programul automat "${b.key}"`;
  if (b.type === 'subnet') return 'reteaua ' + b.key;
  if (b.type === 'path') return 'sectiunea ' + b.key + ' (verificare anti-robot)';
  return b.label;
}
function ipovClientHeadline(d) {
  const v = d.verdict || {};
  if (v.level === 'critical') return 'site-ul a fost tinta unor atacuri automate, iar unele cereri au fost procesate de aplicatie -- recomandam verificarea site-ului';
  if (d.attack_total >= 100) return 'site-ul a fost tinta unor incercari automate de atac, respinse in cea mai mare parte';
  if (v.level === 'high' || v.level === 'medium') return (v.headline || 'am identificat trafic neobisnuit').replace(/^./, c => c.toLowerCase());
  return 'traficul arata normal, fara semne de atac in intervalul analizat';
}
function ipovIsDistributed(d) { return d.total_requests >= 3000 && d.unique_ips / d.total_requests >= 0.25; }
function ipovClientRecs(d) {
  const r = [];
  if (ipovIsDistributed(d)) {
    const tp = (d.top_prefixes || [])[0];
    r.push(`Blocarea pe adrese IP nu este eficienta aici (fiecare accesare vine de la alt IP); recomandam o regula de protectie in Cloudflare${tp ? ' pentru sectiunea ' + tp.prefix : ''}, care verifica doar traficul automat, fara sa afecteze vizitatorii din Romania si motoarele de cautare.`);
  }
  const sc = {}; (d.status_breakdown || []).forEach(x => { sc[x.status] = x.requests; });
  if (d.attack_2xx_total && (d.attacks || []).some(a => a.pattern.startsWith('sqli') && a.served_2xx)) {
    r.push('Verificati continutul site-ului si conturile de administrator; schimbati parolele de administrare si ale bazei de date.');
    r.push('Actualizati platforma (CMS, teme, module/pluginuri) la ultima versiune.');
  } else if (d.attack_total) {
    r.push('Mentineti platforma si modulele actualizate; incercarile de acest tip sunt automate si continue.');
  }
  if ((d.attack_ips || []).length && !IPOV_BLOCK.length && !ipovIsDistributed(d)) r.push('Putem bloca sursele atacurilor la nivel de server sau Cloudflare, la cerere.');
  if (sc['5xx'] && sc['5xx'] / d.total_requests >= 0.03) r.push('Pentru erorile de server: limitarea traficului automat (ex. Cloudflare) reduce incarcarea din momentele de varf.');
  if ((d.crawler_breakdown || []).some(x => x.fake)) r.push('Robotii falsi pot fi blocati din Cloudflare fara a afecta motoarele de cautare reale.');
  if (!r.length) r.push('Nu este necesara nicio actiune in acest moment.');
  return r;
}

$('#ipovReportCopy').addEventListener('click', () => copyText($('#ipovReportOut').value || ''));
$('#ipovReportTxt').addEventListener('click', () => downloadFile(`raport-${ipovReportSlug()}.txt`, $('#ipovReportOut').value || ''));
function ipovReportSlug() { return (($('#ipovReportDomain').value || 'log') + '-' + (IPOV ? IPOV.label : '')).replace(/[^\w.-]+/g, '_'); }
function ipovReportHtml() {
  const title = 'Raport ' + ($('#ipovReportDomain').value || 'logscan');
  return `<!DOCTYPE html><html lang="ro"><head><meta charset="utf-8"><title>${esc(title)}</title>` +
    `<style>body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 20px;color:#1b2333}` +
    `h1{font-size:20px;margin:0 0 16px}pre{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.5}` +
    `.meta{color:#667;font-size:12px;margin-bottom:18px}@media print{body{margin:0}}</style></head><body>` +
    `<h1>${esc(title)}</h1><div class="meta">Generat ${esc(new Date().toLocaleString('ro-RO'))}</div><pre>${esc($('#ipovReportOut').value || '')}</pre></body></html>`;
}
$('#ipovReportHtml').addEventListener('click', () => downloadFile(`raport-${ipovReportSlug()}.html`, ipovReportHtml(), 'text/html;charset=utf-8'));
$('#ipovReportPdf').addEventListener('click', () => {
  const w = window.open('', '_blank');
  if (!w) { showError('Browserul a blocat fereastra noua -- permite pop-up-uri pentru acest site.'); return; }
  w.document.write(ipovReportHtml()); w.document.close(); w.focus();
  setTimeout(() => w.print(), 300);
});

// --- comparatie --------------------------------------------------------------
$('#ipovCmpBtn').addEventListener('click', async () => {
  if (!IPOV) return;
  const out = $('#ipovCmpOut');
  const b = { day: $('#ipovCmpDay').value, start: $('#ipovCmpStart').value, end: $('#ipovCmpEnd').value };
  const qs = new URLSearchParams();
  // A = selectia globala curenta; B = acelasi set de filtre, alta perioada
  const ga = gfObject(), gb = gfObject();
  delete gb.ts_from; delete gb.ts_to;
  if (b.day) {
    gb.ts_from = _dayHmsToEpoch(b.day, b.start ? (b.start.length === 5 ? b.start + ':00' : b.start) : '00:00:00');
    gb.ts_to = _dayHmsToEpoch(b.day, b.end ? (b.end.length === 5 ? b.end + ':59' : b.end) : '23:59:59');
  } else if (b.start || b.end) {
    Object.entries(ipovScopeParams(b)).forEach(([k, v]) => qs.set(k + '_b', v));
  }
  if (Object.keys(ga).length) qs.set('gf_a', JSON.stringify(ga));
  if (Object.keys(gb).length) qs.set('gf_b', JSON.stringify(gb));
  out.innerHTML = '<div class="empty"><span class="spinner"></span> Se calculeaza...</div>';
  try {
    const r = await fetch(`/api/dataset/${DATASET_ID}/ip_compare?${qs}`);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'eroare');
    const A = d.a, B = d.b;
    const delta = (a, bb, lowerIsBetter) => {
      if (!a && !bb) return '<td>-</td>';
      if (!a) return '<td>nou</td>';
      const p = Math.round(100 * (bb - a) / a);
      const cls = p === 0 ? '' : ((p > 0) === lowerIsBetter ? 'up' : 'down');
      return `<td class="num ${cls}">${p > 0 ? '+' : ''}${p}%</td>`;
    };
    const row = (lbl, a, bb, fmt, lib) => `<tr><td>${lbl}</td><td class="num">${fmt(a)}</td><td class="num">${fmt(bb)}</td>${lib === null ? '<td></td>' : delta(a, bb, lib)}</tr>`;
    const n = x => fmtNum(x), p = x => x + '%';
    out.innerHTML = `<table class="cmpTbl"><thead><tr><th></th><th>A: ${esc(A.label)}</th><th>B: ${esc(B.label)}</th><th>B fata de A</th></tr></thead><tbody>` +
      row('Durata acoperita', A.duration_sec, B.duration_sec, ipovDur, null) +
      row('Total cereri', A.total_requests, B.total_requests, n, null) +
      row('Cereri / minut', A.per_min, B.per_min, n, true) +
      row('IP-uri unice', A.unique_ips, B.unique_ips, n, null) +
      row('Varf / minut', A.peak_minute_requests, B.peak_minute_requests, n, true) +
      row('Erori 4xx', A.pct_4xx, B.pct_4xx, p, true) +
      row('Erori 5xx', A.pct_5xx, B.pct_5xx, p, true) +
      row('Cereri cu semnatura de atac', A.attack_total, B.attack_total, n, null) +
      row('Atacuri / minut', A.attack_per_min, B.attack_per_min, n, true) +
      row('...din care 2xx', A.attack_2xx_total, B.attack_2xx_total, n, null) +
      `<tr><td>Verdict</td><td>${esc(A.verdict_headline)}</td><td>${esc(B.verdict_headline)}</td><td></td></tr>` +
      `<tr><td>Top subnete /24</td><td>${A.top_subnets24.slice(0, 5).map(x => esc(x.subnet) + ' ' + x.pct + '%').join('<br>')}</td><td>${B.top_subnets24.slice(0, 5).map(x => esc(x.subnet) + ' ' + x.pct + '%').join('<br>')}</td><td></td></tr>` +
      `<tr><td>Top tari</td><td>${A.top_countries.slice(0, 5).map(x => esc(x.country) + ' ' + x.pct + '%').join(', ')}</td><td>${B.top_countries.slice(0, 5).map(x => esc(x.country) + ' ' + x.pct + '%').join(', ')}</td><td></td></tr>` +
      `</tbody></table><div class="note">Rosu = mai rau in B, verde = mai bine in B. Comparati ratele (pe minut, %) -- totalurile depind de lungimea intervalelor.</div>`;
  } catch (e) { out.innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>'; }
});

// --- extractie linii brute -----------------------------------------------------
function _ipovGatherFilters() {
  const val = id => { const el = $(id); return el ? el.value.trim() : ''; };
  const map = { ip: '#ipovFIp', subnet: '#ipovFSubnet', path: '#ipovFPath', method: '#ipovFMethod', status_class: '#ipovFStatusClass',
    status: '#ipovFStatus', ua: '#ipovFUa', ua_category: '#ipovFUaCat', has_query: '#ipovFHasQuery', referer_empty: '#ipovFRefererEmpty',
    country: '#ipovFCountry', identity: '#ipovFIdentity', pattern: '#ipovFPattern', qkey: '#ipovFQkey' };
  const params = {};
  Object.entries(map).forEach(([k, sel]) => { const v = val(sel); if (v) params[k] = v; });
  if ($('#ipovFFake').checked) params.crawler_fake = '1';
  return params;
}
const IPOV_FILTER_IDS = ['#ipovFIp', '#ipovFSubnet', '#ipovFPath', '#ipovFMethod', '#ipovFStatusClass', '#ipovFStatus', '#ipovFUa', '#ipovFUaCat',
  '#ipovFHasQuery', '#ipovFRefererEmpty', '#ipovFCountry', '#ipovFIdentity', '#ipovFPattern', '#ipovFQkey'];
function ipovClearExtractFilters() { IPOV_FILTER_IDS.forEach(sel => { const el = $(sel); if (el) el.value = ''; }); $('#ipovFFake').checked = false; }
function ipovFillExtractFilters(f) {
  ipovClearExtractFilters();
  const map = { ip: '#ipovFIp', subnet: '#ipovFSubnet', path: '#ipovFPath', status: '#ipovFStatus', ua: '#ipovFUa', ua_category: '#ipovFUaCat',
    country: '#ipovFCountry', identity: '#ipovFIdentity', pattern: '#ipovFPattern' };
  Object.entries(f).forEach(([k, v]) => { if (map[k]) $(map[k]).value = v; });
  if (f.crawler_fake) $('#ipovFFake').checked = true;
}
$('#ipovExtractClearBtn').addEventListener('click', ipovClearExtractFilters);

let IPOV_EXTRACT_STATE = null;
async function ipovExtractFetch(qs, title) {
  const mseq = ++MODAL_SEQ;
  title = title || 'Extractie linii brute';
  LAST_DRILL = { kind: 'ipov_extract', qs, title };
  showModalRawToolbar();
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = '<div class="empty"><span class="spinner"></span> Se scaneaza logul...</div>';
  $('#modalOverlay').style.display = 'flex';
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/extract_raw?${qs}`));
    const data = await resp.json();
    if (mseq !== MODAL_SEQ) return;
    if (!resp.ok) throw new Error(data.error || 'eroare');
    IPOV_EXTRACT_STATE = data;
    renderIpovExtractResult();
  } catch (e) {
    $('#modalBody').innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
  }
}
function renderIpovExtractResult() {
  if (!IPOV_EXTRACT_STATE) return;
  const order = $('#ipovExtractOrder').value;
  const lines = order === 'first' ? IPOV_EXTRACT_STATE.first : IPOV_EXTRACT_STATE.last;
  if (!lines.length) { $('#modalBody').innerHTML = modalEmptyHtml(); return; }
  const other = order === 'first' ? 'last' : 'first';
  let html = `<div class="note">${fmtNum(IPOV_EXTRACT_STATE.total_matching_requests)} cereri potrivite in total -- arat ${order === 'first' ? 'primele' : 'ultimele'} ${fmtNum(lines.length)} ` +
    `<button class="ghost" style="font-size:11px;padding:2px 8px;margin-left:6px" data-ipov-order="${other}">arata ${other === 'first' ? 'primele' : 'ultimele'}</button></div>`;
  html += lines.map(m => `<pre>${esc(m.raw)}</pre>`).join('');
  $('#modalBody').innerHTML = html;
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-ipov-order]');
  if (b) { $('#ipovExtractOrder').value = b.dataset.ipovOrder; renderIpovExtractResult(); }
});
$('#ipovExtractOrder').addEventListener('change', () => { if (IPOV_EXTRACT_STATE) renderIpovExtractResult(); });
$('#ipovExtractBtn').addEventListener('click', () => {
  if (!DATASET_ID) return;
  const f = _ipovGatherFilters();
  const qs = new URLSearchParams({ limit: $('#ipovExtractLimit').value, ...ipovScopeParams(), ...f });
  const lbl = Object.entries(f).map(([k, v]) => `${k}=${v}`).join(', ') || 'fara filtre';
  ipovExtractFetch(qs.toString(), `Extractie: ${lbl} (${IPOV ? IPOV.label : ''})`);
});

function toast(msg) {
  let el = document.getElementById('toastMsg');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toastMsg';
    el.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--bg3);border:1px solid var(--accent);' +
      'color:var(--text);padding:10px 16px;border-radius:8px;font-size:13px;z-index:999;box-shadow:var(--glow);';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.display = 'block';
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = 'none'; }, 1800);
}

function fallbackCopy(text) {
  // navigator.clipboard cere un "context securizat" (HTTPS sau localhost) --
  // aplicatia asta ruleaza intentionat pe HTTP simplu (IP:port), asa ca
  // API-ul modern e indisponibil/blocat de browser in acest caz (esueaza
  // silentios sau arunca eroare). Fallback clasic cu textarea ascuns +
  // document.execCommand('copy'), care functioneaza si pe HTTP simplu.
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.top = '0';
  ta.style.left = '-9999px';
  ta.setAttribute('readonly', '');
  document.body.appendChild(ta);
  const prevFocus = document.activeElement;
  ta.focus();
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (e) {
    ok = false;
  }
  document.body.removeChild(ta);
  if (prevFocus && prevFocus.focus) prevFocus.focus();
  if (ok) {
    toast('Copiat in clipboard!');
  } else {
    toast('Nu am putut copia automat -- selecteaza manual textul din tabel.');
  }
}

function copyText(text) {
  if (REDACT) text = redactClientText(text);
  // navigator.clipboard exista doar in context securizat (HTTPS/localhost);
  // pe HTTP simplu (cazul acestei aplicatii) fie lipseste, fie e blocat de
  // browser -- in ambele cazuri trecem direct pe fallback-ul care merge
  // peste tot.
  if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => toast('Copiat in clipboard!'))
      .catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function copyTable(sel) {
  const table = document.querySelector(sel);
  if (!table) return;
  const rows = [...table.querySelectorAll('tr')];
  const text = rows.map(r => [...r.children].map(c => c.innerText.trim().replace(/\s+/g, ' ')).join('\t')).join('\n');
  copyText(text || 'Fara date.');
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('.copyBtn[data-copy]');
  if (btn) { e.stopPropagation(); copyTable(btn.dataset.copy); }
});

// --------------------------------------------------------------------------
// "Explain this" -- rezumat NARATIV in romana (Faza 3), gata de lipit intr-
// un ticket/Slack, in loc de dump-ul brut de KPI-uri de dinainte. Pur
// aggregare peste CURRENT_SUMMARY deja incarcat -- nicio cerere noua la
// server.
// --------------------------------------------------------------------------
function buildNarrativeSummary() {
  const s = CURRENT_SUMMARY;
  if (!s) return '';
  const fname = $('#fname').textContent.replace(/^—\s*/, '');
  const day = $('#daySelect').value || 'ALL';
  const sentences = [];

  sentences.push(`Rezumat logscan pentru ${fname} (zi: ${day === 'ALL' ? 'toate zilele' : day}).`);
  sentences.push(`Trafic total: ${fmtNum(s.total)} cereri de la ${fmtNum(s.unique_ips)} IP-uri unice, ` +
    `${fmtBytes(s.bandwidth)} bandwidth, ${fmtNum((s.status && s.status['4xx']) || 0)} raspunsuri 4xx si ` +
    `${fmtNum((s.status && s.status['5xx']) || 0)} raspunsuri 5xx.`);

  const crawlers = (s.crawlers || []).filter(c => c.has_tier2 && c.requests > 0).slice(0, 5);
  if (crawlers.length) {
    const parts = crawlers.map(c => {
      let vTxt = '';
      if (CRAWLER_VERIFY_RESULTS) {
        let ok = 0, tot = 0;
        (c.ip_details || []).forEach(d => { tot++; if (CRAWLER_VERIFY_RESULTS[d.ip] && CRAWLER_VERIFY_RESULTS[d.ip].verified === true) ok++; });
        if (tot) vTxt = ` (${ok}/${tot} IP-uri verificate DNS)`;
      }
      return `${c.provider}${vTxt}: ${fmtNum(c.requests)} cereri`;
    });
    sentences.push(`Crawlere principale identificate: ${parts.join(', ')}.`);
  } else {
    sentences.push(`Niciun crawler cu identitate cunoscuta cu trafic semnificativ in aceasta perioada.`);
  }

  const sevCounts = {};
  (s.findings || []).forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  const sevParts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    .filter(sev => sevCounts[sev]).map(sev => `${sevCounts[sev]} ${sev}`);
  sentences.push(`Findings (semnale concrete): ${fmtNum(s.findings_count)} in total` +
    (sevParts.length ? ` (${sevParts.join(', ')}).` : '.'));
  sentences.push(`Anomalii (semnale statistice, mai slabe): ${fmtNum(s.anomalies_count)} in total.`);

  const badBursts = (s.top_bursts || []).filter(b => b.classification && b.classification !== 'Normal' && b.classification !== 'Crawler');
  if (badBursts.length) {
    sentences.push(`Tipare de burst/atac distribuit detectate (${fmtNum(badBursts.length)} ferestre; primele 5): ` +
      badBursts.slice(0, 5).map(b => `${b.classification} la ${b.label} (${fmtNum(b.requests)} cereri, ${fmtNum(b.unique_ips)} IP-uri)`).join('; ') + '.');
  }
  const distEnum = (s.distributed_enum || []).length;
  if (distEnum) {
    sentences.push(`${fmtNum(distEnum)} tipare de enumerare distribuita (multe IP-uri, acelasi path) detectate.`);
  }

  const wp = s.wp || {};
  const wpBits = [];
  if (wp.successful_logins_count) wpBits.push(`${fmtNum(wp.successful_logins_count)} login-uri WP posibil reusite (heuristica)`);
  if (wp.wp_login_post) wpBits.push(`${fmtNum(wp.wp_login_post)} incercari POST wp-login.php`);
  const compromiseCount = (s.compromise_trail || []).filter(t => t.dominant_category === 'confirmed_compromise').length;
  if (compromiseCount) wpBits.push(`${compromiseCount} IP-uri cu semnal de compromitere confirmata (webshell servit cu succes)`);
  if (wpBits.length) {
    sentences.push(`WordPress: ${wpBits.join(', ')}.`);
  }

  sentences.push(`Nota: findings/anomaliile sunt semnale automate de prioritizare, NU dovada definitiva de atac sau compromitere -- verifica manual inainte de a actiona.`);
  return sentences.join(' ');
}

document.addEventListener('click', (e) => {
  if (e.target.closest('#goPrezReport')) {
    e.preventDefault(); showPage('ip');
    setTimeout(() => { $('#ipovReportCard').scrollIntoView({ behavior: 'smooth' }); ipovGenReport(); }, 50);
  }
});
$('#copySummaryBtn').addEventListener('click', () => {
  const text = buildNarrativeSummary();
  if (!text) return;
  copyText(text);
});

// ==========================================================================
// Rapoarte / Raspunsuri (Eduard) -- texte gata de trimis mai departe
// (email/ticket catre client sau catre colegi), generate LIVE din
// CURRENT_SUMMARY deja incarcat -- ZERO cereri noi la server, la fel ca
// buildNarrativeSummary de mai sus. Fiecare tip de raport e o functie
// separata (_report<Tip>(s, domain)) care intoarce un string gata format;
// refreshReport() alege functia dupa dropdown si scrie rezultatul in
// #reportOutput. Regenerat automat de renderSummary (vezi mai sus) de
// fiecare data cand se schimba ziua/intervalul sau se incarca alt log,
// ca raportul sa nu ramana desincronizat de datele afisate.
// ==========================================================================

// Cel mai atacat prefix de CONTINUT (nu static/infrastructura -- vezi
// is_static_prefix, Faza "separam static de continut") + top parametri
// suspecti (filtru/filter_ etc, categoria "suspicious" din query_params).
// Reutilizat de raportul de atac SI de frazele scurte, ca sa nu dublam
// logica de selectie intre cele doua.
function _reportTopAttackSignal(s) {
  const contentPrefixes = (s.top_path_prefixes || []).filter(p => !p.is_static_prefix);
  // Prioritizeaza prefixele cu has_signal (cross-referentiate cu findings/
  // param_abuse REALE, vezi Faza "conecteaza totalurile mari cu semnalele
  // de atac reale") -- altfel cel mai mare prefix DUPA VOLUM e adesea ceva
  // generic gen /include (ajax_total_cart_items.php, apelat de pe orice
  // pagina), nu path-ul chiar atacat. Doar daca NIMIC nu are semnal, cadem
  // pe simplul top-dupa-volum.
  const signaled = contentPrefixes.filter(p => p.has_signal);
  const pool = signaled.length ? signaled : contentPrefixes;
  const top = pool.slice().sort((a, b) => b.requests - a.requests)[0] || null;
  const params = ((s.query_params && s.query_params.suspicious) || [])
    .slice().sort((a, b) => b.requests - a.requests).slice(0, 6);
  return { top, params };
}

function _reportSeverityCounts(list) {
  const c = {};
  (list || []).forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
  return c;
}

function _reportDomainLabel(domain) {
  return domain ? domain : 'site-ul analizat';
}

// --- Tip 1: Raport de atac (tehnic) -- formatul cerut de Eduard, ca exemplul
// lui pentru magazin.exemplu.ro: total/IP-uri, path+parametri
// atacati, bursturi, wp-cron, recomandare de mitigare la final.
function _reportAttack(s, domain) {
  const lbl = _reportDomainLabel(domain);
  const lines = [];
  lines.push(`Sistemele de monitorizare au semnalat trafic anormal pe ${lbl}.`);
  lines.push('');
  lines.push('Atasez informatiile din logs:');
  lines.push('');
  lines.push(`${fmtNum(s.total)} cereri totale, ${fmtNum(s.unique_ips)} IP-uri unice.`);
  lines.push('');

  const { top, params } = _reportTopAttackSignal(s);
  if (top) {
    lines.push(`Path-ul principal vizat: ${top.path} (${fmtNum(top.requests)} cereri, ${fmtNum(top.unique_ips)} IP-uri unice)${params.length ? ', combinat cu un numar mare de variante de parametri de filtrare' : ''}.`);
    if (top.has_signal && top.signal_summary) {
      lines.push(`Semnal concret confirmat: ${top.signal_summary}.`);
    }
    if (top.depth_levels && top.depth_levels.some(d => d.requests > 0)) {
      const dl = top.depth_levels.map(d => `${d.label}: ${fmtNum(d.requests)}`).join(', ');
      lines.push(`Adancime path: ${dl}.`);
    }
    lines.push('');
  }
  if (params.length) {
    lines.push('Parametri de query implicati (categorie suspecta):');
    params.forEach(p => lines.push(`${p.key}\t${fmtNum(p.requests)}`));
    lines.push('');
  }

  const badBursts = (s.top_bursts || []).filter(b => b.classification && b.classification !== 'Normal' && b.classification !== 'Crawler');
  if (badBursts.length) {
    const b0 = badBursts[0];
    lines.push(`In intervale de 30 secunde apar bursturi constante de trafic (ex. ${fmtNum(b0.requests)} cereri / ${fmtNum(b0.unique_ips)} IP-uri la ${b0.label}) -- ${badBursts.length} astfel de fereastra(e) detectate in total.`);
    lines.push('');
  }

  const wp = s.wp || {};
  if (wp.wp_cron > 0) {
    lines.push(`wp-cron.php a generat ${fmtNum(wp.wp_cron)} cereri in perioada analizata -- incarca suplimentar platforma, mai ales combinat cu atacul de mai sus. Recomandam dezactivarea cron-ului la nivel de platforma (DISABLE_WP_CRON) si activarea lui la nivel de server (cron real, la interval fix).`);
    lines.push('');
  }

  const ct = s.country_totals || [];
  const roReq = ct.filter(r => (r.country || '').toUpperCase() === 'RO').reduce((a, b) => a + b.requests, 0);
  const nonRoReq = (s.total || 0) - roReq;
  if (s.total) {
    lines.push(`Distributie geografica: ${(100 * nonRoReq / s.total).toFixed(1)}% din trafic provine din afara Romaniei.`);
    lines.push('');
  }

  lines.push('Recomandam implementarea de reguli de protectie (Cloudflare sau echivalent) tintite pe combinatia path + parametru de filtrare, cu atentie sa nu fie afectati utilizatorii legitimi (excludere Romania/tari cunoscute, excludere boti verificati).');
  return lines.join('\n');
}

// --- Tip 2: Rezumat non-tehnic, pentru un client fara cunostinte tehnice --
// fara jargon (fara "burst", "enumerare", "findings"), explica IMPACTUL si
// ce s-a facut, nu mecanismul tehnic.
function _reportClient(s, domain) {
  const lbl = _reportDomainLabel(domain);
  const lines = [];
  const ct = s.country_totals || [];
  const roReq = ct.filter(r => (r.country || '').toUpperCase() === 'RO').reduce((a, b) => a + b.requests, 0);
  // v44: "din afara Romaniei" = tara CUNOSCUTA alta decat RO (IP-urile fara tara nu sunt ghicite)
  const nonRoPct = s.total ? Math.round(100 * ct.filter(r => { const c = (r.country || '??').toUpperCase(); return c !== 'RO' && c !== '??'; }).reduce((a, b) => a + b.requests, 0) / s.total) : 0;

  lines.push(`Va informam ca am identificat activitate automatizata neobisnuita (de tip "robot") pe ${lbl}, care a generat un volum mare de cereri catre site intr-un timp scurt.`);
  lines.push('');
  lines.push(`In perioada analizata am inregistrat ${fmtNum(s.total)} accesari, dintre care aproximativ ${nonRoPct}% provin din afara Romaniei -- un tipar tipic pentru acest gen de activitate automatizata, nu pentru vizitatori obisnuiti.`);
  lines.push('');
  lines.push('Acest volum suplimentar de trafic poate incetini site-ul sau, in cazuri extreme, il poate face temporar inaccesibil pentru vizitatorii reali.');
  lines.push('');
  lines.push('Am aplicat masuri de protectie care blocheaza automat acest tip de activitate, fara sa afecteze vizitatorii si clientii dumneavoastra reali.');
  lines.push('');
  lines.push('Nu este necesara nicio actiune din partea dumneavoastra. Ramanem la dispozitie pentru orice intrebare.');
  return lines.join('\n');
}

// --- Tip 3: Raport de securitate, uz intern -- findings pe severitate,
// IP-uri suspecte, activitate admin/WP, traseu de compromitere.
function _reportSecurity(s, domain) {
  const lbl = _reportDomainLabel(domain);
  const lines = [];
  lines.push(`Raport de securitate -- ${lbl}`);
  lines.push('');

  const sevF = _reportSeverityCounts(s.findings);
  const sevParts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].filter(k => sevF[k]).map(k => `${sevF[k]} ${k}`);
  lines.push(`Findings: ${fmtNum(s.findings_count)} total` + (sevParts.length ? ` (${sevParts.join(', ')}).` : '.'));
  lines.push(`Anomalii statistice: ${fmtNum(s.anomalies_count)} total.`);
  lines.push(`IP-uri marcate suspecte: ${fmtNum((s.suspicious_ips || []).length)}.`);
  lines.push('');

  const topFindings = (s.findings || [])
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .slice(0, 8);
  if (topFindings.length) {
    lines.push('Findings prioritare (CRITICAL/HIGH):');
    topFindings.forEach(f => lines.push(`[${f.severity}] ${f.rule} -- ${f.detail}`));
    lines.push('');
  }

  const wp = s.wp || {};
  if (wp.wp_login_post || wp.successful_logins_count) {
    lines.push(wp.successful_logins_confirmed != null
      ? `WordPress: ${fmtNum(wp.wp_login_post || 0)} cereri POST la wp-login.php; ${fmtNum(wp.successful_logins_confirmed)} login-uri CONFIRMATE (POST 302 + /wp-admin/ 200) de la ${fmtNum(wp.successful_logins_confirmed_ips)} IP-uri` + (wp.successful_logins_unconfirmed ? `; ${fmtNum(wp.successful_logins_unconfirmed)} POST cu 302 fara acces confirmat (nu e login dovedit).` : '.')
      : `WordPress: ${fmtNum(wp.wp_login_post || 0)} incercari POST wp-login.php, ${fmtNum(wp.successful_logins_count || 0)} login-uri posibil reusite (heuristica, neconfirmata).`);
  }
  const adminCount = (s.admin_activity || []).length;
  if (adminCount) lines.push(`Activitate admin/WP inregistrata pentru ${fmtNum(adminCount)} IP-uri.`);
  const compromiseCount = (s.compromise_trail || []).filter(t => t.dominant_category === 'confirmed_compromise').length;
  if (compromiseCount) lines.push(`ATENTIE: ${compromiseCount} IP-uri cu semnal de compromitere CONFIRMATA (webshell servit cu succes) -- verifica traseul de compromitere complet in dashboard.`);
  lines.push('');
  lines.push('Nota: findings/anomaliile sunt semnale automate de prioritizare, nu dovada definitiva -- verifica manual inainte de a actiona.');
  return lines.join('\n');
}

// --- Tip 4: Rezumat general de trafic (periodic, nu neaparat incident) --
// reutilizeaza buildNarrativeSummary (deja existent, Faza 3) ca baza, plus
// distributia geografica din ro_vs_world.
function _reportTraffic(s, domain) {
  const lbl = _reportDomainLabel(domain);
  const lines = [];
  lines.push(`Rezumat de trafic -- ${lbl}`);
  lines.push('');
  lines.push(buildNarrativeSummary());
  lines.push('');

  const ct = s.country_totals || [];
  const top5 = ct.slice().sort((a, b) => b.requests - a.requests).slice(0, 5);
  if (top5.length) {
    lines.push('Top 5 tari dupa volum de cereri:');
    top5.forEach(r => lines.push(`${r.country || '??'}\t${fmtNum(r.requests)}\t${r.pct}%`));
  }
  return lines.join('\n');
}

// --- Tip 5: Fraze scurte, independente -- de lipit direct intr-un
// ticket/Slack fara sa mai editezi nimic, 5-7 propozitii.
function _reportShort(s, domain) {
  const lbl = _reportDomainLabel(domain);
  const { top, params } = _reportTopAttackSignal(s);
  const ct = s.country_totals || [];
  const roReq = ct.filter(r => (r.country || '').toUpperCase() === 'RO').reduce((a, b) => a + b.requests, 0);
  // v44: "din afara Romaniei" = tara CUNOSCUTA alta decat RO (IP-urile fara tara nu sunt ghicite)
  const nonRoPct = s.total ? Math.round(100 * ct.filter(r => { const c = (r.country || '??').toUpperCase(); return c !== 'RO' && c !== '??'; }).reduce((a, b) => a + b.requests, 0) / s.total) : 0;
  const badBursts = (s.top_bursts || []).filter(b => b.classification && b.classification !== 'Normal' && b.classification !== 'Crawler');
  const wp = s.wp || {};

  const out = [];
  out.push(`Am identificat ${fmtNum(s.total)} cereri de la ${fmtNum(s.unique_ips)} IP-uri unice pe ${lbl}, aproximativ ${nonRoPct}% din afara Romaniei.`);
  if (top) {
    out.push(`Tinta principala este ${top.path}, prin enumerare de parametri de filtrare (query string)${params.length ? ' (ex. ' + params.slice(0, 3).map(p => p.key).join(', ') + ')' : ''}.`);
  }
  if (badBursts.length) {
    out.push(`Traficul depaseste ${fmtNum(badBursts[0].requests)} cereri per fereastra de 30 de secunde in perioadele de varf.`);
  }
  if (wp.wp_cron > 0) {
    out.push(`wp-cron.php a mai adaugat ${fmtNum(wp.wp_cron)} cereri, agravand impactul asupra resurselor serverului.`);
  }
  out.push('Recomandam reguli de tip rate-limiting/blocare pe combinatia path + parametru, excluzand Romania si botii verificati, ca sa nu fie afectati utilizatorii legitimi.');
  out.push(`Findings: ${fmtNum(s.findings_count)} total, ${fmtNum(s.anomalies_count)} anomalii statistice.`);
  out.push('Va rugam confirmati aplicarea masurilor de mitigare mentionate.');
  return out.join('\n');
}

const REPORT_BUILDERS = {
  attack: _reportAttack,
  client: _reportClient,
  security: _reportSecurity,
  traffic: _reportTraffic,
  short: _reportShort,
};

function refreshReport() {
  const s = CURRENT_SUMMARY;
  const out = $('#reportOutput');
  if (!s || !out) { if (out) out.textContent = ''; return; }
  const type = $('#reportType').value;
  const domain = $('#reportDomain').value.trim();
  const fn = REPORT_BUILDERS[type] || _reportTraffic;
  out.textContent = fn(s, domain);
  $('#cReports').textContent = 'actualizat acum';
}

$('#reportType').addEventListener('change', refreshReport);
$('#reportDomain').addEventListener('input', refreshReport);
$('#reportRegenBtn').addEventListener('click', refreshReport);
$('#reportCopyBtn').addEventListener('click', () => {
  const out = $('#reportOutput');
  if (out && out.textContent) copyText(out.textContent);
});

$('#modalCopy').addEventListener('click', () => {
  const pres = [...document.querySelectorAll('#modalBody pre')];
  if (pres.length) { copyText(pres.map(p => p.textContent).join('\n')); return; }
  const table = document.querySelector('#modalBody table');
  if (table) { copyTable('#modalBody table'); return; }
  copyText(document.querySelector('#modalBody').innerText || '');
});

function renderTable(sel, rows, rowFn, drillType, rowClassFn) {
  const tbody = document.querySelector(sel + ' tbody');
  if (!rows || !rows.length) { tbody.innerHTML = '<tr><td colspan="10" class="empty">Fara date</td></tr>'; return; }
  tbody.innerHTML = rows.map(r => `<tr${rowClassFn ? ' class="' + esc(rowClassFn(r) || '') + '"' : ''}>${rowFn(r).join('')}</tr>`).join('');
}

// ==========================================================================
// Helper reutilizabil #1: dropdown "Arata: 50/200/1000/Tot" + click-to-sort
// pe headere, pentru toate tabelele principale (evita duplicarea logicii de
// limitare/sortare in ~12 locuri diferite din renderSummary). Starea
// (limita curenta + coloana/directie de sortare curenta) e pastrata PER
// TABEL in TBL_STATE, indexata dupa selectorul tabelului (ex: '#tblIps'),
// si SUPRAVIETUIESTE unui renderSummary nou (schimbare de zi/interval) --
// doar array-ul de randuri (`rows`) si functia de randare (`rowFn`) se
// actualizeaza, limita/sortarea aleasa raman.
// ==========================================================================
const TBL_STATE = {};

function cellText(html) {
  const d = document.createElement('div');
  d.innerHTML = html == null ? '' : String(html);
  return (d.textContent || '').trim();
}

// Checkbox-uri de selectie (generator reguli de blocare) -- vezi helper #2
// mai jos. Definite aici ca sa poata fi folosite de renderTableEnh.
const SELECTED = { ip: new Set(), subnet: new Set(), path: new Set() };

function selCheckboxTd(type, val) {
  const checked = SELECTED[type].has(val) ? ' checked' : '';
  return `<td class="selCol"><input type="checkbox" class="ruleCheck" data-sel-type="${esc(type)}" data-sel-val="${esc(val)}"${checked}></td>`;
}

// sel: selectorul tabelului (ex: '#tblIps'); badgeSel: selectorul span-ului
// de "count" din h2 (ex: '#cIp'), sau null daca tabelul n-are unul;
// rows/rowFn/drillType/rowClassFn: exact ca la renderTable(); selType: 'ip'
// | 'subnet' | 'path' daca tabelul are coloana de checkbox pentru
// generatorul de reguli, altfel null; keyFn(r): valoarea de retinut la
// bifare (CIDR-ul subnetului, path-ul prefixului, sau IP-ul).
function renderTableEnh(sel, badgeSel, rows, rowFn, drillType, rowClassFn, selType, keyFn) {
  const st = TBL_STATE[sel] || (TBL_STATE[sel] = { limit: 50, sortIdx: null, sortDir: 1 });
  st.rows = rows || [];
  st.rowFn = rowFn;
  st.drillType = drillType;
  st.rowClassFn = rowClassFn;
  st.badgeSel = badgeSel;
  st.selType = selType || null;
  st.keyFn = keyFn || null;
  // sincronizeaza dropdown-ul de limita cu starea retinuta (in caz ca a fost
  // schimbata la un summary anterior)
  const limitSel = document.querySelector(`.rowLimitSel[data-for="${sel}"]`);
  if (limitSel) limitSel.value = String(st.limit);
  renderTableFromState(sel);
}

function renderTableFromState(sel) {
  const st = TBL_STATE[sel];
  if (!st) return;
  let rows = st.rows || [];
  if (st.sortIdx !== null && st.sortIdx !== undefined) {
    rows = [...rows].sort((a, b) => {
      const ta = cellText(st.rowFn(a)[st.sortIdx]);
      const tb = cellText(st.rowFn(b)[st.sortIdx]);
      const na = parseFloat(ta.replace(/[^0-9.\-]/g, ''));
      const nb = parseFloat(tb.replace(/[^0-9.\-]/g, ''));
      const bothNumeric = ta !== '' && tb !== '' && !isNaN(na) && !isNaN(nb) &&
        /^-?[\d.,\s]+%?$/.test(ta) && /^-?[\d.,\s]+%?$/.test(tb);
      const cmp = bothNumeric ? (na - nb) : ta.localeCompare(tb, 'ro');
      return cmp * st.sortDir;
    });
  }
  const shown = st.limit === 'all' ? rows : rows.slice(0, st.limit);
  const wrappedRowFn = st.selType
    ? (r => [selCheckboxTd(st.selType, st.keyFn(r)), ...st.rowFn(r)])
    : st.rowFn;
  renderTable(sel, shown, wrappedRowFn, st.drillType, st.rowClassFn);
  attachDrillHandlers();
  if (st.badgeSel) {
    const badge = $(st.badgeSel);
    if (badge) badge.textContent = (rows.length === shown.length) ? (shown.length + ' afisate') : (shown.length + ' din ' + rows.length);
  }
  updateSortIndicators(sel);
}

function updateSortIndicators(sel) {
  const st = TBL_STATE[sel];
  const table = document.querySelector(sel);
  if (!st || !table) return;
  table.querySelectorAll('th.sortable').forEach(th => {
    if (!th.dataset.label) th.dataset.label = th.textContent.trim();
    const idx = parseInt(th.dataset.sortIdx, 10);
    th.innerHTML = esc(th.dataset.label) + (idx === st.sortIdx ? `<span class="arrow">${st.sortDir === 1 ? '▲' : '▼'}</span>` : '');
  });
}

// Delegat GLOBAL pentru dropdown-urile "Arata:" si click-to-sort pe headere
// -- un singur listener pentru toate tabelele, in loc sa lege cate unul per
// tabel (acelasi principiu ca attachDrillHandlers pentru drill-down).
document.addEventListener('change', (e) => {
  const limitSel = e.target.closest('.rowLimitSel');
  if (limitSel) {
    const tblSel = limitSel.dataset.for;
    const st = TBL_STATE[tblSel];
    if (st) { st.limit = limitSel.value === 'all' ? 'all' : parseInt(limitSel.value, 10); renderTableFromState(tblSel); }
    return;
  }
  const cb = e.target.closest('input.ruleCheck');
  if (cb) {
    const type = cb.dataset.selType, val = cb.dataset.selVal;
    if (cb.checked) SELECTED[type].add(val); else SELECTED[type].delete(val);
    updateRuleGen();
  }
});
document.addEventListener('click', (e) => {
  const th = e.target.closest('th.sortable');
  if (!th) return;
  const table = th.closest('table');
  if (!table || !table.id) return;
  const sel = '#' + table.id;
  const st = TBL_STATE[sel];
  if (!st) return;
  const idx = parseInt(th.dataset.sortIdx, 10);
  if (st.sortIdx === idx) { st.sortDir *= -1; } else { st.sortIdx = idx; st.sortDir = 1; }
  renderTableFromState(sel);
});

// ==========================================================================
// Helper reutilizabil #2: generatorul de reguli de blocare (.htaccess +
// Cloudflare), live -- se regenereaza la fiecare (de)bifare de subnet/IP/
// prefix de path (vezi delegatul 'change' de mai sus). SELECTED e definit
// mai sus (langa selCheckboxTd), impartit intre cele 3 tipuri de selectie.
// ==========================================================================
function escApacheRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildHtaccessRules(ipsAndSubnets, paths) {
  let out = '# Generat de logscan -- verifica inainte sa aplici in productie (Apache 2.4+)\n';
  if (ipsAndSubnets.length) {
    out += '\n<RequireAll>\n  <RequireAll>\n    Require all granted\n';
    ipsAndSubnets.forEach(v => { out += `    Require not ip ${v}\n`; });
    out += '  </RequireAll>\n</RequireAll>\n';
  }
  if (paths.length) {
    out += '\nRewriteEngine on\n';
    paths.forEach(p => { out += `RewriteRule ^${escApacheRegex(p)} - [F,L]\n`; });
  }
  return out.trim() + '\n';
}

function buildCloudflareExpr(ipsAndSubnets, paths) {
  const parts = [];
  if (ipsAndSubnets.length) parts.push(`(ip.src in {${ipsAndSubnets.join(' ')}})`);
  if (paths.length) parts.push('(' + paths.map(p => `http.request.uri.path contains "${p}"`).join(' or ') + ')');
  return parts.join(' or ');
}

function updateRuleGen() {
  const ipsAndSubnets = [...SELECTED.ip, ...SELECTED.subnet];
  const paths = [...SELECTED.path];
  const chips = $('#ruleChips'), empty = $('#ruleGenEmpty'), body = $('#ruleGenBody');
  if (!ipsAndSubnets.length && !paths.length) {
    if (body) body.style.display = 'none';
    if (empty) empty.style.display = 'block';
    return;
  }
  if (empty) empty.style.display = 'none';
  if (body) body.style.display = 'block';
  if (chips) chips.innerHTML = [...ipsAndSubnets, ...paths].map(v => `<span>${esc(v)}</span>`).join('');
  const htEl = $('#ruleHtaccess'), cfEl = $('#ruleCloudflare');
  if (htEl) htEl.value = buildHtaccessRules(ipsAndSubnets, paths);
  if (cfEl) cfEl.value = buildCloudflareExpr(ipsAndSubnets, paths);
}

document.addEventListener('click', (e) => {
  if (e.target.closest('#ruleCopyHt')) { copyText($('#ruleHtaccess').value || ''); }
  if (e.target.closest('#ruleCopyCf')) { copyText($('#ruleCloudflare').value || ''); }
});

function attachDrillHandlers() {
  // Faza 3: click pe orice IP deschide panoul de DETALIU per-IP (KPI-uri +
  // findings/anomalii/crawler/admin/traseu filtrate din summary, plus buton
  // spre log-ul brut) -- vezi showIpDetail. Inainte deschidea direct
  // drillDown-ul de linii brute; acum acel drilldown ramane la un click
  // distanta (butonul "Vezi cererile brute" din panou).
  // v44: IP / URL / tara din aceste tabele pot deveni filtru GLOBAL (panoul
  // de jos, Prezentare, toate taburile) -- actiunea veche ramane in meniu.
  document.querySelectorAll('[data-ip]').forEach(el => {
    el.onclick = (e) => showEntityMenu(e, 'ip', el.dataset.ip, 'Detaliul IP (fereastra, din analiza detaliata)', () => showIpDetail(el.dataset.ip));
  });
  document.querySelectorAll('[data-path]').forEach(el => {
    el.onclick = (e) => showEntityMenu(e, 'path', el.dataset.path, 'Linii brute pentru acest path (fereastra)', () => drillDown({ path: el.dataset.path }, 'Path ' + el.dataset.path));
  });
  document.querySelectorAll('[data-ua]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillDown({ ua: el.dataset.ua }, 'UA ' + el.dataset.ua); };
  });
  // Feature #2 (Eduard): parametru de query clickable -- vezi qkey in
  // /api/dataset/{id}/raw (match pe numele parametrului din query string).
  document.querySelectorAll('[data-qkey]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillDown({ qkey: el.dataset.qkey }, 'Parametru query ' + el.dataset.qkey); };
  });
  // Feature #3 (Eduard): tabelul COMPLET de bursturi -- fiecare rand
  // deschide acelasi drill-down brut ca butonul din cardurile top 3.
  document.querySelectorAll('[data-burst-key]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillBurst(el.dataset.burstKey, el.dataset.burstLabel || 'burst'); };
  });
  // Findings care NU au un IP unic asociat (ex: wp-cron.php stacking/volum,
  // care e un semnal pe fereastra de timp, nu pe un atacator anume) --
  // dus la ACELASI endpoint /api/raw, dar filtrat pe path (+ zi/ora/minut
  // exacte cand finding-ul le are), nu pe IP. Vezi build_summary (app.py)
  // pentru cum sunt populate day/hour/minute pe aceste findings.
  document.querySelectorAll('[data-fpath]').forEach(el => {
    el.onclick = (e) => {
      e.stopPropagation();
      const params = { path: el.dataset.fpath };
      let label = el.dataset.fpath;
      if (el.dataset.fday) { params.day = el.dataset.fday; label += ' -- ' + el.dataset.fday; }
      if (el.dataset.fhour) {
        params.hour = el.dataset.fhour;
        label += ' ' + el.dataset.fhour + ':' + (el.dataset.fminute || '');
      }
      if (el.dataset.fminute) { params.minute = el.dataset.fminute; params.span = 1; }
      drillDownRaw(params, label);
    };
  });
  document.querySelectorAll('[data-subnet]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillDown({ subnet: el.dataset.subnet }, 'Subnet ' + el.dataset.subnet); };
  });
  // Feature (Eduard): tabelul "Cereri totale pe tara" -- click pe o tara
  // deschide direct cererile brute din acea tara (filtru "country" nou in
  // /api/dataset/{id}/raw).
  document.querySelectorAll('[data-country]').forEach(el => {
    el.onclick = (e) => showEntityMenu(e, 'country', el.dataset.country, 'Linii brute din aceasta tara (fereastra)', () => drillDown({ country: el.dataset.country }, 'Tara ' + el.dataset.country));
  });
  // Cardul "RO vs restul lumii" -- barele de identitate (Eduard: "aici nu
  // era bine sa pot da click, chiar daca nu e tara / valabil pentru toate").
  // Scope-ul (RO sau __non_ro__) e cel selectat in donut cand s-a randat
  // bara, ca sa filtreze exact ce se vede in card.
  document.querySelectorAll('[data-rvw-identity]').forEach(el => {
    el.onclick = (e) => {
      e.stopPropagation();
      const identity = el.dataset.rvwIdentity;
      const scope = el.dataset.rvwScope;
      const params = { identity };
      if (scope) params.country = scope;
      const label = (identity === '__none__' ? 'Fara identitate cunoscuta' : identity) + ' (' + (scope === 'RO' ? 'RO' : scope === '??' ? 'tara nedeterminata' : 'NON-RO') + ')';
      drillDown(params, label);
    };
  });
  // "Sa vad subneturile ? care il alcatuiesc?" (Eduard) -- buton separat
  // langa fiecare tara (tabelul "Cereri totale pe tara"), deschide un
  // panou cu subnetele /24 care compun acea tara (inclusiv bucketul "??"
  // de IP-uri neresolvate de geoip). Butonul e distinct de clickul pe
  // celula tarii (care duce direct la liniile brute), ca sa nu se bata.
  document.querySelectorAll('[data-country-subnets]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); showCountrySubnets(el.dataset.countrySubnets); };
  });
  // Task 3 (Eduard): badge "atac real" pe un prefix/path -- click deruleaza
  // la tabelul "Abuz parametri / filtre" (cea mai probabila sursa a
  // semnalului) si il ilumineaza scurt, in loc sa deschida un alt modal.
  document.querySelectorAll('[data-signal-jump]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); jumpToSignalSource(); };
  });
  document.querySelectorAll('[data-sig]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillDown({ sig: el.dataset.sig }, 'Semnatura ' + el.dataset.sig); };
  });
  document.querySelectorAll('[data-bot-cat]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); showBotCategory(el.dataset.botCat); };
  });
  document.querySelectorAll('[data-admin-ip]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); showAdminActivity(el.dataset.adminIp); };
  });
  document.querySelectorAll('[data-trail-ip]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); showCompromiseTrail(el.dataset.trailIp); };
  });
  // Butonul "exploreaza" din tabelul de prefixe de path (si, in interiorul
  // Path Explorer-ului insusi, orice segment care are sub-segmente) --
  // deschide/continua drill-down-ul ierarhic. Vezi openPathExplorer.
  document.querySelectorAll('[data-explore-path]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); openPathExplorer(el.dataset.explorePath); };
  });
  // Anomalii (Faza 2) a caror sursa e un burst anume (ex: clasificare
  // "Security scan"/"Suspicious automation" pe o fereastra de 30s) --
  // refolosim direct drillBurst, la fel ca butonul din cardul de bursturi.
  document.querySelectorAll('[data-anomaly-burst]').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); drillBurst(el.dataset.anomalyBurst, el.dataset.anomalyBurstLabel || 'burst'); };
  });
}

// ==========================================================================
// Path Explorer -- drill-down ierarhic pe segmente de path (cerinta directa
// a lui Eduard: vrea imaginea COMPLETA la /bijuterii/, si sa poata continua
// sa sape in sub-segmente cu trafic mare). Backend: GET
// /api/dataset/{id}/path_breakdown?prefix=...&day=... (vezi app.py --
// _scan_chunk_path_breakdown / api_path_breakdown), un singur nivel mai
// adanc de fiecare data, agregat pe path_only (fara query string).
// ==========================================================================
const PATH_EXPLORER = { prefix: '/' };

function openPathExplorer(prefix) {
  PATH_EXPLORER.prefix = prefix || '/';
  const card = $('#pathExplorerCard');
  if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  loadPathExplorer();
}
$('#pathExplorerStartRoot') && $('#pathExplorerStartRoot').addEventListener('click', () => openPathExplorer('/'));

function renderPathExplorerBreadcrumb(prefix) {
  const wrap = $('#pathExplorerBreadcrumb');
  if (!wrap) return;
  const parts = prefix === '/' ? [] : prefix.split('/').filter(Boolean);
  let html = `<span class="seg${parts.length === 0 ? ' current' : ''}" data-explore-path="/">/ (radacina)</span>`;
  let acc = '';
  parts.forEach((p, i) => {
    acc += '/' + p;
    const isLast = i === parts.length - 1;
    html += `<span class="sep">›</span><span class="seg${isLast ? ' current' : ''}" data-explore-path="${esc(acc)}">${esc(p)}</span>`;
  });
  wrap.innerHTML = html;
  wrap.querySelectorAll('.seg:not(.current)').forEach(el => {
    el.onclick = () => openPathExplorer(el.dataset.explorePath);
  });
}

function statusSummary(st) {
  if (!st) return '-';
  return `${fmtNum(st['2xx'] || 0)}/${fmtNum(st['3xx'] || 0)}/${fmtNum(st['4xx'] || 0)}/${fmtNum(st['5xx'] || 0)}`;
}

async function loadPathExplorer() {
  if (!DATASET_ID) return;
  renderPathExplorerBreadcrumb(PATH_EXPLORER.prefix);
  const body = $('#pathExplorerBody');
  const tableWrap = $('#pathExplorerTableWrap');
  body.innerHTML = '<div class="empty"><span class="spinner"></span> Se calculeaza breakdown-ul (scaneaza tot fisierul/ziua selectata)...</div>';
  body.style.display = 'block';
  tableWrap.style.display = 'none';
  const day = $('#daySelect').value;
  const qs = new URLSearchParams({ prefix: PATH_EXPLORER.prefix });
  if (day && day !== 'ALL') qs.set('day', day);
  // Daca dashboard-ul arata curent un interval scopat (hour/minute/span sau
  // second/window_seconds, ales in widgetul "Vezi cererile dintr-un moment
  // exact"), Path Explorer trebuie sa respecte ACELASI interval -- altfel
  // breakdown-ul (si liniile brute deschise din el) veneau din ziua
  // intreaga, indiferent de ora bifata (bug raportat de Eduard).
  if (IN_INTERVAL_VIEW && CURRENT_INTERVAL_PARAMS) {
    Object.entries(CURRENT_INTERVAL_PARAMS).forEach(([k, v]) => {
      if (k !== 'day' && v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
  }
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/path_breakdown?${qs.toString()}`));
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'eroare');
    renderPathExplorerResult(data);
  } catch (e) {
    body.innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
  }
}

function renderPathExplorerResult(data) {
  const body = $('#pathExplorerBody');
  const tableWrap = $('#pathExplorerTableWrap');
  const exactDiv = $('#pathExplorerExact');
  if (!data.parent_total) {
    body.innerHTML = '<div class="empty">Nicio cerere sub acest prefix ' + (gfIsActive() ? 'in selectia curenta (' + tEsc(gfDescribe()) + ').' : '(in ziua selectata).') + '</div>';
    body.style.display = 'block';
    tableWrap.style.display = 'none';
    return;
  }
  body.style.display = 'none';
  tableWrap.style.display = 'block';

  if (data.exact && data.exact.requests) {
    exactDiv.style.display = 'block';
    exactDiv.innerHTML = `(exact match, fara sub-segment) -- ${fmtNum(data.exact.requests)} cereri ` +
      `(${data.exact.pct_of_parent}% din nivel), ${fmtNum(data.exact.unique_ips)} IP unice, ` +
      `${fmtNum(data.exact.unique_subnets)} subnet-uri, ${fmtBytes(data.exact.bytes || 0)}, ` +
      `status ${statusSummary(data.exact.status)}, ${data.exact.with_query} cu query string, ` +
      `${esc(data.exact.first_seen)} &rarr; ${esc(data.exact.last_seen)}` +
      ` <button class="explorerActionBtn" data-path="${esc(data.prefix)}">vezi cereri</button>`;
  } else {
    exactDiv.style.display = 'none';
    exactDiv.innerHTML = '';
  }

  renderTableEnh('#tblPathExplorer', '#cPathExplorer', data.children || [], r => [
    `<td class="mono" style="word-break:break-all">` +
      (r.has_children
        ? `<span class="explorerSeg hasChildren" data-explore-path="${esc(r.path)}">${esc(r.path)}</span><span class="childBadge">are sub-segmente</span>`
        : `<span class="explorerSeg">${esc(r.path)}</span>`) +
      `</td>`,
    `<td class="num">${fmtNum(r.requests)}</td>`,
    `<td class="num">${r.pct_of_parent}%</td>`,
    `<td class="num">${fmtNum(r.unique_ips)}</td>`,
    `<td class="num">${fmtNum(r.unique_subnets)}</td>`,
    `<td class="num">${fmtBytes(r.bytes || 0)}</td>`,
    `<td class="mono">${statusSummary(r.status)}</td>`,
    `<td class="mono">${esc(r.first_seen)}</td>`,
    `<td class="mono">${esc(r.last_seen)}</td>`,
    `<td>` +
      (r.has_children ? `<button class="explorerActionBtn" data-explore-path="${esc(r.path)}">&#128269; exploreaza</button> ` : '') +
      `<button class="explorerActionBtn" data-path="${esc(r.path)}">vezi cereri</button></td>`
  ]);
  // click pe randul intreg (in afara butoanelor) = acelasi shortcut ca
  // butonul "exploreaza", DOAR daca segmentul are sub-segmente -- pentru
  // leaf-uri, un click pe rand nu face nimic in plus fata de butonul
  // explicit "vezi cereri" (nu vrem sa deschidem modalul din greseala la
  // orice click).
  document.querySelectorAll('#tblPathExplorer tbody tr').forEach(tr => {
    const seg = tr.querySelector('.explorerSeg.hasChildren');
    if (!seg) return;
    tr.onclick = () => openPathExplorer(seg.dataset.explorePath);
  });
  attachDrillHandlers();
}

// --------------------------------------------------------------------------
// Panou de detaliu per-IP (Faza 3) -- clic pe orice data-ip din dashboard.
// Doua surse de date:
//  1) totale exacte (cereri/bandwidth/path-uri unice/prima-ultima vazuta) --
//     dintr-un re-scan SCOPAT, lazy, declansat DOAR la deschiderea acestui
//     panou (/api/dataset/{id}/ip_detail), niciodata la upload;
//  2) tot restul (findings/anomalii/verificare crawler/activitate admin/
//     traseu de compromitere/IP suspect) -- filtrat INSTANT, client-side,
//     din CURRENT_SUMMARY deja incarcat (zero cost de server).
// --------------------------------------------------------------------------
async function showIpDetail(ip) {
  hideModalRawToolbar();
  const mseq = ++MODAL_SEQ;
  MODAL_REFRESH = () => showIpDetail(ip);
  $('#modalTitle').textContent = 'Detaliu IP: ' + ip;
  const s = CURRENT_SUMMARY || {};
  const findingsForIp = (s.findings || []).filter(f => f.ip === ip);
  const anomaliesForIp = (s.anomalies || []).filter(a => a.ip === ip);
  const suspRow = (s.suspicious_ips || []).find(x => x.ip === ip);
  const adminRow = (s.admin_activity || []).find(x => x.ip === ip);
  const trailRow = (s.compromise_trail || []).find(x => x.ip === ip);
  const crawlerVerify = CRAWLER_VERIFY_RESULTS ? CRAWLER_VERIFY_RESULTS[ip] : null;
  let crawlerProviderRow = null;
  (s.crawlers || []).forEach(c => { if ((c.ip_details || []).some(d => d.ip === ip)) crawlerProviderRow = c; });

  let html = '<div class="empty"><span class="spinner"></span> Se calculeaza totalurile (scaneaza doar liniile acestui IP)...</div>';
  $('#modalBody').innerHTML = html;
  $('#modalOverlay').style.display = 'flex';

  let agg = null;
  try {
    const day = $('#daySelect') ? $('#daySelect').value : '';
    const qs = new URLSearchParams({ ip });
    if (day && day !== 'ALL') qs.set('day', day);
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/ip_detail?${qs.toString()}`));
    if (resp.ok) agg = await resp.json();
  } catch (e) { /* ignorat -- panoul ramane util si fara agregatul exact */ }
  if (mseq !== MODAL_SEQ) return;

  const kpi = (val, lbl) => `<div class="kpi"><div class="val">${val}</div><div class="lbl">${lbl}</div></div>`;
  html = '<div class="ipDetailKpis">';
  if (agg) {
    html += kpi(fmtNum(agg.requests), 'Cereri totale') +
      kpi(fmtNum(agg.unique_paths), 'Path-uri unice') +
      kpi(fmtBytes(agg.bandwidth), 'Bandwidth') +
      kpi(flagEmoji(agg.country) + ' ' + esc(agg.country || '?'), 'Tara');
  } else {
    html += '<div class="note">Nu s-au putut calcula totalurile exacte (eroare de retea) -- vezi mai jos semnalele deja cunoscute.</div>';
  }
  html += '</div>';
  if (agg) {
    html += `<div class="note" style="margin-bottom:10px">Prima vazuta: <span class="mono">${esc(agg.first_seen || '-')}</span> &middot; Ultima vazuta: <span class="mono">${esc(agg.last_seen || '-')}</span></div>`;
  }

  html += `<div style="margin-bottom:10px"><button class="explorerActionBtn" id="ipDetailRawBtn">&#128269; Vezi cererile brute (log complet)</button></div>`;

  if (suspRow) {
    html += `<div class="ipDetailSection"><h4>IP suspect</h4><div class="note"><span class="tag ${suspRow.risk === 'HIGH' ? 'HIGH' : 'MEDIUM'}">${esc(suspRow.risk)}</span> ${(suspRow.reasons || []).map(esc).join('; ')}</div></div>`;
  }

  if (findingsForIp.length) {
    html += `<div class="ipDetailSection"><h4>Findings (${findingsForIp.length})</h4><table><thead><tr><th>Severitate</th><th>Regula</th><th>Detaliu</th><th>Ora</th></tr></thead><tbody>` +
      findingsForIp.map(f => `<tr><td><span class="tag ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.rule)}</td><td style="word-break:break-all">${esc(f.detail)}</td><td class="mono">${esc(f.time || '-')}</td></tr>`).join('') +
      '</tbody></table></div>';
  }
  if (anomaliesForIp.length) {
    html += `<div class="ipDetailSection"><h4>Anomalii (${anomaliesForIp.length})</h4><table><thead><tr><th>Severitate</th><th>Regula</th><th>Detaliu</th></tr></thead><tbody>` +
      anomaliesForIp.map(a => `<tr><td><span class="tag ${esc(a.severity)}">${esc(a.severity)}</span></td><td>${esc(a.rule)}</td><td style="word-break:break-all">${esc(a.detail)}</td></tr>`).join('') +
      '</tbody></table></div>';
  }
  if (crawlerProviderRow) {
    const cv = crawlerVerify;
    const verifTxt = cv ? (cv.verified === true ? 'verificat &#10003;' : (cv.verified === false ? 'nesigur (posibil spoofing) &#10007;' : 'neverificat')) : 'se verifica...';
    html += `<div class="ipDetailSection"><h4>Crawler</h4><div class="note">Revendica identitatea <strong>${esc(crawlerProviderRow.provider)}</strong> -- DNS: ${verifTxt}${cv && cv.ptr_hostname ? (' (' + esc(cv.ptr_hostname) + ')') : ''}. <span class="clickable mono" data-crawler-provider="${esc(crawlerProviderRow.provider)}">vezi tot providerul &rarr;</span></div></div>`;
  }
  if (adminRow) {
    html += `<div class="ipDetailSection"><h4>Activitate admin/WordPress</h4><div class="note">${fmtNum(adminRow.total_actions)} actiuni: ${Object.entries(adminRow.actions).map(([k, v]) => esc(k) + ' (' + fmtNum(v) + ')').join(', ')}. <span class="clickable mono" data-admin-ip="${esc(ip)}">vezi cronologia completa &rarr;</span></div></div>`;
  }
  if (trailRow) {
    html += `<div class="ipDetailSection"><h4>Traseu de compromitere</h4><div class="note">Categorie dominanta: <span class="catTag ${esc(trailRow.dominant_category)}">${esc(trailRow.dominant_category_label)}</span> -- scor risc ${esc(String(trailRow.risk_score))}. <span class="clickable mono" data-trail-ip="${esc(ip)}">vezi traseul complet &rarr;</span></div></div>`;
  }
  if (!findingsForIp.length && !anomaliesForIp.length && !suspRow && !adminRow && !trailRow && !crawlerProviderRow) {
    html += '<div class="ipDetailSection"><div class="empty">Niciun semnal (finding/anomalie/activitate admin) inregistrat pentru acest IP in analiza curenta.</div></div>';
  }

  $('#modalBody').innerHTML = html;
  const rawBtn = document.getElementById('ipDetailRawBtn');
  if (rawBtn) rawBtn.onclick = () => drillDown({ ip }, 'IP ' + ip);
  attachDrillHandlers();
}

// --------------------------------------------------------------------------
// "Sa vad subneturile ? care il alcatuiesc?" (Eduard) -- buton "subnete"
// langa fiecare tara din "Cereri totale pe tara" (si, la fel, refolosibil
// din cardul RO vs restul lumii). Re-scan SCOPAT, lazy, declansat doar la
// deschiderea acestui panou (/api/dataset/{id}/country_subnets), niciodata
// la upload -- acelasi tipar ca showIpDetail. Fiecare subnet din lista e
// la randul lui clickable, prin acelasi data-subnet deja cablat in
// attachDrillHandlers -- nu reinventam drilldown-ul de subnet.
async function showCountrySubnets(country) {
  hideModalRawToolbar();
  const mseq = ++MODAL_SEQ;
  MODAL_REFRESH = () => showCountrySubnets(country);
  const label = country === '??' ? 'necunoscuta (??)' : country;
  $('#modalTitle').textContent = 'Subnete /24 -- tara ' + label;
  $('#modalBody').innerHTML = '<div class="empty"><span class="spinner"></span> Se calculeaza subnetele (scaneaza doar liniile acestei tari)...</div>';
  $('#modalOverlay').style.display = 'flex';

  let data = null;
  try {
    const day = $('#daySelect') ? $('#daySelect').value : '';
    const qs = new URLSearchParams({ country });
    if (day && day !== 'ALL') qs.set('day', day);
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/country_subnets?${qs.toString()}`));
    if (resp.ok) data = await resp.json();
  } catch (e) { /* ignorat -- afisam eroarea mai jos */ }
  if (mseq !== MODAL_SEQ) return;

  if (!data || !data.subnets || !data.subnets.length) {
    $('#modalBody').innerHTML = '<div class="empty">Niciun subnet gasit pentru aceasta tara (sau eroare de retea).</div>';
    return;
  }

  let html = `<div class="note" style="margin-bottom:10px">${fmtNum(data.total_requests)} cereri, ${fmtNum(data.total_subnets)} subnete /24 distincte pentru ${flagEmoji(country)} ${esc(label)}. Click pe un subnet pentru cererile brute din acel subnet.</div>`;
  html += '<table><thead><tr><th>Subnet /24</th><th class="num">Cereri</th><th class="num">IP unice</th></tr></thead><tbody>';
  data.subnets.forEach(r => {
    html += `<tr><td class="clickable mono" data-subnet="${esc(r.subnet)}">${esc(r.subnet)}</td><td class="num">${fmtNum(r.requests)}</td><td class="num">${fmtNum(r.unique_ips)}</td></tr>`;
  });
  html += '</tbody></table>';
  $('#modalBody').innerHTML = html;
  attachDrillHandlers();
}

function showCompromiseTrail(ip) {
  hideModalRawToolbar();
  const row = (CURRENT_SUMMARY && CURRENT_SUMMARY.compromise_trail || []).find(a => a.ip === ip);
  $('#modalTitle').textContent = 'Traseu de compromitere: ' + ip + (row && row.domains && row.domains.length ? ' (' + row.domains.join(', ') + ')' : '');
  if (!row || !row.events || !row.events.length) {
    $('#modalBody').innerHTML = '<div class="empty">Fara evenimente inregistrate pentru acest IP.</div>';
  } else {
    let html = `<div class="note">${flagEmoji(row.country)} ${esc(row.country || '?')} -- scor de risc ${esc(String(row.risk_score))} (prioritizare, nu certitudine), ${row.events.length} evenimente, de la ${esc(row.first_seen)} pana la ${esc(row.last_seen)}.</div>`;
    if (row.summary && row.summary.length) {
      html += '<ul style="margin:8px 0 14px 0;padding-left:20px;font-size:13.5px">' +
        row.summary.map(s => `<li>${esc(s)}</li>`).join('') + '</ul>';
    }
    const showDomainCol = row.domains && row.domains.length > 1;
    html += '<table><thead><tr><th>Ora</th><th>Tip</th><th>Categorie</th><th>Ce</th><th>Detaliu</th>' + (showDomainCol ? '<th>Domeniu</th>' : '') + '</tr></thead><tbody>';
    const typeLabel = { finding: 'Finding', login: 'Login WP', admin: 'Admin/WP' };
    row.events.forEach(ev => {
      const sevTag = ev.severity ? `<span class="tag ${ev.severity}">${esc(ev.severity)}</span> ` : '';
      const catTag = ev.category ? `<span class="catTag ${esc(ev.category)}" title="${esc(ev.category_reason || '')}">${esc(ev.category_label || ev.category)}</span>` : '-';
      html += `<tr><td class="mono">${esc(ev.time)}</td><td>${esc(typeLabel[ev.type] || ev.type)}</td><td>${catTag}</td><td>${sevTag}${esc(ev.label)}</td><td style="word-break:break-all">${esc(ev.detail)}</td>` +
        (showDomainCol ? `<td class="mono">${esc(ev.domain || '-')}</td>` : '') + '</tr>';
    });
    html += '</tbody></table>';
    html += '<div class="note" style="margin-top:10px">Categoriile (cerere suspecta / incercare de atac / login reusit / activitate admin confirmata / compromitere confirmata) reetichetazza evenimentele deja calculate -- treci mouse-ul peste o categorie pentru motiv. "Compromitere confirmata" e rezervata unui fisier posibil webshell servit EFECTIV cu succes, nu doar cerut/scanat.</div>';
    $('#modalBody').innerHTML = html;
  }
  $('#modalOverlay').style.display = 'flex';
}

function showAdminActivity(ip) {
  hideModalRawToolbar();
  const row = (CURRENT_SUMMARY && CURRENT_SUMMARY.admin_activity || []).find(a => a.ip === ip);
  $('#modalTitle').textContent = 'Activitate admin/WP: ' + ip + (row && row.domains && row.domains.length ? ' (' + row.domains.join(', ') + ')' : '');
  if (!row || !row.events || !row.events.length) {
    $('#modalBody').innerHTML = '<div class="empty">Fara evenimente inregistrate pentru acest IP.</div>';
  } else {
    const showDomainCol = row.domains && row.domains.length > 1;
    let html = `<div class="note">${flagEmoji(row.country)} ${esc(row.country || '?')} -- ${fmtNum(row.total_actions)} actiuni in total, ${row.events.length} evenimente afisate (cronologic).</div>`;
    html += '<table><thead><tr><th>Ora</th><th>Actiune</th><th>Metoda</th><th>Path</th><th class="num">Status</th>' + (showDomainCol ? '<th>Domeniu</th>' : '') + '</tr></thead><tbody>';
    row.events.forEach(ev => {
      html += `<tr><td class="mono">${esc(ev.time)}</td><td>${esc(ev.label)}</td><td class="mono">${esc(ev.method)}</td><td class="mono" style="word-break:break-all">${esc(ev.path)}</td><td class="num">${esc(String(ev.status))}</td>` +
        (showDomainCol ? `<td class="mono">${esc(ev.domain || '-')}</td>` : '') + '</tr>';
    });
    html += '</tbody></table>';
    $('#modalBody').innerHTML = html;
  }
  $('#modalOverlay').style.display = 'flex';
}

// --------------------------------------------------------------------------
// Traffic Composition (Build 2)
// --------------------------------------------------------------------------
function renderTrafficComposition(s) {
  const rows = s.traffic_composition || [];
  $('#tblTrafficComp tbody').innerHTML = rows.map(r => `<tr>
    <td>${esc(r.category)}</td>
    <td class="num">${fmtNum(r.requests)}</td>
    <td class="num">${(r.pct != null ? r.pct : 0).toFixed(2)}%</td>
    <td class="num">${fmtNum(r.unique_ips)}</td>
    <td class="num">${fmtBytes(r.bandwidth)}</td>
    <td style="font-size:11px;word-break:break-all">${(r.top_uas || []).map(u => esc(u.ua)).join('<br>') || '-'}</td>
    <td class="mono" style="font-size:11px">${(r.top_ips || []).map(i => esc(i.ip)).join('<br>') || '-'}</td>
  </tr>`).join('');
  $('#cTrafficComp').textContent = rows.length + ' categorii -- ' +
    (rows.reduce((a, r) => a + (r.pct || 0), 0)).toFixed(1) + '% din total acoperit';
}

// --------------------------------------------------------------------------
// Crawlers (Build 3) -- Tier 1 (din summary, instant) + Tier 2 (async, DNS,
// interogat separat prin polling -- vezi pollCrawlerVerification).
// --------------------------------------------------------------------------
let CRAWLER_VERIFY_STATUS = null;   // ultimul raspuns de /crawler_verification_status
let CRAWLER_VERIFY_RESULTS = null;  // ultimul raspuns de /crawler_verification (ip -> {verified,...})
let CRAWLER_POLL_TIMER = null;
let CRAWLER_POLL_DATASET = null;

function renderCrawlers(s) {
  const rows = s.crawlers || [];
  const verifyCell = (row) => {
    if (!row.has_tier2) {
      return '<span class="verifyPill na">fara verificare (fara identitate cunoscuta)</span>';
    }
    if (!CRAWLER_VERIFY_RESULTS) {
      return '<span class="verifyPill pending"><span class="spinner" style="width:10px;height:10px;margin-right:2px"></span>se verifica...</span>';
    }
    let ok = 0, bad = 0, nc = 0;
    (row.ip_details || []).forEach(d => {
      const r = CRAWLER_VERIFY_RESULTS[d.ip];
      if (!r) { nc++; return; }
      if (r.verified === true) ok++;
      else if (r.verified === false) bad++;
      else nc++;
    });
    const pendingNote = (CRAWLER_VERIFY_STATUS && CRAWLER_VERIFY_STATUS.pending)
      ? ' <span class="verifyPill pending">se verifica...</span>' : '';
    return `<span class="verifyPill ok">&#10003; ${ok} verificat</span> ` +
      `<span class="verifyPill bad">&#10007; ${bad} nesigur</span> ` +
      `<span class="verifyPill na">${nc} neverificat</span>${pendingNote}`;
  };
  $('#tblCrawlers tbody').innerHTML = rows.map(r => `<tr class="clickableRow" data-crawler-provider="${esc(r.provider)}">
    <td><strong>${esc(r.provider)}</strong></td>
    <td class="num">${fmtNum(r.requests)}</td>
    <td class="num">${fmtNum(r.unique_ips)}</td>
    <td class="num">${fmtBytes(r.bandwidth)}</td>
    <td>${verifyCell(r)}</td>
  </tr>`).join('');
  $('#cCrawlers').textContent = rows.length + ' furnizori -- click pe un rand pentru lista de IP-uri';
  if (CRAWLER_VERIFY_STATUS) {
    const st = CRAWLER_VERIFY_STATUS;
    $('#crawlersVerifyNote').textContent = st.pending
      ? `Se verifica DNS (Tier 2): ${fmtNum(st.completed)}/${fmtNum(st.total_to_check)} IP-uri...`
      : `Verificare DNS (Tier 2) completa: ${fmtNum(st.verified_count)} verificate, ${fmtNum(st.unverified_count)} nesigure/spoofing posibil, ${fmtNum(st.not_checked_count)} neverificate (timeout/eroare) din ${fmtNum(st.total_to_check)} IP-uri care revendica o identitate cunoscuta.`;
  }
}

document.addEventListener('click', (e) => {
  const row = e.target.closest('[data-crawler-provider]');
  if (!row) return;
  showCrawlerProvider(row.dataset.crawlerProvider);
});

function showCrawlerProvider(provider) {
  hideModalRawToolbar();
  const row = (CURRENT_SUMMARY && CURRENT_SUMMARY.crawlers || []).find(c => c.provider === provider);
  $('#modalTitle').textContent = 'Crawler: ' + provider;
  if (!row || !row.ip_details || !row.ip_details.length) {
    $('#modalBody').innerHTML = '<div class="empty">Fara IP-uri inregistrate pentru acest furnizor.</div>';
    $('#modalOverlay').style.display = 'flex';
    return;
  }
  const hasTier2 = row.has_tier2;
  let verifiedSummary = '';
  if (hasTier2) {
    let ok = 0, bad = 0, nc = 0;
    row.ip_details.forEach(d => {
      const r = CRAWLER_VERIFY_RESULTS ? CRAWLER_VERIFY_RESULTS[d.ip] : null;
      if (!r) { nc++; return; }
      if (r.verified === true) ok++; else if (r.verified === false) bad++; else nc++;
    });
    verifiedSummary = ` <span class="verifyPill ok">${ok} verificat</span> <span class="verifyPill bad">${bad} nesigur</span> <span class="verifyPill na">${nc} neverificat</span>`;
  }
  let html = `<div class="note">${fmtNum(row.requests)} cereri, ${fmtNum(row.unique_ips)} IP unice, ${fmtBytes(row.bandwidth)} bandwidth.${verifiedSummary}` +
    (hasTier2 ? ' Verificarea DNS (PTR + forward-confirm) ruleaza async -- vezi coloana Verificat.' :
      ' Fara identitate revendicata cunoscuta -- fara verificare DNS Tier 2 pentru aceasta categorie.') + '</div>';
  html += '<table><thead><tr><th>IP</th><th>Tara</th><th class="num">Cereri</th>' +
    (hasTier2 ? '<th>Verificat</th><th>PTR</th><th>Top paths</th><th>Status codes</th><th>Prima/ultima vazuta</th>' : '') +
    '</tr></thead><tbody>';
  row.ip_details.forEach(d => {
    const vr = CRAWLER_VERIFY_RESULTS ? CRAWLER_VERIFY_RESULTS[d.ip] : null;
    let verifCell = '<span class="verifyPill pending">se verifica...</span>';
    let ptrCell = '-';
    if (vr) {
      ptrCell = esc(vr.ptr_hostname || '-');
      if (vr.verified === true) verifCell = '<span class="verifyPill ok">&#10003; verificat</span>';
      else if (vr.verified === false) verifCell = '<span class="verifyPill bad">&#10007; nesigur (posibil spoofing)</span>';
      else if ((vr.method || []).includes('not_dns_verifiable')) verifCell = '<span class="verifyPill na" title="furnizorul nu publica verificare prin reverse DNS, doar liste de IP -- PTR lipsa nu inseamna fals">neverificabil prin DNS</span>';
      else if ((vr.method || []).includes('known_ip_range')) verifCell = '<span class="verifyPill ok">&#10003; retea oficiala</span>';
      else verifCell = '<span class="verifyPill na">neverificat (timeout/eroare)</span>';
    }
    const topPaths = (d.top_paths || []).slice(0, 5).map(p => esc(p.path) + ' (' + fmtNum(p.requests) + ')').join('<br>') || '-';
    const statusStr = d.status_breakdown ? Object.entries(d.status_breakdown).map(([k, v]) => k + ':' + v).join(', ') : '-';
    html += `<tr>
      <td class="mono clickable" data-ip="${esc(d.ip)}">${esc(d.ip)}</td>
      ${countryCell(d.country)}
      <td class="num">${fmtNum(d.requests)}</td>` +
      (hasTier2 ? `<td>${verifCell}</td><td class="mono" style="font-size:11px">${ptrCell}</td>` +
        `<td style="font-size:11px;word-break:break-all">${topPaths}</td>` +
        `<td style="font-size:11px">${esc(statusStr)}</td>` +
        `<td style="font-size:11px">${esc(d.first_seen || '-')}<br>${esc(d.last_seen || '-')}</td>` : '') +
      `</tr>`;
  });
  html += '</tbody></table>';
  $('#modalBody').innerHTML = html;
  $('#modalOverlay').style.display = 'flex';
  attachDrillHandlers();  // altfel data-ip din acest modal ramane fara handler (bug preexistent)
}

// Polling la ~1.5s cat timp verificarea DNS Tier 2 e 'pending' -- se opreste
// singur cand serverul raporteaza pending:false. Reintra de la zero la
// fiecare renderSummary() (upload nou / schimbare de zi), leaga polling-ul
// de dataset-ul CURENT (CRAWLER_POLL_DATASET) ca sa nu continue sa bata la
// usa unui dataset vechi daca userul incarca alt fisier intre timp.
async function pollCrawlerVerification() {
  if (!DATASET_ID) return;
  if (CRAWLER_POLL_TIMER) { clearTimeout(CRAWLER_POLL_TIMER); CRAWLER_POLL_TIMER = null; }
  CRAWLER_VERIFY_STATUS = null;
  CRAWLER_VERIFY_RESULTS = null;
  CRAWLER_POLL_DATASET = DATASET_ID;
  await crawlerVerifyTick();
}

async function crawlerVerifyTick() {
  const ds = CRAWLER_POLL_DATASET;
  if (!ds || ds !== DATASET_ID) return;
  try {
    const resp = await fetch(`/api/dataset/${ds}/crawler_verification_status`);
    const st = await resp.json();
    if (!resp.ok || ds !== DATASET_ID) return;
    CRAWLER_VERIFY_STATUS = st;
    // Aducem rezultatele per-IP mereu (chiar si intermediar, in timp ce
    // pending=true) -- asa se pot vedea IP-urile confirmate pana acum,
    // fara sa se astepte finalul (vezi renderCrawlers -- contorul de
    // verificate/nesigure/neverificate se actualizeaza progresiv).
    if (st.total_to_check > 0) {
      const rresp = await fetch(`/api/dataset/${ds}/crawler_verification`);
      const rdata = await rresp.json();
      if (rresp.ok && ds === DATASET_ID) CRAWLER_VERIFY_RESULTS = rdata.results || {};
    } else {
      CRAWLER_VERIFY_RESULTS = {};
    }
    if (ds === DATASET_ID) {
      renderCrawlers(CURRENT_SUMMARY);
      // Bug #1 fix (Eduard): re-adnoteaza LIVE tabelul de IP-uri suspecte
      // (rowFn foloseste CRAWLER_VERIFY_RESULTS, actualizat mai sus) --
      // rows/rowFn raman aceleasi (deja in TBL_STATE), doar randarea se reia.
      if (TBL_STATE['#tblSusp'] && TBL_STATE['#tblSusp'].rows) renderTableFromState('#tblSusp');
      if (TBL_STATE['#tblSubnet'] && TBL_STATE['#tblSubnet'].rows) renderTableFromState('#tblSubnet');
    }
    if (st.pending && ds === DATASET_ID) {
      CRAWLER_POLL_TIMER = setTimeout(crawlerVerifyTick, 1500);
    }
    // v47: la finalul verificarii DNS, crawlerele VERIFICATE sunt scoase din
    // findings / alerte (fals pozitive) pe server -> reincarcam sumarul.
    if (!st.pending && ds === DATASET_ID && (st.verified_count || 0) > 0 && window._fpReloaded !== ds) {
      window._fpReloaded = ds;
      try {
        const r2 = await fetch(`/api/dataset/${ds}/summary`);
        const s2 = await r2.json();
        if (r2.ok && ds === DATASET_ID) {
          GF.fullSummary = s2;
          if (!GF.showingFiltered) { CURRENT_SUMMARY = s2; renderSummary(s2); }
          GF_LISTENERS.forEach(fn => { try { fn(GF.lastKey); } catch (e) {} });
          if (typeof gfRefreshOverview === 'function') gfRefreshOverview();
          const fp = s2.fp_suppressed;
          if (fp && (fp.findings || fp.suspicious_ips)) toast(`Fals pozitive eliminate: ${fp.findings} findings si ${fp.suspicious_ips} IP-uri de la ${fp.verified_crawler_ips} crawlere verificate DNS.`);
        }
      } catch (e) {}
    }
  } catch (e) {
    // eroare de retea la polling -- nu blocam dashboard-ul, doar oprim polling-ul
  }
}

function showBotCategory(category) {
  hideModalRawToolbar();
  const cat = (CURRENT_SUMMARY && CURRENT_SUMMARY.bot_breakdown || []).find(b => b.category === category);
  $('#modalTitle').textContent = 'Boti: ' + category;
  if (!cat || !cat.sample_uas || !cat.sample_uas.length) {
    $('#modalBody').innerHTML = '<div class="empty">Fara User-Agents in aceasta categorie.</div>';
  } else {
    let html = '<div class="note">User-Agents exacte clasificate in aceasta categorie (top ' +
      cat.sample_uas.length + ', dupa nr. de cereri) -- clasificarea e orientativa, bazata pe textul ' +
      'User-Agent (poate fi falsificat).</div>';
    html += '<table><thead><tr><th>User-Agent</th><th class="num">Cereri</th><th class="num">IP unice</th></tr></thead><tbody>';
    cat.sample_uas.forEach(u => {
      html += `<tr><td style="word-break:break-all">${esc(u.ua)}</td><td class="num">${fmtNum(u.requests)}</td><td class="num">${fmtNum(u.unique_ips)}</td></tr>`;
    });
    html += '</tbody></table>';
    html += '<div class="note" style="margin-top:10px">Vrei sa vezi cererile brute complete de la un anume User-Agent? Foloseste caseta de cautare din tabelul de User-Agents (mai jos in dashboard) ca sa-l gasesti, apoi cauta IP-ul in log.</div>';
    $('#modalBody').innerHTML = html;
  }
  $('#modalOverlay').style.display = 'flex';
}

async function drillDown(params, title) {
  if (!DATASET_ID) return;
  // v45: CAUZA bugului "drilldown-ul arata date din afara perioadei": aici
  // se copiau din selectia globala DOAR ip / o singura tara / path / zi --
  // intervalul de timp, codurile, severitatea etc. se pierdeau, iar /raw nu
  // avea oricum parametru de timp. Acum selectia COMPLETA pleaca in `gf`
  // (vezi drillDownRaw -> gfUrl), iar serverul intersecteaza entitatea
  // drilldown-ului cu ea, prin index.
  // Acelasi principiu ca in loadPathExplorer: daca userul e curent intr-o
  // vizualizare de interval (ora/minut bifate + "Statistici pe interval"),
  // orice drill-down pe linii brute pornit din tabelele dashboard-ului
  // (inclusiv "vezi cereri" din Path Explorer) trebuie sa ramana scopat la
  // acelasi interval -- nu doar la ziua deja setata mai sus.
  if (IN_INTERVAL_VIEW && CURRENT_INTERVAL_PARAMS) {
    Object.entries(CURRENT_INTERVAL_PARAMS).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '' && !(k in params)) params[k] = v;
    });
  }
  await drillDownRaw(params, title);
}

async function drillDownRaw(params, title) {
  if (!DATASET_ID) return;
  const mseq = ++MODAL_SEQ;
  LAST_DRILL = { kind: 'raw', params: { ...params }, title };
  showModalRawToolbar();
  const limit = $('#modalLimitSel') ? $('#modalLimitSel').value : '2000';
  const qs = new URLSearchParams({ ...params, limit }).toString();
  $('#modalTitle').textContent = 'Drill-down: ' + title;
  $('#modalBody').innerHTML = '<div class="empty"><span class="spinner"></span> Se incarca liniile brute...</div>';
  $('#modalOverlay').style.display = 'flex';
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/raw?${qs}`));
    const data = await resp.json();
    if (mseq !== MODAL_SEQ) return;   // un drilldown/o selectie mai noua l-a inlocuit
    if (!resp.ok) throw new Error(data.error || 'eroare');
    if (!data.matches.length) {
      $('#modalBody').innerHTML = modalEmptyHtml();
      return;
    }
    let html = `<div class="note">${data.matches.length} linii${data.truncated ? (' (trunchiat la limita aleasa: ' + fmtNum(data.limit || limit) + ')') : ''}</div>`;
    html += data.matches.map(m => `<pre>${esc(m.raw)}</pre>`).join('');
    $('#modalBody').innerHTML = html;
  } catch (e) {
    $('#modalBody').innerHTML = '<div class="empty">Eroare: ' + esc(e.message) + '</div>';
  }
}

$('#modalClose').addEventListener('click', () => { $('#modalOverlay').style.display = 'none'; MODAL_REFRESH = null; MODAL_SEQ++; });
function modalPlace() {
  const bar = $('#globalFilterBar'), hd = document.querySelector('header');
  const top = Math.max(0, bar && bar.offsetParent ? bar.getBoundingClientRect().bottom : 0, hd ? hd.getBoundingClientRect().bottom : 0);
  document.documentElement.style.setProperty('--gfTop', Math.round(top) + 'px');
}
new MutationObserver(() => { if (modalIsOpen()) { modalUpdateScope(); modalPlace(); } }).observe($('#modalOverlay'), { attributes: true, attributeFilter: ['style'] });
window.addEventListener('scroll', () => { if (modalIsOpen()) modalPlace(); }, { passive: true });
$('#modalOverlay').addEventListener('click', (e) => { if (e.target.id === 'modalOverlay') { $('#modalOverlay').style.display = 'none'; MODAL_REFRESH = null; MODAL_SEQ++; } });

// --- Search instant (client-side, fara request la server) pe tabelele
// principale -- ajuta sa gasesti rapid un IP/path/pattern anume intr-o
// lista de zeci de randuri, fara sa dai scroll manual.
function applyAdminActivityFilter() {
  const table = $('#tblAdminActivity');
  const cb = $('#adminNonRoOnly');
  if (!table || !cb) return;
  const onlyNonRo = cb.checked;
  const searchInp = document.querySelector('.tblSearch[data-target="#tblAdminActivity"]');
  const q = searchInp ? searchInp.value.trim().toLowerCase() : '';
  table.querySelectorAll('tbody tr').forEach(tr => {
    const matchesSearch = !q || tr.textContent.toLowerCase().includes(q);
    const matchesNonRo = !onlyNonRo || tr.classList.contains('nonRoRow');
    tr.style.display = matchesSearch && matchesNonRo ? '' : 'none';
  });
}
$('#adminNonRoOnly') && $('#adminNonRoOnly').addEventListener('change', applyAdminActivityFilter);

document.addEventListener('input', (e) => {
  const inp = e.target.closest('.tblSearch');
  if (!inp) return;
  const table = document.querySelector(inp.dataset.target);
  if (!table) return;
  if (inp.dataset.target === '#tblAdminActivity') { applyAdminActivityFilter(); return; }
  const q = inp.value.trim().toLowerCase();
  table.querySelectorAll('tbody tr').forEach(tr => {
    tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
});

// ==========================================================================
// v43 -- Upload chunked (client) + Security Triage Engine (tab "Triaj")
// ==========================================================================

// -------------------- Upload chunked, cu progres real --------------------
async function _isCompressedFile(file) {
  if (/\.(gz|tgz|zip|bz2|xz|zst|7z|rar)$/i.test(file.name)) return true;
  try {
    const h = new Uint8Array(await file.slice(0, 4).arrayBuffer());
    return (h[0] === 0x1f && h[1] === 0x8b) || (h[0] === 0x50 && h[1] === 0x4b);   // gzip / zip
  } catch (e) { return false; }
}
function _gzipBlob(blob) {
  return new Response(blob.stream().pipeThrough(new CompressionStream('gzip'))).blob();
}
let UPLOAD_CTRL = null, UPLOAD_ID = null, UPLOAD_CANCELLED = false;
function _uploadUiStart() {
  UPLOAD_CANCELLED = false;
  UPLOAD_CTRL = null; UPLOAD_ID = null;
  $('#uploadCancel').style.display = 'inline-block';
}
function _uploadUiEnd() {
  $('#uploadCancel').style.display = 'none';
  UPLOAD_CTRL = null; UPLOAD_ID = null;
}
function cancelUpload() {
  UPLOAD_CANCELLED = true;
  if (UPLOAD_CTRL) { try { UPLOAD_CTRL.abort(); } catch (e) {} }
  const id = UPLOAD_ID;
  UPLOAD_ID = null;
  if (id) fetch(`/api/upload2/cancel/${id}`, { method: 'POST' }).catch(() => {});
  $('#uploadMsg').textContent = 'Încărcare anulată.';
  $('#uploadCancel').style.display = 'none';
  setTimeout(() => {
    $('#uploadProgress').style.display = 'none';
    $('#dropzone').style.display = 'block';
  }, 300);
}
$('#uploadCancel').addEventListener('click', cancelUpload);

async function uploadFileChunked(file) {
  // v50: logurile text se comprima cu gzip IN BROWSER, bucata cu bucata (un
  // log de acces scade de ~10 ori) -- pe o conexiune obisnuita, trimiterea e
  // partea cea mai lenta, deci timpul de upload scade aproape proportional.
  // Bucata urmatoare se comprima in timp ce cea curenta se trimite.
  // Fisierele deja comprimate (.gz/.zip) se trimit ca inainte.
  // doar daca serverul confirma ca stie sa primeasca bucati gzip (un server
  // mai vechi, cu interfata noua deja pe disc, ar parsa octetii comprimati)
  let srvGz = false;
  try { const v = await (await fetch('/api/version')).json(); srvGz = v.upload_gzip === true; } catch (e) {}
  const gz = srvGz && typeof CompressionStream === 'function' && !(await _isCompressedFile(file));
  const CHUNK_SIZE = (gz ? 16 : 4) * 1024 * 1024;   // necomprimat; comprimat ~1.5 MB/cerere
  const ctrl = new AbortController();
  UPLOAD_CTRL = ctrl;
  $('#uploadMsg').textContent = `Se incarca "${file.name}" (0%)...`;
  const initResp = await fetch('/api/upload2/init', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename: file.name, total_size: file.size, encoding: gz ? 'gzip' : '' }),
    signal: ctrl.signal,
  });
  const initData = await initResp.json();
  if (!initResp.ok) throw new Error(initData.error || ('HTTP ' + initResp.status));
  const uploadId = initData.upload_id;
  UPLOAD_ID = uploadId;

  const t0 = performance.now();
  const prep = (off) => {
    const raw = file.slice(off, Math.min(off + CHUNK_SIZE, file.size));
    return gz ? _gzipBlob(raw).then(b => ({ b, n: raw.size })) : Promise.resolve({ b: raw, n: raw.size });
  };
  let sent = 0, wire = 0, idx = 0;
  let next = file.size ? prep(0) : null;
  while (next) {
    const { b, n } = await next;
    next = sent + n < file.size ? prep(sent + n) : null;
    const resp = await fetch(`/api/upload2/chunk/${uploadId}?index=${idx}`, { method: 'POST', body: b, signal: ctrl.signal });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    sent += n; wire += b.size; idx += 1;
    const pct = file.size ? Math.min(100, Math.round(100 * sent / file.size)) : 100;
    const sec = (performance.now() - t0) / 1000;
    const rate = sec > 0.5 ? ` · ${(sent / 1048576 / sec).toFixed(1)} MB/s` : '';
    const eta = (pct >= 3 && pct < 100 && sec > 1)
      ? ` · ~${fmtDur(Math.max(1, Math.round(sec * (100 - pct) / pct)))} ramase` : '';
    $('#uploadMsg').textContent = `Se incarca "${file.name}" (${pct}%)` +
      (gz ? ` · comprimat: ${(wire / 1048576).toFixed(1)} MB trimiși pentru ${(sent / 1048576).toFixed(1)} MB` : '') + rate + eta + '...';
  }

  $('#uploadMsg').textContent = `"${file.name}" incarcat -- se decomprima si se analizeaza...`;
  const compResp = await fetch(`/api/upload2/complete/${uploadId}`, { method: 'POST', signal: ctrl.signal });
  const compData = await compResp.json();
  if (!compResp.ok) throw new Error(compData.error || ('HTTP ' + compResp.status));
  const jobId = compData.job_id;
  // Dupa complete, upload-ul e inchis pe server; anularea nu mai opreste
  // indexarea. Ascundem butonul ca sa nu promitem ceva ce nu se intampla.
  $('#uploadCancel').style.display = 'none';
  UPLOAD_CTRL = null; UPLOAD_ID = null;

  const PHASE_LABELS = { queued: 'in asteptare', parsing: 'se parseaza logul', summarizing: 'se calculeaza statisticile', indexing: 'se indexeaza evenimentele de securitate' };
  for (;;) {
    await new Promise(r => setTimeout(r, 600));
    const jResp = await fetch(`/api/jobs/${jobId}`, { signal: ctrl.signal });
    const job = await jResp.json();
    if (!jResp.ok) throw new Error(job.error || ('HTTP ' + jResp.status));
    if (job.status === 'error') throw new Error(job.error || 'Eroare necunoscuta la procesare.');
    if (job.status === 'done') { window._lastUploadReused = !!job.reused; _onUploadSuccess(job); return; }
    // progres real (spec §4): procent, linii procesate, timp scurs
    const pct = typeof job.progress === 'number' ? ` ${job.progress}%` : '';
    const lines = job.lines_done ? ` -- ${Number(job.lines_done).toLocaleString('ro-RO')} linii procesate` : '';
    const el = job.elapsed ? ` (${Math.round(job.elapsed)}s)` : '';
    let eta = '';
    if (job.progress > 18 && job.progress < 92 && job.elapsed > 2) {
      const frac = (job.progress - 15) / 73;
      const rem = job.elapsed * (1 - frac) / Math.max(0.03, frac);
      if (rem > 1) eta = ` · ~${fmtDur(Math.round(rem))} ramase`;
    }
    $('#uploadMsg').textContent = `"${file.name}" -- ${PHASE_LABELS[job.status] || job.status}${pct}${lines}${el}${eta}...`;
  }
}

// -------------------- Stare + utilitare generale --------------------
// v44: O SINGURA stare de selectie (TRIAGE.filters + TRIAGE.tsFrom/tsTo),
// folosita de tabelul RAW, histograma, sinteza din panoul inferior, pagina
// Prezentare si analiza detaliata a taburilor. Fiecare cerere poarta un
// numar de generatie: un raspuns depasit de o selectie mai noua e ignorat
// (inainte, un reset venit in timpul unei incarcari era aruncat, iar
// raspunsul vechi umplea tabelul cu randurile selectiei anterioare).
function emptyTriageFilters() {
  // v45: + filtre de entitate (URL exact, clasa de cod, categorie WordPress,
  // UA exact) si EXCLUDERI -- toate in aceeasi stare unica, serializata in gf.
  return { countries: [], severities: [], statuses: [], actions: [], ip: '', pathContains: '', uaContains: '', method: '', day: '',
           pathExact: '', statusClass: [], wpCat: '', uaExact: '',
           x: { ips: [], countries: [], statuses: [], paths: [], uas: [] } };
}
const TRIAGE = {
  tzOffset: 10800, // +0300 (Romania) default, actualizat din primul ts_str real vazut
  filters: emptyTriageFilters(),
  tsFrom: null, tsTo: null,
  boundsFrom: null, boundsTo: null,
  rows: [], total: null, offset: 0, pageSize: 150, sort: 'ts_desc', loading: false, allLoaded: false,
  gen: 0, ctrl: null, histSeq: 0, histChart: null, histBuckets: [], histBucketSec: 300,
  ready: false, loadedForDataset: null, selId: null, engine: null,
  selected: new Set(), lastSelIdx: null, aborted: false,
};
const ROW_H = 30;
const RAW_COL_DEFS = [
  { key: 'ts', w: '112px' }, { key: 'ip', w: '178px' }, { key: 'status', w: '50px' },
  { key: 'path', w: 'minmax(0, 1fr)' }, { key: 'method', w: '58px' }, { key: 'signal', w: '150px' },
  { key: 'ua', w: 'minmax(0, 1fr)' },
];
const RAW_COL_KEYS = RAW_COL_DEFS.map(c => c.key);
let RAW_VIS = new Set(RAW_COL_KEYS);
try {
  const savedCols = JSON.parse(localStorage.getItem('logscan_rawcols') || 'null');
  if (Array.isArray(savedCols)) {
    const valid = savedCols.filter(k => RAW_COL_KEYS.includes(k));
    if (valid.length) RAW_VIS = new Set(valid);
  }
} catch (e) {}
function rawColCls(key) { return RAW_VIS.has(key) ? '' : ' rc-hidden'; }
const MS_DEFS = [
  { key: 'countries', btn: 'msCountry', label: 'Tara' },
  { key: 'severities', btn: 'msSeverity', label: 'Severitate' },
  { key: 'statuses', btn: 'msStatus', label: 'Status HTTP' },
  { key: 'actions', btn: 'msAction', label: 'Actiune' },
];
const SEV_ORDER_T = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// Denumiri de tara (ISO -> "RO — România") din browser, fara liste hardcodate.
const CC_NAMES = (() => { try { return new Intl.DisplayNames(['ro'], { type: 'region' }); } catch (e) { return null; } })();
const CC_NAMES_EN = (() => { try { return new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { return null; } })();
function ccName(cc) {
  if (!cc || cc === '??') return 'nedeterminata';
  if (cc === '__NON_RO__') return 'orice tara cunoscuta, alta decat RO';
  try { const n = CC_NAMES ? CC_NAMES.of(cc) : null; return n && n !== cc ? n : ''; } catch (e) { return ''; }
}
function ccLabel(cc) {
  if (!cc || cc === '??') return '?? (nedeterminata)';
  if (cc === '__NON_RO__') return 'Non-RO';
  const n = ccName(cc);
  return n ? `${cc} — ${n}` : cc;
}

function tzOffsetFromTsStr(tsStr) {
  const m = /([+-])(\d{2})(\d{2})$/.exec(tsStr || '');
  if (!m) return null;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (parseInt(m[2], 10) * 3600 + parseInt(m[3], 10) * 60);
}
function epochToDtLocal(epoch, tzOff) {
  const d = new Date((epoch + tzOff) * 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function dtLocalToEpoch(value, tzOff) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value || '');
  if (!m) return null;
  const utcMs = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  return Math.floor(utcMs / 1000) - tzOff;
}
function fmtTimeShort(tsStr) {
  // "13/Oct/2026:10:07:00 +0300" -> "13 Oct 10:07:00"
  const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/.exec(tsStr || '');
  return m ? `${m[1]} ${m[2]} ${m[4]}` : (tsStr || '');
}
async function copyToClipboard(text) {
  if (REDACT) text = redactClientText(text);
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e2) {}
    document.body.removeChild(ta);
  }
  const t = $('#copiedToast');
  t.classList.add('show');
  clearTimeout(t._hideTimer);
  t._hideTimer = setTimeout(() => t.classList.remove('show'), 1100);
}
function tEsc(s) { return (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function tEscAttr(s) { return tEsc(s); }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function setRowCount(text, kind) {
  const el = $('#triageRowCount');
  el.textContent = text || '';
  el.className = 'note' + (kind ? ' ' + kind : '');
  // cand tabelul e gol, acelasi mesaj (motivul / starea) apare si IN zona tabelului
  const em = $('#triageEmptyMsg');
  if (em) {
    em.textContent = text || '';
    em.className = (!TRIAGE.rows.length && text) ? 'on' + (kind === 'err' ? ' err' : kind === 'busy' ? ' spBusy' : '') : '';
  }
}

// -------------------- Intrare in tab / dataset nou --------------------
function triageOnDatasetLoaded() {
  TRIAGE.loadedForDataset = DATASET_ID;
  TRIAGE.ready = false;
  TRIAGE.gen++;
  if (TRIAGE.ctrl) { try { TRIAGE.ctrl.abort(); } catch (e) {} }
  TRIAGE.filters = emptyTriageFilters();
  TRIAGE._filterOptions = null;
  TRIAGE.tsFrom = TRIAGE.tsTo = TRIAGE.boundsFrom = TRIAGE.boundsTo = null;
  $('#triageIpFilter').value = ''; $('#triagePathFilter').value = '';
  $('#triageActiveFilters').innerHTML = '';
  TRIAGE.rows = []; TRIAGE.offset = 0; TRIAGE.allLoaded = false; TRIAGE.total = null; TRIAGE.loading = false;
  TRIAGE.selected = new Set(); TRIAGE.lastSelIdx = null; TRIAGE.selId = null; TRIAGE.aborted = false;
  $('#triageSpacer').style.height = '0px';
  if ($('#rawQueryStat')) $('#rawQueryStat').textContent = '';
  if ($('#rawCancelLoad')) $('#rawCancelLoad').style.display = 'none';
  rawSyncBulk();
  triageRenderVisibleRows();
  setRowCount('Se indexeaza evenimentele -- inregistrarile RAW apar automat cand indexarea e gata.', 'busy');
  $('#triageAlertsRow').innerHTML = '<div class="triageEmptyAlerts">Se incarca...</div>';
  triageRenderMultiSelects();
  gfOnDatasetLoaded();
  triageWaitForIndexAndInit();
}
async function triageWaitForIndexAndInit() {
  const myDataset = DATASET_ID;
  const note = $('#triageIndexingNote');
  note.style.display = 'block';
  // Asteptam cat dureaza indexarea, fara plafon artificial (o versiune veche
  // renunta dupa ~48s si toate cererile ulterioare primeau 202 "se
  // indexeaza", inghitite fara mesaj -- panou gol, filtrul Tara gol).
  const t0 = Date.now();
  let st = {};
  for (;;) {
    if (DATASET_ID !== myDataset) return; // s-a incarcat alt log cat asteptam
    try {
      st = await (await fetch(`/api/dataset/${myDataset}/triage_status`)).json();
    } catch (e) { st = {}; }
    if (st.ready) break;
    if (st.error) {
      note.textContent = '⚠ Indexarea a esuat: ' + st.error;
      $('#triageAlertsRow').innerHTML = '<div class="triageEmptyAlerts">Indexarea a esuat -- vezi mesajul de mai sus.</div>';
      setRowCount('Indexarea a esuat: ' + st.error + ' -- reincarca fisierul.', 'err');
      gfSetStatus('Indexarea a esuat: ' + st.error, 'err');
      spSetMsg('Panoul nu poate afisa date: indexarea a esuat (' + st.error + ').', 'err');
      return;
    }
    const sec = Math.round((Date.now() - t0) / 1000);
    note.textContent = `Se indexeaza evenimentele de securitate... (${sec}s) -- tabelul si filtrele se populeaza automat cand termina.`;
    await new Promise(r => setTimeout(r, 600));
  }
  if (DATASET_ID !== myDataset) return;
  note.style.display = 'none';
  GF.geoip = st.geoip || null;
  TRIAGE.engine = st.engine || null;
  TRIAGE.contentSha = st.content_sha || null;
  TRIAGE.filename = st.filename || '';
  TRIAGE.ready = true;
  await triageFetchTimeBounds();
  await triageLoadFilterOptions();
  triageLoadAlerts();
  triageLoadHistogram(); triageResetAndLoadEvents();
  gfAfterIndexReady();
}
function triageOnShow() {
  if (!TRIAGE.ready) return;
  setTimeout(() => { if (TRIAGE.histChart) TRIAGE.histChart.resize(); }, 30);
  if (!TRIAGE._filterOptions) triageLoadFilterOptions();
  if (TRIAGE.boundsFrom == null || TRIAGE.boundsTo == null) triageFetchTimeBounds();
  if (!$('#triageAlertsRow').querySelector('.alertCard')) triageLoadAlerts();
  admLoad();   // v47.3
  incLoad();   // v47.2: reincarca doar daca s-a schimbat datasetul sau selectia
  setTimeout(triageRenderVisibleRows, 40);
}

async function triageFetchTimeBounds() {
  try {
    const [first, last] = await Promise.all([
      fetch(`/api/dataset/${DATASET_ID}/events?sort=ts_asc&limit=1`).then(r => r.json()),
      fetch(`/api/dataset/${DATASET_ID}/events?sort=ts_desc&limit=1`).then(r => r.json()),
    ]);
    const f = (first.events || [])[0], l = (last.events || [])[0];
    if (f) TRIAGE.tzOffset = tzOffsetFromTsStr(f.ts_str) ?? TRIAGE.tzOffset;
    TRIAGE.boundsFrom = f ? f.ts : Math.floor(Date.now() / 1000) - 86400;
    TRIAGE.boundsTo = l ? l.ts : Math.floor(Date.now() / 1000);
    TRIAGE.tsFrom = TRIAGE.boundsFrom; TRIAGE.tsTo = TRIAGE.boundsTo;
    $('#triageFrom').value = epochToDtLocal(TRIAGE.tsFrom, TRIAGE.tzOffset);
    $('#triageTo').value = epochToDtLocal(TRIAGE.tsTo, TRIAGE.tzOffset);
  } catch (e) { /* ramane fallback-ul initial */ }
}

// -------------------- Alerte critice --------------------
function triageAlertCardHtml(a) {
  const hits = a.hits > 1 ? ` <span class="acHits">&times;${a.hits}</span>` : '';
  // data-alert-ip (NU data-ip): attachDrillHandlers() din v42 leaga onclick +
  // stopPropagation pe ORICE [data-ip] din pagina dupa fiecare renderSummary.
  return `<div class="alertCard sev-${tEscAttr(a.severity)}" data-alert-ip="${tEscAttr(a.ip)}" data-action="${tEscAttr(a.action_type)}" title="Click: filtreaza toata aplicatia pe acest IP">
    <div class="acTop"><span class="acIp">${tEsc(a.ip)}</span><span class="tag ${tEscAttr(a.severity)}">${tEsc(a.severity)}</span></div>
    <div class="acLabel">${tEsc(a.label || a.action_type)}${hits}</div>
    <div class="acHits">${tEsc(a.country ? ccLabel(a.country) : '?? (nedeterminata)')} &middot; ${tEsc(a.sample_path || '')}</div>
    ${(a.related || []).map(r => `<div class="acRel">+ ${tEsc(r.label || r.action_type)} &times;${fmtN(r.hits)} (${tEsc(r.severity)}, aceeasi sesiune/IP)</div>`).join('')}
  </div>`;
}
async function triageLoadAlerts() {
  try {
    const resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/alerts/top?limit=12`));
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    const alerts = data.alerts || [];
    const mv = $('#triageAlertsMoved'); if (mv) mv.textContent = data.moved_unconfirmed ? ` ${data.moved_unconfirmed} semnal(e) de acces /wp-admin/ neconfirmat nu sunt alerte -- vezi "Acces WP admin" > "Acces neconfirmat".` : '';
    const tot = data.total_ips != null ? data.total_ips : alerts.length;
    $('#triageAlertsCount').textContent = alerts.length ? (tot > alerts.length ? `(${alerts.length} din ${tot} IP-uri)` : `(${alerts.length})`) : '';
    $('#triageAlertsRow').innerHTML = alerts.length
      ? alerts.map(triageAlertCardHtml).join('')
      : '<div class="triageEmptyAlerts">Niciun semnal CRITICAL/HIGH in acest log -- nimic de prioritizat momentan.</div>';
  } catch (e) {
    $('#triageAlertsRow').innerHTML = '<div class="triageEmptyAlerts">Eroare la incarcarea alertelor: ' + tEsc(e.message) + '</div>';
  }
}
// v45: click pe o alerta = panoul de explorare al alertei (dovezile RAW,
// cronologia, IP-ul, alertele corelate) DOAR in selectia curenta; click
// dreapta / "..." = meniul de actiuni (filtreaza, exclude, audit trail...).
$('#triageAlertsRow').addEventListener('click', (e) => {
  const card = e.target.closest('.alertCard');
  if (!card) return;
  XP.open('alert', card.dataset.alertIp + '|' + card.dataset.action, 'raw');
});

// -------------------- Multi-select (Tara / Severitate / Status / Actiune) --------------------
const MS_STATE = { open: null, q: {} };
function msOptionLabel(key, o) {
  if (key === 'countries') return ccLabel(o.value);
  return String(o.value);
}
function msBodyHtml(def) {
  const opts = TRIAGE._filterOptions ? TRIAGE._filterOptions[def.key] : null;
  if (!TRIAGE.ready) return '<div class="msNote">Se indexeaza evenimentele -- optiunile apar automat in cateva secunde.</div>';
  if (!opts) return '<div class="msNote">Se incarca optiunile...</div>';
  let note = '';
  if (def.key === 'countries') {
    const g = GF.geoip || {};
    if (g.ipv4 === false) {
      note = `<div class="msNote warn">GeoIP indisponibil pe server${(g.missing || []).length ? ' (lipsesc: ' + tEsc(g.missing.join(', ')) + ')' : ''} -- tara nu poate fi determinata pentru niciun IP, deci filtrul pe o tara anume nu are ce selecta. Doar "nedeterminata" e disponibila.</div>`;
    } else if (opts.some(o => o.value === '??')) {
      note = `<div class="msNote">"??" = IP-uri pentru care GeoIP nu are tara (private/rezervate${g.ipv6 ? '' : ', IPv6 -- baza IPv6 lipseste'}). Nu sunt atribuite niciunei tari.</div>`;
    }
  }
  if (!opts.length) return note + '<div class="msNote">Nicio valoare in acest log.</div>';
  const search = (def.key === 'countries' || opts.length > 12)
    ? `<input type="text" class="msSearch" placeholder="cauta (cod sau nume)..." value="${tEscAttr(MS_STATE.q[def.key] || '')}">` : '';
  return note + search + `<div class="msList">${msListHtml(def)}</div>`;
}
function msListHtml(def) {
  const opts = (TRIAGE._filterOptions && TRIAGE._filterOptions[def.key]) || [];
  const selected = TRIAGE.filters[def.key] || [];
  const q = (MS_STATE.q[def.key] || '').trim().toLowerCase();
  const shown = q ? opts.filter(o => {
    const lab = msOptionLabel(def.key, o).toLowerCase();
    let en = '';
    if (def.key === 'countries' && CC_NAMES_EN && o.value && o.value !== '??') { try { en = (CC_NAMES_EN.of(o.value) || '').toLowerCase(); } catch (e) {} }
    return lab.includes(q) || en.includes(q);
  }) : opts;
  if (!shown.length) return '<div class="msNote">Nicio valoare nu se potriveste cautarii.</div>';
  return shown.map(o => `<label class="msOption"><input type="checkbox" value="${tEscAttr(String(o.value))}" ${selected.includes(String(o.value)) ? 'checked' : ''}><span>${tEsc(msOptionLabel(def.key, o))}</span><span class="msOptCount">${fmtN(o.count)}</span></label>`).join('');
}
function triageRenderMultiSelects() {
  MS_DEFS.forEach(def => {
    const wrap = $('#' + def.btn);
    if (!wrap) return;
    const selected = TRIAGE.filters[def.key] || [];
    const isOpen = MS_STATE.open === def.key;
    wrap.innerHTML = `
      <button type="button" class="ghost msBtn" aria-expanded="${isOpen}">${def.label}${selected.length ? ` <span class="msCount">${selected.length}</span>` : ''}</button>
      <div class="msPanel${isOpen ? ' open' : ''}">${msBodyHtml(def)}${selected.length ? '<div class="msClear">&times; sterge selectia</div>' : ''}</div>`;
    wrap.querySelector('.msBtn').addEventListener('click', (e) => {
      e.stopPropagation();
      if (MS_STATE.open && MS_STATE.open !== def.key) msClose();
      MS_STATE.open = MS_STATE.open === def.key ? null : def.key;
      if (!MS_STATE.open) { msClose(def.key); return; }
      document.querySelectorAll('.msPanel.open').forEach(p => p.classList.remove('open'));
      if (MS_STATE.open === def.key) {
        wrap.querySelector('.msPanel').classList.add('open');
        const si = wrap.querySelector('.msSearch'); if (si) si.focus();
      }
    });
    const si = wrap.querySelector('.msSearch');
    if (si) si.addEventListener('input', () => {
      MS_STATE.q[def.key] = si.value;
      wrap.querySelector('.msList').innerHTML = msListHtml(def);
    });
    // delegare: lista se poate re-randa la cautare
    wrap.querySelector('.msPanel').addEventListener('change', (e) => {
      const cb = e.target.closest('input[type=checkbox]');
      if (!cb) return;
      let vals = (TRIAGE.filters[def.key] || []).slice();
      if (cb.checked) { if (!vals.includes(cb.value)) vals.push(cb.value); }
      else vals = vals.filter(v => v !== cb.value);
      TRIAGE.filters[def.key] = vals;
      MS_STATE.open = def.key;          // panoul ramane deschis: poti bifa mai multe valori
      triageRenderMultiSelects();
      triageRenderActiveChips();
      triageReloadAll();
    });
    const clearEl = wrap.querySelector('.msClear');
    if (clearEl) clearEl.addEventListener('click', (e) => {
      e.stopPropagation();
      TRIAGE.filters[def.key] = [];
      triageRenderMultiSelects();
      triageRenderActiveChips();
      triageReloadAll();
    });
  });
}
// la inchidere, cautarea se goleste (altfel urmatoarea deschidere ar arata
// doar valorile potrivite cu o cautare veche, invizibila)
function msClose(key) {
  const k = key || MS_STATE.open;
  MS_STATE.open = null;
  document.querySelectorAll('.msPanel.open').forEach(p => p.classList.remove('open'));
  if (k && MS_STATE.q[k]) {
    MS_STATE.q[k] = '';
    const def = MS_DEFS.find(d => d.key === k);
    const wrap = def && $('#' + def.btn);
    if (wrap && wrap.querySelector('.msSearch')) { wrap.querySelector('.msSearch').value = ''; wrap.querySelector('.msList').innerHTML = msListHtml(def); }
  }
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('.msWrap') && MS_STATE.open) msClose();
});

async function triageLoadFilterOptions() {
  try {
    const resp = await fetch(`/api/dataset/${DATASET_ID}/filters`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));
    if (data.geoip) GF.geoip = data.geoip;
    TRIAGE._filterOptions = {
      countries: (data.countries || []).map(o => ({ value: o.value === '' ? '??' : o.value, count: o.count })),
      severities: (data.severities || []).sort((a, b) => (SEV_ORDER_T[a.value] ?? 9) - (SEV_ORDER_T[b.value] ?? 9)),
      statuses: (data.statuses || []).map(o => ({ value: String(o.value), count: o.count })).sort((a, b) => +a.value - +b.value),
      actions: data.action_types || [],
    };
  } catch (e) {
    TRIAGE._filterOptions = null;
    gfSetStatus('Nu am putut incarca valorile pentru filtre: ' + e.message, 'err');
  }
  triageRenderMultiSelects();
}

// -------------------- Filtre active (chips) + reset --------------------
function triageSetSingleFilter(field, value) {
  if (value == null) return;
  value = String(value);
  if (field === 'ip') { TRIAGE.filters.ip = value.trim(); $('#triageIpFilter').value = TRIAGE.filters.ip; }
  else if (field === 'path') { TRIAGE.filters.pathContains = value; $('#triagePathFilter').value = value; }
  else if (field === 'ua') { TRIAGE.filters.uaContains = value; }
  else if (field === 'method') { TRIAGE.filters.method = value.toUpperCase(); }
  else if (field === 'country') { TRIAGE.filters.countries = [value === '' ? '??' : value]; }
  else if (field === 'status') { TRIAGE.filters.statuses = [value]; }
  else if (field === 'action') { TRIAGE.filters.actions = [value]; }
  else if (field === 'severity') { TRIAGE.filters.severities = [value]; }
  else if (field === 'path_exact') { TRIAGE.filters.pathExact = value.split('?')[0]; }
  else if (field === 'sclass') { TRIAGE.filters.statusClass = [value]; }
  else if (field === 'wp') { TRIAGE.filters.wpCat = value; }
  else if (field === 'ua_exact') { TRIAGE.filters.uaExact = value; }
  else if (field === 'ts_minute') {
    // click pe un timestamp -> intervalul = minutul acelei cereri
    const t = parseInt(value, 10);
    if (!isNaN(t)) { triageSetRange(Math.floor(t / 60) * 60, Math.floor(t / 60) * 60 + 59, true); }
  }
  triageRenderMultiSelects();
  triageRenderActiveChips();
  triageReloadAll();
  // filtrul e GLOBAL: pagina curenta, graficele ei si panoul inferior se
  // actualizeaza pe loc; panoul trece pe inregistrarile RAW ale selectiei.
  if (GF.spTab !== 'raw') { GF.spTab = 'raw'; spRenderPane(); }
}
function triageSetRange(a, b, silent) {
  TRIAGE.tsFrom = Math.max(TRIAGE.boundsFrom ?? a, a);
  TRIAGE.tsTo = Math.min(TRIAGE.boundsTo ?? b, b);
  if (TRIAGE.tsTo < TRIAGE.tsFrom) TRIAGE.tsTo = TRIAGE.tsFrom;
  $('#triageFrom').value = epochToDtLocal(TRIAGE.tsFrom, TRIAGE.tzOffset);
  $('#triageTo').value = epochToDtLocal(TRIAGE.tsTo, TRIAGE.tzOffset);
  if (!silent) { triageRenderActiveChips(); triageReloadAll(); }
}
// v49: acelasi format ca selectorul de perioada (ziua din log + ora), capete incluse
function fmtRange(a, b) { const f = e => epochToDtLocalStr(e).replace(/^(\d{2}\/\w{3}\/\d{4}):/, '$1 ').replace(/ [+-]\d{4}$/, ''); return f(a) + ' – ' + f(b); }
function triageRenderActiveChips() {
  const chips = [];
  if (TRIAGE.filters.ip) chips.push(['IP', TRIAGE.filters.ip, () => { TRIAGE.filters.ip = ''; $('#triageIpFilter').value = ''; }]);
  if (TRIAGE.filters.pathContains) chips.push(['URL contine', TRIAGE.filters.pathContains, () => { TRIAGE.filters.pathContains = ''; $('#triagePathFilter').value = ''; }]);
  if (TRIAGE.filters.uaContains) chips.push(['User-Agent', TRIAGE.filters.uaContains, () => { TRIAGE.filters.uaContains = ''; }]);
  if (TRIAGE.filters.method) chips.push(['Metoda', TRIAGE.filters.method, () => { TRIAGE.filters.method = ''; }]);
  if (TRIAGE.filters.day) chips.push(['Zi', TRIAGE.filters.day, () => { TRIAGE.filters.day = ''; if ($('#daySelect')) $('#daySelect').value = 'ALL'; }]);
  if (gfTimeNarrowed()) chips.push(['Interval', fmtRange(TRIAGE.tsFrom, TRIAGE.tsTo), () => triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo, true)]);
  MS_DEFS.forEach(def => (TRIAGE.filters[def.key] || []).forEach(v => {
    chips.push([def.label, def.key === 'countries' ? ccLabel(v) : v, () => { TRIAGE.filters[def.key] = TRIAGE.filters[def.key].filter(x => x !== v); triageRenderMultiSelects(); }]);
  }));
  const F = TRIAGE.filters;
  if (F.pathExact) chips.push(['URL', F.pathExact, () => { F.pathExact = ''; }]);
  (F.statusClass || []).forEach(v => chips.push(['Clasa HTTP', v, () => { F.statusClass = F.statusClass.filter(x => x !== v); }]));
  if (F.wpCat) chips.push(['WordPress', WP_CAT_LABEL[F.wpCat] || F.wpCat, () => { F.wpCat = ''; }]);
  if (F.uaExact) chips.push(['User-Agent =', F.uaExact, () => { F.uaExact = ''; }]);
  const X = F.x || (F.x = { ips: [], countries: [], statuses: [], paths: [], uas: [] });
  [['ips', '≠ IP'], ['countries', '≠ Tara'], ['statuses', '≠ Cod'], ['paths', '≠ URL contine'], ['uas', '≠ UA contine']].forEach(([k, lbl]) =>
    (X[k] || []).forEach(v => chips.push([lbl, k === 'countries' ? ccLabel(v) : v, () => { X[k] = X[k].filter(x => x !== v); }, 'neg'])));
  $('#triageActiveFilters').innerHTML = chips.map((c, i) => `<span class="filterChip${c[3] ? ' neg' : ''}" data-i="${i}" title="Elimina doar acest filtru">${tEsc(c[0])}: ${tEsc(c[1])}<span class="x" role="button" aria-label="Elimina filtrul">&times;</span></span>`).join('');
  [...$('#triageActiveFilters').children].forEach((el, i) => {
    el.querySelector('.x').addEventListener('click', () => { chips[i][2](); triageRenderActiveChips(); triageReloadAll(); });
  });
}
$('#triageIpFilter').addEventListener('input', debounce(() => { TRIAGE.filters.ip = $('#triageIpFilter').value.trim(); triageRenderActiveChips(); triageReloadAll(); }, 400));
$('#triagePathFilter').addEventListener('input', debounce(() => { TRIAGE.filters.pathContains = $('#triagePathFilter').value.trim(); triageRenderActiveChips(); triageReloadAll(); }, 400));
$('#triageFrom').addEventListener('change', () => { const v = dtLocalToEpoch($('#triageFrom').value, TRIAGE.tzOffset); if (v != null) triageSetRange(v, TRIAGE.tsTo); });
$('#triageTo').addEventListener('change', () => { const v = dtLocalToEpoch($('#triageTo').value, TRIAGE.tzOffset); if (v != null) triageSetRange(TRIAGE.tsFrom, v); });
$('#triageResetBtn').addEventListener('click', () => {
  TRIAGE.filters = emptyTriageFilters();
  $('#triageIpFilter').value = ''; $('#triagePathFilter').value = '';
  if (TRIAGE.boundsFrom != null) triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo, true);
  if ($('#daySelect')) $('#daySelect').value = 'ALL';
  triageRenderMultiSelects();
  triageRenderActiveChips();
  triageReloadAll();
});
function triageReloadAll() {
  if (!TRIAGE.ready) return;
  triageLoadHistogram(); triageResetAndLoadEvents();
  gfOnFiltersChanged();
}

// v45: SURSA UNICA DE ADEVAR pentru selectie -- TRIAGE.filters + intervalul
// (TRIAGE.tsFrom/tsTo) serializate o singura data, in gfObject(); TOATE
// cererile (tabel, histograma, sinteza, Prezentare, taburile detaliate,
// drilldown-urile vechi, panoul de explorare, exporturile) trimit acelasi
// obiect in parametrul `gf`. Inainte, fiecare componenta isi construia
// singura parametrii -- iar drilldown-urile vechi (/raw, /ip_detail,
// /country_subnets, /path_breakdown, /burst_raw, Explorator, Extractie)
// nu primeau deloc intervalul de timp.
function gfObject(opts) {
  const f = TRIAGE.filters, o = {};
  const forceTime = opts && opts.forceTime;
  if ((forceTime || gfTimeNarrowed()) && TRIAGE.tsFrom != null && TRIAGE.tsTo != null) {
    o.ts_from = Math.floor(TRIAGE.tsFrom); o.ts_to = Math.floor(TRIAGE.tsTo);
  }
  if ((f.countries || []).length) o.countries = f.countries.map(v => v === '??' ? '' : v);
  if ((f.severities || []).length) o.severities = f.severities.slice();
  if ((f.statuses || []).length) o.statuses = f.statuses.map(Number);
  if ((f.actions || []).length) o.action_types = f.actions.slice();
  if (f.ip) o.ip = f.ip;
  if (f.method) o.method = f.method;
  if (f.pathContains) o.path_contains = f.pathContains;
  if (f.uaContains) o.ua_contains = f.uaContains;
  if (f.day) o.ts_str_day = f.day;
  if (f.pathExact) o.path_exact = f.pathExact;
  if ((f.statusClass || []).length) o.status_class = f.statusClass.slice();
  if (f.wpCat) o.wp_cat = f.wpCat;
  if (f.uaExact) o.ua = f.uaExact;
  const x = f.x || {};
  if ((x.ips || []).length) o.x_ips = x.ips.slice();
  if ((x.countries || []).length) o.x_countries = x.countries.map(v => v === '??' ? '' : v);
  if ((x.statuses || []).length) o.x_statuses = x.statuses.map(Number);
  if ((x.paths || []).length) o.x_paths = x.paths.slice();
  if ((x.uas || []).length) o.x_uas = x.uas.slice();
  return o;
}
function gfJSON(opts) { const o = gfObject(opts); return Object.keys(o).length ? JSON.stringify(o) : ''; }
function gfUrl(u, opts) { const j = gfJSON(opts); return j ? u + (u.includes('?') ? '&' : '?') + 'gf=' + encodeURIComponent(j) : u; }
function triageQueryParams(extra) {
  const p = new URLSearchParams();
  const j = gfJSON();
  if (j) p.set('gf', j);
  if (extra) Object.entries(extra).forEach(([k, v]) => p.set(k, v));
  return p;
}

// -------------------- Histograma (Chart.js) + selectie de interval --------------------
// ~150-400 bare indiferent de interval (inainte: 7 zile + 1 secunda => 8 bare de o zi)
function pickBucketSeconds(rangeSec) {
  const steps = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800];
  return steps.find(b => rangeSec / b <= 400) || 604800;
}
async function triageLoadHistogram() {
  if (TRIAGE.tsFrom == null || TRIAGE.tsTo == null) return;
  const seq = ++TRIAGE.histSeq;
  TRIAGE.histLoading = true;
  const bucket = pickBucketSeconds(Math.max(1, TRIAGE.tsTo - TRIAGE.tsFrom));
  const params = triageQueryParams({ bucket_seconds: bucket, ts_from: Math.floor(TRIAGE.tsFrom), ts_to: Math.floor(TRIAGE.tsTo) });
  let data, resp;
  try { resp = await fetch(`/api/dataset/${DATASET_ID}/histogram?${params}`); data = await resp.json(); }
  catch (e) { if (seq === TRIAGE.histSeq) { TRIAGE.histLoading = false; $('#histNote').textContent = 'Eroare la histograma: ' + e.message; } return; }
  if (seq !== TRIAGE.histSeq) return;      // o selectie mai noua a inlocuit-o
  TRIAGE.histLoading = false;
  if (!resp.ok) { $('#histNote').textContent = 'Histograma indisponibila: ' + (data.error || resp.status); return; }
  const buckets = data.buckets || [];
  const bsec = data.bucket_seconds || bucket;
  TRIAGE.histBuckets = buckets; TRIAGE.histBucketSec = bsec;
  const labels = buckets.map(b => fmtTimeShort(epochToDtLocalStr(b.bucket)));
  const unit = bsec % 86400 === 0 ? (bsec / 86400) + (bsec === 86400 ? ' zi' : ' zile') : bsec % 3600 === 0 ? (bsec / 3600) + (bsec === 3600 ? ' ora' : ' ore') : (bsec / 60) + ' min';
  $('#histNote').textContent = buckets.length
    ? `Cereri pe intervale de ${unit} pentru selectia curenta (rosu = CRITICAL, portocaliu = HIGH). Click pe o bara sau trage pe histograma ca sa restrangi intervalul -- se aplica pe toata aplicatia.`
    : 'Niciun eveniment in intervalul si filtrele curente.';
  const ctx = $('#triageHistChart').getContext('2d');
  if (TRIAGE.histChart) TRIAGE.histChart.destroy();
  TRIAGE.histChart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [
      { label: 'Altele', data: buckets.map(b => Math.max(0, b.total - b.critical - b.high)), backgroundColor: 'rgba(11,110,115,.42)', stack: 's' },
      { label: 'HIGH', data: buckets.map(b => b.high), backgroundColor: '#E08A1E', stack: 's' },
      { label: 'CRITICAL', data: buckets.map(b => b.critical), backgroundColor: '#D2384C', stack: 's' },
    ] },
    options: {
      animation: false, maintainAspectRatio: false, responsive: true,
      interaction: { mode: 'index', intersect: false },
      datasets: { bar: { barPercentage: 1, categoryPercentage: 1 } },
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        title: (items) => labels[items[0].dataIndex],
        footer: (items) => 'Total: ' + fmtN(buckets[items[0].dataIndex].total),
      } } },
      scales: {
        x: { stacked: true, ticks: { color: '#5D6A79', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }, grid: { display: false } },
        y: { stacked: true, display: false, beginAtZero: true },
      },
    },
  });
}
function epochToDtLocalStr(epoch) {
  // ts_str-compatibil ("13/Oct/2026:10:07:00 +0300") pentru fmtTimeShort
  const d = new Date((epoch + TRIAGE.tzOffset) * 1000);
  const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const pad = n => String(n).padStart(2, '0');
  return `${pad(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
}
// selectie prin "drag": UN singur set de handlere (inainte, fiecare redesenare
// adauga inca un listener mouseup pe window, care pastra bucket-urile VECHI).
let _histDrag = null;
function _histIndexAt(e) {
  if (!TRIAGE.histChart) return null;
  const rect = $('#triageHistChart').getBoundingClientRect();
  const scale = TRIAGE.histChart.scales.x;
  const val = scale.getValueForPixel(e.clientX - rect.left);
  if (val == null || !TRIAGE.histBuckets.length) return null;
  return Math.max(0, Math.min(TRIAGE.histBuckets.length - 1, Math.round(val)));
}
$('#triageHistChart').addEventListener('mousedown', (e) => {
  const idx = _histIndexAt(e);
  if (idx != null) _histDrag = { startIdx: idx, endIdx: idx, moved: false };
});
$('#triageHistChart').addEventListener('mousemove', (e) => {
  if (!_histDrag) return;
  const idx = _histIndexAt(e);
  if (idx != null && idx !== _histDrag.endIdx) { _histDrag.endIdx = idx; _histDrag.moved = true; }
});
// click simplu = bucket-ul de sub cursor (oriunde pe inaltimea graficului,
// inclusiv pe etichetele axei); drag = intervalul dintre doua bucket-uri.
window.addEventListener('mouseup', () => {
  if (!_histDrag) return;
  const d = _histDrag;
  _histDrag = null;
  const lo = Math.min(d.startIdx, d.endIdx), hi = Math.max(d.startIdx, d.endIdx);
  const b0 = TRIAGE.histBuckets[lo], b1 = TRIAGE.histBuckets[hi];
  if (b0 && b1) triageSetRange(b0.bucket, b1.bucket + TRIAGE.histBucketSec - 1);
});

// -------------------- Tabel virtualizat (panoul inferior, RAW) --------------------
async function triageResetAndLoadEvents() {
  TRIAGE.gen++;
  if (TRIAGE.ctrl) { try { TRIAGE.ctrl.abort(); } catch (e) {} }
  TRIAGE.ctrl = null; TRIAGE.loading = false;
  TRIAGE.rows = []; TRIAGE.offset = 0; TRIAGE.allLoaded = false; TRIAGE.total = null;
  TRIAGE.selected = new Set(); TRIAGE.lastSelIdx = null; TRIAGE.selId = null; TRIAGE.aborted = false;
  $('#triageViewport').scrollTop = 0;
  $('#triageSpacer').style.height = '0px';
  rawSyncBulk();
  triageRenderVisibleRows();
  setRowCount('Se incarca inregistrarile pentru selectie...', 'busy');
  await triageLoadMoreEvents(true);
}
function triageEmptyReason() {
  const f = TRIAGE.filters;
  const desc = gfDescribe({ contentOnly: true });
  const active = desc === 'tot logul' ? [] : [desc];
  const interval = (TRIAGE.tsFrom != null && TRIAGE.tsTo != null) ? ` in intervalul ${fmtRange(TRIAGE.tsFrom, TRIAGE.tsTo)}` : '';
  let why = active.length
    ? `Nicio cerere${interval} cu filtrele active (${active.join(', ')}). Elimina un filtru (x pe chip), apasa "Inapoi" sau "Reset filtre".`
    : `Nicio cerere${interval}. Largeste intervalul de timp sau apasa "Reset filtre".`;
  const g = GF.geoip || {};
  if ((f.countries || []).some(c => c !== '??') && g.ipv4 === false) {
    why += ' Atentie: GeoIP e indisponibil pe server, deci nicio cerere nu are o tara determinata -- filtrul pe tara nu poate selecta nimic.';
  }
  return why;
}
async function triageLoadMoreEvents(isReset) {
  if (!TRIAGE.ready) return;
  if (!isReset && (TRIAGE.loading || TRIAGE.allLoaded || TRIAGE.aborted)) return;
  const gen = TRIAGE.gen;
  TRIAGE.loading = true;
  TRIAGE.aborted = false;
  const ctrl = new AbortController();
  TRIAGE.ctrl = ctrl;
  const t0 = performance.now();
  const stat = $('#rawQueryStat');
  const cancelBtn = $('#rawCancelLoad');
  if (stat) stat.textContent = 'Se interogheaza...';
  if (cancelBtn) { cancelBtn.textContent = 'Anuleaza'; cancelBtn.style.display = ''; }
  const params = triageQueryParams({ limit: TRIAGE.pageSize, offset: TRIAGE.offset, sort: TRIAGE.sort, raw: 'true' });
  if (isReset) params.set('with_count', 'true');
  let data, resp;
  try {
    resp = await fetch(`/api/dataset/${DATASET_ID}/events?${params}`, { signal: ctrl.signal });
    data = await resp.json();
  } catch (e) {
    if (gen !== TRIAGE.gen) return;          // anulata de o selectie noua -- nu atingem starea ei
    TRIAGE.loading = false;
    TRIAGE.ctrl = null;
    if (e.name === 'AbortError') {
      TRIAGE.aborted = true;
      if (stat) stat.textContent = 'Interogare anulata.';
      if (cancelBtn) { cancelBtn.textContent = 'Reia'; cancelBtn.style.display = ''; }
      return;
    }
    if (stat) stat.textContent = 'Eroare.';
    if (cancelBtn) cancelBtn.style.display = 'none';
    setRowCount('Eroare de retea la incarcarea inregistrarilor: ' + e.message + '. Schimba un filtru sau apasa "Reset filtre" ca sa reincerci.', 'err');
    return;
  }
  if (gen !== TRIAGE.gen) return;
  TRIAGE.loading = false;
  TRIAGE.ctrl = null;
  if (cancelBtn) cancelBtn.style.display = 'none';
  if (resp.status === 202) {
    if (stat) stat.textContent = 'Indexare in curs';
    setRowCount('Indexarea e inca in curs -- tabelul se populeaza automat.', 'busy');
    return;
  }
  if (!resp.ok) {
    if (stat) stat.textContent = 'Eroare';
    setRowCount('Eroare: ' + (data.error || ('HTTP ' + resp.status)), 'err');
    return;
  }
  const evs = data.events || [];
  if (isReset) TRIAGE.total = (typeof data.total === 'number') ? data.total : null;
  TRIAGE.rows.push(...evs);
  TRIAGE.offset += evs.length;
  if (evs.length < TRIAGE.pageSize) TRIAGE.allLoaded = true;
  $('#triageSpacer').style.height = (TRIAGE.rows.length * ROW_H + (TRIAGE.allLoaded ? 0 : ROW_H)) + 'px';
  const elapsed = (typeof data.elapsed_ms === 'number') ? data.elapsed_ms : Math.round(performance.now() - t0);
  if (stat) {
    stat.textContent = `${TRIAGE.rows.length.toLocaleString('ro-RO')} randuri incarcate · ${elapsed.toLocaleString('ro-RO')} ms`;
    stat.title = 'Timpul ultimei interogari pe server; derularea mai incarca pagini.';
  }
  if (!TRIAGE.rows.length) {
    // Niciodata un panou gol fara explicatie: spunem DE CE e gol.
    setRowCount(triageEmptyReason(), '');
  } else {
    const n = TRIAGE.rows.length.toLocaleString('ro-RO');
    const orderTxt = TRIAGE.sort === 'risk_desc' ? 'risc maxim primele'
      : TRIAGE.sort === 'ts_asc' ? 'cele mai vechi primele' : 'cele mai noi primele';
    setRowCount((TRIAGE.total != null
      ? `${n} din ${TRIAGE.total.toLocaleString('ro-RO')} cereri care corespund selectiei (${orderTxt}; derularea incarca restul)`
      : `${n} cereri incarcate (${orderTxt})`) + ' -- click pe un rand pentru detaliul complet si linia originala din log.', '');
  }
  rawSyncBulk();
  triageRenderVisibleRows();
}
// Tipurile de actiune fara semnal (trafic obisnuit): nu se mai afiseaza
// "INFO normal" / "INFO non_ro" pe fiecare rand -- coloana arata doar ce
// merita citit (severitate peste INFO, login reusit, actiune clasificata).
const RAW_QUIET_ACTIONS = new Set(['normal', 'non_ro', '']);
function triageRowInnerHtml(ev, idx) {
  const sevTag = `<span class="tag ${tEscAttr(ev.severity)}">${tEsc(ev.severity)}</span>`;
  const isLoginOk = ev.action_type === 'admin_login_success';
  const quiet = ev.severity === 'INFO' && RAW_QUIET_ACTIONS.has(ev.action_type || '');
  const actionCell = isLoginOk
    ? `<span class="badgeLoginOk" data-audit-ip="${tEscAttr(ev.ip)}" data-audit-ts="${ev.ts}">&#10003; Login OK</span> ${sevTag}`
    : quiet ? '<span class="sigNone">&ndash;</span>'
    : `${ev.severity !== 'INFO' ? sevTag + ' ' : ''}<span class="cellInteractive" data-field="action" data-value="${tEscAttr(ev.action_type)}" style="font-size:11px" title="${tEscAttr(ev.label || ev.action_type)}">${tEsc(ev.label || ev.action_type)}</span>`;
  const ccv = ev.country || '??';
  const countryBadge = ev.is_non_ro
    ? flagHtml(ccv) + `<span class="nonRoBadge cellInteractive" data-field="country" data-value="${tEscAttr(ccv)}" title="${tEscAttr(ccLabel(ccv))}">${tEsc(ccv)}</span>`
    : flagHtml(ev.country) + `<span class="cellInteractive" data-field="country" data-value="${tEscAttr(ccv)}" style="color:var(--text-dim)" title="${tEscAttr(ev.country ? ccLabel(ccv) : 'Tara nedeterminata (GeoIP nu a rezolvat IP-ul)')}">${tEsc(ccv)}</span>`;
  const checked = TRIAGE.selected.has(Number(ev.id)) ? ' checked' : '';
  return `
    <div class="c-sel"><input type="checkbox" data-rowsel="${ev.id}" aria-label="Selecteaza cererea"${checked}></div>
    <div class="c-ts${rawColCls('ts')} cellInteractive" data-field="ts_str" data-value="${tEscAttr(ev.ts_str)}" data-ts="${ev.ts}" title="${tEscAttr(ev.ts_str)}">${tEsc(fmtTimeShort(ev.ts_str))}</div>
    <div class="c-ip${rawColCls('ip')}"><span class="cellInteractive colIp" data-field="ip" data-value="${tEscAttr(ev.ip)}">${tEsc(ev.ip)}</span> ${countryBadge}</div>
    <div class="c-status${rawColCls('status')} cellInteractive" data-field="http_status" data-value="${tEscAttr(ev.http_status)}">${tEsc(ev.http_status)}</div>
    <div class="c-path${rawColCls('path')} cellInteractive colPath" data-field="path" data-value="${tEscAttr(ev.path)}" title="${tEscAttr(ev.path)}">${tEsc(ev.path)}</div>
    <div class="c-method${rawColCls('method')} cellInteractive" data-field="method" data-value="${tEscAttr(ev.method)}">${tEsc(ev.method)}</div>
    <div class="c-signal${rawColCls('signal')}">${actionCell}</div>
    <div class="c-ua${rawColCls('ua')} cellInteractive" data-field="ua" data-value="${tEscAttr(ev.ua)}" title="${tEscAttr(ev.ua)}">${tEsc(ev.ua)}</div>
    <div class="c-act"><button class="rowCopyBtn" data-detail="1" title="Detaliul complet al cererii + linia originala din log">&#9432;</button></div>`;
}
const _rowPool = [];
function triageRenderVisibleRows() {
  const vp = $('#triageViewport');
  if (!vp) return;
  if (TRIAGE.rawView === 'lines') { rawRenderLines(); return; }
  const scrollTop = vp.scrollTop;
  const viewH = vp.clientHeight || 400;
  const firstIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - 5);
  const lastIdx = Math.min(TRIAGE.rows.length - 1, Math.ceil((scrollTop + viewH) / ROW_H) + 5);
  // reciclam nodurile existente (fara sute de noduri DOM noi la fiecare scroll)
  const needed = Math.max(0, lastIdx - firstIdx + 1);
  while (_rowPool.length < needed) {
    const row = document.createElement('div');
    row.className = 'triageRow';
    vp.appendChild(row);
    _rowPool.push(row);
  }
  _rowPool.forEach((row, i) => {
    const idx = firstIdx + i;
    if (idx > lastIdx || idx >= TRIAGE.rows.length) { row.style.display = 'none'; row._evId = null; return; }
    const ev = TRIAGE.rows[idx];
    row.style.display = '';
    row.style.transform = `translateY(${idx * ROW_H}px)`;
    row.className = 'triageRow' + (ev.severity === 'CRITICAL' || ev.severity === 'HIGH' ? ' sev-' + ev.severity : '') + (ev.id === TRIAGE.selId ? ' selRow' : '') + (TRIAGE.selected.has(Number(ev.id)) ? ' bulkSel' : '');
    row.dataset.idx = idx;
    row.dataset.evId = ev.id;
    if (row._evId !== ev.id) { row.innerHTML = triageRowInnerHtml(ev, idx); row._evId = ev.id; }
    else {
      const cb = row.querySelector('[data-rowsel]');
      if (cb) cb.checked = TRIAGE.selected.has(Number(ev.id));
    }
  });
  // pagina urmatoare se cere din timp, inainte de capatul listei
  if (TRIAGE.ready && !TRIAGE.allLoaded && !TRIAGE.loading && TRIAGE.rows.length && lastIdx > TRIAGE.rows.length - 40) {
    triageLoadMoreEvents(false);
  }
}
$('#triageViewport').addEventListener('scroll', () => { requestAnimationFrame(triageRenderVisibleRows); });
// -------------------- Raw: tabel / linii originale + copiere --------------------
function rawSetView(view) {
  TRIAGE.rawView = view === 'lines' ? 'lines' : 'table';
  try { localStorage.setItem('logscan_rawview', TRIAGE.rawView); } catch (e) {}
  document.querySelectorAll('.rawSegBtn').forEach(b => b.classList.toggle('active', b.dataset.rawview === TRIAGE.rawView));
  const card = $('#triageViewport').closest('.triageTableCard');
  if (card) card.classList.toggle('rawLines', TRIAGE.rawView === 'lines');
  _rowPool.forEach(r => { r._evId = null; });
  $('#rawLinesBox').style.display = TRIAGE.rawView === 'lines' ? '' : 'none';
  RAWLN.n = 0; $('#rawLinesBox').innerHTML = '';
  triageRenderVisibleRows();
}
// Linii originale: lista simpla (fara virtualizare), rupta pe mai multe
// randuri ca linia sa se vada INTREAGA; derularea spre capat incarca restul.
const RAWLN = { n: 0, rows: null };
function rawRenderLines() {
  const box = $('#rawLinesBox');
  if (RAWLN.rows !== TRIAGE.rows || RAWLN.n > TRIAGE.rows.length) { RAWLN.rows = TRIAGE.rows; RAWLN.n = 0; box.innerHTML = ''; }
  const more = box.querySelector('.rawLinesMore'); if (more) more.remove();
  if (TRIAGE.rows.length > RAWLN.n) {
    const html = [];
    for (let i = RAWLN.n; i < TRIAGE.rows.length; i++) {
      const ev = TRIAGE.rows[i];
      const sev = ev.severity === 'CRITICAL' || ev.severity === 'HIGH' ? ' sev-' + ev.severity : '';
      html.push(`<div class="rawLn${sev}" data-idx="${i}"><span class="rawNo">${(i + 1).toLocaleString('ro-RO')}</span><span class="rawTx">${tEsc(rawLineOf(ev))}</span></div>`);
    }
    box.insertAdjacentHTML('beforeend', html.join(''));
    RAWLN.n = TRIAGE.rows.length;
  }
  if (!TRIAGE.rows.length) box.innerHTML = `<div class="rawLinesMore">${tEsc($('#triageRowCount').textContent || 'Nicio cerere.')}</div>`;
  else if (!TRIAGE.allLoaded) box.insertAdjacentHTML('beforeend', '<div class="rawLinesMore">derulează pentru următoarele cereri...</div>');
}
$('#rawLinesBox').addEventListener('scroll', () => {
  const box = $('#rawLinesBox');
  if (TRIAGE.ready && !TRIAGE.allLoaded && !TRIAGE.loading && box.scrollTop + box.clientHeight > box.scrollHeight - 400) triageLoadMoreEvents(false);
});
$('#rawLinesBox').addEventListener('click', (e) => {
  if (String(window.getSelection() || '')) return;   // click-ul a servit la selectarea textului
  const ln = e.target.closest('.rawLn'); if (!ln) return;
  const ev = TRIAGE.rows[parseInt(ln.dataset.idx, 10)]; if (ev) openEventDetail(ev);
});
function rawLineOf(ev) {
  return ev.raw_line != null ? ev.raw_line : `${ev.ip} - - [${ev.ts_str}] "${ev.method} ${ev.path}" ${ev.http_status} ${ev.size} "${ev.referer || '-'}" "${ev.ua || '-'}"`;
}
function rawSelectedRows() { return TRIAGE.rows.filter(ev => TRIAGE.selected.has(Number(ev.id))); }
function rawSyncBulk() {
  const bar = $('#rawBulkBar');
  if (!bar) return;
  const n = TRIAGE.selected.size;
  bar.style.display = n ? '' : 'none';
  const count = $('#rawBulkCount');
  if (count) count.textContent = `${n.toLocaleString('ro-RO')} ${n === 1 ? 'rand selectat' : 'randuri selectate'}`;
  const master = $('#rawSelAll');
  if (master) {
    const loaded = TRIAGE.rows.length;
    const chosen = loaded ? TRIAGE.rows.reduce((a, ev) => a + (TRIAGE.selected.has(Number(ev.id)) ? 1 : 0), 0) : 0;
    master.disabled = !loaded;
    master.checked = loaded > 0 && chosen === loaded;
    master.indeterminate = chosen > 0 && chosen < loaded;
  }
}
function rawUpdateRowSelectionVisuals() {
  document.querySelectorAll('.triageRow[data-ev-id]').forEach(row => {
    const on = TRIAGE.selected.has(Number(row.dataset.evId));
    row.classList.toggle('bulkSel', on);
    const cb = row.querySelector('[data-rowsel]');
    if (cb) cb.checked = on;
  });
}
function rawSelectAll(on) {
  TRIAGE.rows.forEach(ev => { if (on) TRIAGE.selected.add(Number(ev.id)); else TRIAGE.selected.delete(Number(ev.id)); });
  rawUpdateRowSelectionVisuals();
  rawSyncBulk();
}
function rawCsvCell(v) {
  const s = v == null ? '' : String(v);
  return csvCell(/^[=+\-@]/.test(s) ? "'" + s : s);
}
function rawExportSelectedCsv(rows) {
  const head = ['timestamp', 'ip', 'country', 'status', 'method', 'path', 'user_agent', 'severity', 'action', 'raw_line'];
  const csv = [head.join(',')];
  rows.forEach(ev => csv.push([
    ev.ts_str, ev.ip, ev.country, ev.http_status, ev.method, ev.path, ev.ua, ev.severity, ev.action_type, rawLineOf(ev),
  ].map(rawCsvCell).join(',')));
  return '\ufeff' + csv.join('\r\n') + '\r\n';
}
function rawApplyColumns() {
  const widths = ['28px'];
  RAW_COL_DEFS.forEach(c => { if (RAW_VIS.has(c.key)) widths.push(c.w); });
  widths.push('36px');
  const card = document.querySelector('.triageTableCard');
  if (card) card.style.setProperty('--triageCols', widths.join(' '));
  document.querySelectorAll('.triageTableHead [data-rawcol]').forEach(h => h.classList.toggle('rc-hidden', !RAW_VIS.has(h.dataset.rawcol)));
  document.querySelectorAll('.triageRow [class*="c-"]').forEach(cell => {
    const m = String(cell.className).match(/\bc-(ts|ip|status|path|method|signal|ua)\b/);
    if (m) cell.classList.toggle('rc-hidden', !RAW_VIS.has(m[1]));
  });
  document.querySelectorAll('#rawColsMenu input[data-rawcol]').forEach(cb => { cb.checked = RAW_VIS.has(cb.dataset.rawcol); });
}
function rawSaveColumns() { try { localStorage.setItem('logscan_rawcols', JSON.stringify([...RAW_VIS])); } catch (e) {} }
function rawResetColumns() {
  RAW_VIS = new Set(RAW_COL_KEYS);
  rawSaveColumns();
  rawApplyColumns();
}
$('#rawColsMenu').addEventListener('change', (e) => {
  const cb = e.target.closest('input[data-rawcol]');
  if (!cb) return;
  const key = cb.dataset.rawcol;
  if (!cb.checked && RAW_VIS.size <= 1) {
    cb.checked = true;
    toast('Pastreaza cel putin o coloana vizibila.');
    return;
  }
  if (cb.checked) RAW_VIS.add(key); else RAW_VIS.delete(key);
  rawSaveColumns();
  rawApplyColumns();
});
$('#rawColsReset').addEventListener('click', () => rawResetColumns());
document.addEventListener('click', (e) => {
  const menu = $('#rawColsMenu');
  if (menu && menu.open && !e.target.closest('#rawColsMenu')) menu.open = false;
});
function rawToggleSelectedById(id, force) {
  id = Number(id);
  const on = force === undefined ? !TRIAGE.selected.has(id) : !!force;
  if (on) TRIAGE.selected.add(id); else TRIAGE.selected.delete(id);
  return on;
}
$('#rawBulkBar').addEventListener('click', async (e) => {
  const act = e.target.closest('[data-bulk]')?.dataset.bulk;
  if (!act) return;
  const rows = rawSelectedRows();
  if (act === 'clear') {
    TRIAGE.selected = new Set(); TRIAGE.lastSelIdx = null; TRIAGE.selId = null;
    rawUpdateRowSelectionVisuals(); rawSyncBulk(); triageRenderVisibleRows();
    return;
  }
  if (!rows.length) { toast('Selecteaza mai intai cel putin un rand.'); return; }
  if (act === 'copy') {
    await copyToClipboard(rows.map(rawLineOf).join('\n') + '\n');
    toast(`Copiate ${rows.length.toLocaleString('ro-RO')} linii din selectie.`);
    return;
  }
  if (act === 'csv') {
    downloadFile('logscan-selectie.csv', rawExportSelectedCsv(rows), 'text/csv;charset=utf-8');
    toast(`Export CSV: ${rows.length.toLocaleString('ro-RO')} randuri.`);
  }
});
function rawExportUrl(limit) {
  const p = triageQueryParams({ format: 'log', kind: 'sel' });
  if (limit) p.set('limit', String(limit));
  return redactUrl(`/api/dataset/${DATASET_ID}/export_events?${p}`);
}
$('#rawBar').addEventListener('click', async (e) => {
  const seg = e.target.closest('[data-rawview]');
  if (seg) { rawSetView(seg.dataset.rawview); return; }
  if (e.target.closest('#rawCopyLoaded')) {
    if (!TRIAGE.rows.length) { toast('Nicio cerere incarcata in tabel.'); return; }
    await copyToClipboard(TRIAGE.rows.map(rawLineOf).join('\n') + '\n');
    toast(`Copiate ${TRIAGE.rows.length.toLocaleString('ro-RO')} linii originale (randurile incarcate).`);
    return;
  }
  if (e.target.closest('#rawCopyAll')) {
    if (!DATASET_ID || !TRIAGE.ready) return;
    const LIM = 50000;
    const btn = $('#rawCopyAll'); btn.disabled = true; const old = btn.textContent; btn.textContent = 'Se copiaza...';
    try {
      const r = await fetch(rawExportUrl(LIM));
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const txt = await r.text();
      const total = parseInt(r.headers.get('X-Total-Matched') || '0', 10);
      const n = parseInt(r.headers.get('X-Exported') || '0', 10);
      await copyToClipboard(txt);
      toast(total > n
        ? `Copiate primele ${n.toLocaleString('ro-RO')} din ${total.toLocaleString('ro-RO')} linii (ordine cronologica). Pentru toate, foloseste "Descarca .log".`
        : `Copiate toate cele ${n.toLocaleString('ro-RO')} linii originale ale selectiei (ordine cronologica).`);
    } catch (err) { toast('Copierea a esuat: ' + err.message); }
    finally { btn.disabled = false; btn.textContent = old; }
    return;
  }
  if (e.target.closest('#rawDlAll')) {
    if (!DATASET_ID || !TRIAGE.ready) return;
    const a = document.createElement('a'); a.href = rawExportUrl(0); a.download = ''; document.body.appendChild(a); a.click(); a.remove();
  }
});
try { if (localStorage.getItem('logscan_rawview') === 'lines') setTimeout(() => rawSetView('lines'), 0); } catch (e) {}
window.addEventListener('resize', () => { triageRenderVisibleRows(); });

// -------------------- Click pe rand / celula --------------------
$('#triageViewport').addEventListener('click', (e) => {
  const auditBadge = e.target.closest('[data-audit-ip]');
  if (auditBadge) { openAuditDrawer(auditBadge.dataset.auditIp, parseInt(auditBadge.dataset.auditTs, 10)); return; }
  const cb = e.target.closest('[data-rowsel]');
  const row = e.target.closest('.triageRow');
  const ev = row ? TRIAGE.rows[parseInt(row.dataset.idx, 10)] : null;
  if (cb && ev) {
    const idx = parseInt(row.dataset.idx, 10);
    if (e.shiftKey && TRIAGE.lastSelIdx != null) {
      const lo = Math.min(TRIAGE.lastSelIdx, idx), hi = Math.max(TRIAGE.lastSelIdx, idx);
      const on = cb.checked;
      for (let i = lo; i <= hi; i++) {
        const item = TRIAGE.rows[i];
        if (!item) continue;
        if (on) TRIAGE.selected.add(Number(item.id)); else TRIAGE.selected.delete(Number(item.id));
      }
    } else {
      rawToggleSelectedById(ev.id, cb.checked);
    }
    TRIAGE.lastSelIdx = idx;
    TRIAGE.selId = ev.id;
    document.querySelectorAll('.triageRow.selRow').forEach(r => r.classList.remove('selRow'));
    row.classList.add('selRow');
    rawUpdateRowSelectionVisuals();
    rawSyncBulk();
    return;
  }
  if (e.target.closest('[data-detail]')) { if (ev) openEventDetail(ev); return; }
  const cell = e.target.closest('.cellInteractive');
  if (cell) { showCellPopover(cell, cell.dataset.field, cell.dataset.value, ev); return; }
  if (ev) openEventDetail(ev);
});
$('.triageTableHead').addEventListener('change', (e) => {
  if (e.target.id !== 'rawSelAll') return;
  rawSelectAll(e.target.checked);
});
$('#rawCancelLoad').addEventListener('click', () => {
  if (TRIAGE.aborted) {
    TRIAGE.aborted = false;
    triageResetAndLoadEvents();
    return;
  }
  if (TRIAGE.ctrl) { try { TRIAGE.ctrl.abort(); } catch (e) {} }
});
function rawSetSort(sort, persist) {
  if (!['ts_desc', 'ts_asc', 'risk_desc'].includes(sort)) sort = 'ts_desc';
  TRIAGE.sort = sort;
  const sel = $('#rawSort'); if (sel) sel.value = sort;
  if (persist) { try { localStorage.setItem('logscan_rawsort', sort); } catch (e) {} }
}
function rawSetPageSize(n, persist) {
  n = parseInt(n, 10);
  if (![150, 300, 600].includes(n)) n = 150;
  TRIAGE.pageSize = n;
  const sel = $('#rawPageSize'); if (sel) sel.value = String(n);
  if (persist) { try { localStorage.setItem('logscan_rawpagesize', String(n)); } catch (e) {} }
}
$('#rawSort').addEventListener('change', (e) => {
  rawSetSort(e.target.value, true);
  triageResetAndLoadEvents();
});
$('#rawPageSize').addEventListener('change', (e) => {
  rawSetPageSize(e.target.value, true);
  triageResetAndLoadEvents();
});
$('#rawConfirmed').addEventListener('click', () => {
  presetApply(f => { f.severities = ['CRITICAL', 'HIGH']; f.statusClass = ['2xx']; }, 'Atac confirmat (CRITICAL/HIGH + 2xx)');
});
try {
  rawSetSort(localStorage.getItem('logscan_rawsort') || 'ts_desc', false);
  rawSetPageSize(localStorage.getItem('logscan_rawpagesize') || 150, false);
} catch (e) { rawSetSort('ts_desc', false); rawSetPageSize(150, false); }
rawApplyColumns();
rawSyncBulk();

function showCellPopover(anchorEl, field, value, ev) {
  const pop = $('#cellPopover');
  const rect = anchorEl.getBoundingClientRect();
  const filterLabel = {
    ip: 'Filtreaza toata aplicatia pe acest IP', country: 'Filtreaza toata aplicatia pe aceasta tara',
    path: 'Filtreaza pe URL-uri care contin asta', http_status: 'Filtreaza pe acest cod HTTP',
    ts_str: 'Restrange intervalul la minutul acestei cereri', ua: 'Filtreaza pe acest User-Agent',
    method: 'Filtreaza pe aceasta metoda', action: 'Filtreaza pe acest tip de actiune',
  }[field] || 'Filtreaza dupa asta';
  const shown = field === 'country' ? ccLabel(value) : value;
  pop.innerHTML = `
    <div class="cpVal">${tEsc(shown || '(gol)')}</div>
    <div class="cpItem" data-act="filter">&#128269; ${tEsc(filterLabel)}</div>
    ${field === 'ip' ? '<div class="cpItem" data-act="profile">&#128100; Profil IP (activitatea pe intervalul selectat)</div>' : ''}
    ${ev ? '<div class="cpItem" data-act="detail">&#128196; Detaliul complet al cererii</div>' : ''}
    <div class="cpItem" data-act="copy">&#10697; Copiaza</div>`;
  pop.style.left = Math.max(4, Math.min(window.innerWidth - 300, rect.left)) + 'px';
  pop.style.top = Math.max(4, Math.min(window.innerHeight - 170, rect.bottom + 4)) + 'px';
  pop.classList.add('open');
  pop.querySelector('[data-act="copy"]').onclick = () => { copyToClipboard(value || ''); pop.classList.remove('open'); };
  const prof = pop.querySelector('[data-act="profile"]');
  if (prof) prof.onclick = () => { pop.classList.remove('open'); openIpProfile(value); };
  const det = pop.querySelector('[data-act="detail"]');
  if (det) det.onclick = () => { pop.classList.remove('open'); openEventDetail(ev); };
  pop.querySelector('[data-act="filter"]').onclick = () => {
    pop.classList.remove('open');
    const map = { ip: 'ip', country: 'country', path: 'path', http_status: 'status', action: 'action', ua: 'ua', method: 'method' };
    if (field === 'ts_str') triageSetSingleFilter('ts_minute', anchorEl.dataset.ts);
    else if (map[field]) triageSetSingleFilter(map[field], value);
    else copyToClipboard(value || '');
  };
}
document.addEventListener('click', (e) => { if (!e.target.closest('#cellPopover')) $('#cellPopover').classList.remove('open'); }, true);

// -------------------- Sertarul din dreapta: audit / detaliu / profil --------------------
function openDrawer(title, subtitle) {
  $('#auditOverlay').classList.add('open');
  $('#auditDrawer').classList.add('open');
  $('#adTitle').textContent = title;
  $('#adSubtitle').textContent = subtitle || '';
  $('#adBody').innerHTML = '';
  $('#auditDrawer').dataset.seq = String((+$('#auditDrawer').dataset.seq || 0) + 1);
  return $('#auditDrawer').dataset.seq;
}
function drawerStillMine(seq) { return $('#auditDrawer').dataset.seq === seq && $('#auditDrawer').classList.contains('open'); }
let AUDIT_LAST = null;
async function openAuditDrawer(ip, ts) {
  AUDIT_LAST = [ip, ts];
  const seq = openDrawer('Audit Trail -- ' + ip, 'Se incarca sesiunea...');
  const params = new URLSearchParams({ ip });
  if (ts != null && !isNaN(ts)) params.set('ts', ts);
  let data, resp;
  try { resp = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/admin_session?${params}`)); data = await resp.json(); }
  catch (e) { if (drawerStillMine(seq)) $('#adSubtitle').textContent = 'Eroare la incarcare: ' + e.message; return; }
  if (!drawerStillMine(seq)) return;
  if (!resp.ok) { $('#adSubtitle').textContent = 'Eroare: ' + (data.error || resp.status); return; }
  const evs = data.events || [];
  $('#adSubtitle').textContent = evs.length ? `${evs.length} cereri in +/-30 min in jurul autentificarii` : 'Niciun login gasit pentru acest IP -- nimic de reconstituit.';
  const mins = Math.round((data.duration_seconds || 0) / 60 * 10) / 10;
  const kpis = `<div class="adSummary">
    <div class="kpi"><div class="val">${evs.length}</div><div class="lbl">Cereri</div></div>
    <div class="kpi"><div class="val">${mins}m</div><div class="lbl">Durata sesiune</div></div>
  </div><div class="spMsg">O autentificare reusita e dedusa (POST wp-login 302 urmat de /wp-admin/ 200 in max 5 min) -- e un indicator, nu o certitudine; confirma din logul aplicatiei WordPress.</div>`;
  const list = evs.map(ev => `<div class="adEvent">
      <span class="adTime">${tEsc(fmtTimeShort(ev.ts_str).split(' ').slice(-1)[0])}</span>
      <span class="adMethod">${tEsc(ev.method)}</span>
      <span class="adPath" title="${tEscAttr(ev.path)}">${tEsc(ev.path)}</span>
      <span class="adStatus">${tEsc(ev.http_status)}</span>
    </div>`).join('');
  $('#adBody').innerHTML = kpis + list;
}
function closeAuditDrawer() { $('#auditOverlay').classList.remove('open'); $('#auditDrawer').classList.remove('open'); }
$('#auditOverlay').addEventListener('click', closeAuditDrawer);
$('#adCloseBtn').addEventListener('click', closeAuditDrawer);
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  closeAuditDrawer();
  $('#cellPopover').classList.remove('open');
  $('#entityMenu').classList.remove('open');
  if (MS_STATE.open) msClose();
});

const STATUS_HINT = { 2: 'succes', 3: 'redirect', 4: 'eroare client', 5: 'eroare server' };
async function openEventDetail(ev) {
  TRIAGE.selId = ev.id;
  _rowPool.forEach(r => { r._evId = null; });
  triageRenderVisibleRows();
  const seq = openDrawer('Cererea #' + ev.id, ev.ts_str);
  const row = (k, v, raw) => `<div class="k">${tEsc(k)}</div><div class="v">${raw ? v : tEsc(v == null || v === '' ? '-' : v)}</div>`;
  const render = (d, rawLine, loading) => {
    const cc = d.country || '';
    const st = +d.http_status;
    const sevNote = d.severity && d.severity !== 'INFO'
      ? `<div class="spMsg">Clasificarea (${tEsc(d.severity)} -- ${tEsc(d.label || d.action_type)}) e un INDICATOR calculat din reguli pe URL/cod/tara, nu o confirmare de atac.</div>` : '';
    $('#adBody').innerHTML = `
      <div class="evActions">
        <button class="ghost" data-ev="ip">&#128269; Activitatea acestui IP</button>
        <button class="ghost" data-ev="country">&#127758; Tara ${tEsc(cc || '??')}</button>
        <button class="ghost" data-ev="path">URL (fara query)</button>
        <button class="ghost" data-ev="status">Cod ${tEsc(d.http_status)}</button>
        <button class="ghost" data-ev="profile">&#128100; Profil IP</button>
      </div>
      <div class="evGrid">
        ${row('Timp', d.ts_str)}
        ${row('IP', d.ip)}
        ${row('Tara', cc ? ccLabel(cc) : 'nedeterminata (GeoIP nu are tara pentru acest IP -- nu e ghicita)')}
        ${row('Metoda', d.method)}
        ${row('URL', d.path)}
        ${d.path_decoded && d.path_decoded !== d.path ? row('URL decodat', d.path_decoded) : ''}
        ${d.query ? row('Query string', d.query) : ''}
        ${row('Cod HTTP', `${d.http_status}${STATUS_HINT[Math.floor(st / 100)] ? ' (' + STATUS_HINT[Math.floor(st / 100)] + ')' : ''}`)}
        ${row('Marime', d.size != null ? fmtBytes(+d.size) : '-')}
        ${row('Referer', d.referer)}
        ${row('User-Agent', d.ua)}
        ${row('Severitate', d.severity)}
        ${row('Clasificare', d.label || d.action_type)}
        ${d.domain ? row('Domeniu', d.domain) : ''}
      </div>
      ${sevNote}
      <div class="ipProfSec">Linia originala din log ${rawLine ? '<button class="spBtnMini" data-ev="copyraw">&#10697; copiaza linia</button>' : ''}<button class="spBtnMini" data-ev="copyjson">{ } copiaza ca JSON</button><button class="spBtnMini" data-ev="copytsv">&#9776; copiaza ca text</button></div>
      <div class="evRaw">${loading ? '<span class="spBusy">se citeste din fisier...</span>' : tEsc(rawLine || '(linia originala nu mai e disponibila -- datasetul a expirat?)')}</div>`;
    $('#adBody').querySelectorAll('[data-ev]').forEach(b => b.onclick = () => {
      const a = b.dataset.ev;
      if (a === 'copyraw') { copyToClipboard(rawLine || ''); return; }
      if (a === 'copyjson') { copyToClipboard(JSON.stringify(d, null, 2)); return; }
      if (a === 'copytsv') { copyToClipboard([d.ts_str, d.ip, d.country, d.method, d.path, d.http_status, d.severity, d.action_type, d.ua].join('\t')); return; }
      if (a === 'profile') { openIpProfile(d.ip); return; }
      closeAuditDrawer();
      if (a === 'ip') triageSetSingleFilter('ip', d.ip);
      else if (a === 'country') triageSetSingleFilter('country', cc || '??');
      else if (a === 'path') triageSetSingleFilter('path', (d.path || '').split('?')[0]);
      else if (a === 'status') triageSetSingleFilter('status', d.http_status);
    });
  };
  render(ev, '', true);
  try {
    const resp = await fetch(`/api/dataset/${DATASET_ID}/event?id=${encodeURIComponent(ev.id)}`);
    const d = await resp.json();
    if (!drawerStillMine(seq)) return;
    if (!resp.ok) { render(ev, '', false); $('#adSubtitle').textContent = 'Eroare: ' + (d.error || resp.status); return; }
    render(d, d.raw_line, false);
  } catch (e) {
    if (drawerStillMine(seq)) { render(ev, '', false); $('#adSubtitle').textContent = 'Eroare de retea: ' + e.message; }
  }
}

// ==========================================================================
// v43.2/v44 -- FILTRE GLOBALE + PANOU INFERIOR (spec §3, §6, §7)
// ==========================================================================
const GF = { history: [], lastState: null, lastKey: null, applying: false,
             fullSummary: null, showingFiltered: false, summarySeq: 0, overviewSeq: 0,
             spTab: 'raw', overview: null, geoip: null, detailKey: '', detailPending: null, wpSeq: 0 };
// Taburile care afiseaza analiza detaliata (v42) -- recalculata pe server
// pentru selectie DOAR cand unul dintre ele e deschis.
const DETAIL_PAGES = ['traffic', 'countries', 'endpoints', 'errors', 'security', 'wordpress', 'ip', 'raw', 'investigations'];

function gfSnapshot() {
  return JSON.parse(JSON.stringify({ f: TRIAGE.filters, a: TRIAGE.tsFrom, b: TRIAGE.tsTo }));
}
function gfTimeNarrowed() {
  if (TRIAGE.tsFrom == null || TRIAGE.boundsFrom == null) return false;
  return Math.floor(TRIAGE.tsFrom) > Math.floor(TRIAGE.boundsFrom) || Math.floor(TRIAGE.tsTo) < Math.floor(TRIAGE.boundsTo);
}
function gfParams() {
  // intervalul e in gf DOAR daca e mai ingust decat tot logul
  return triageQueryParams();
}
function gfIsActive() { return gfParams().toString() !== ''; }
function gfDescribe(opts) {
  const parts = [];
  const f = TRIAGE.filters;
  if ((f.countries || []).length) parts.push('tara ' + f.countries.map(c => c === '??' ? 'nedeterminata' : c).join('/'));
  if (f.ip) parts.push('IP ' + f.ip);
  if (f.pathContains) parts.push('URL contine "' + f.pathContains + '"');
  if ((f.statuses || []).length) parts.push('status ' + f.statuses.join('/'));
  if ((f.severities || []).length) parts.push('severitate ' + f.severities.join('/'));
  if ((f.actions || []).length) parts.push('actiune ' + f.actions.join('/'));
  if (f.uaContains) parts.push('UA contine "' + f.uaContains + '"');
  if (f.method) parts.push('metoda ' + f.method);
  if (f.pathExact) parts.push('URL = ' + f.pathExact);
  if ((f.statusClass || []).length) parts.push('clasa ' + f.statusClass.join('/'));
  if (f.wpCat) parts.push('WordPress: ' + (WP_CAT_LABEL[f.wpCat] || f.wpCat));
  if (f.uaExact) parts.push('UA = "' + f.uaExact + '"');
  const x = f.x || {};
  (x.ips || []).forEach(v => parts.push('fara IP ' + v));
  (x.countries || []).forEach(v => parts.push('fara tara ' + (v === '??' ? 'nedeterminata' : v)));
  (x.statuses || []).forEach(v => parts.push('fara cod ' + v));
  (x.paths || []).forEach(v => parts.push('fara URL-uri cu "' + v + '"'));
  (x.uas || []).forEach(v => parts.push('fara UA cu "' + v + '"'));
  if (!(opts && opts.contentOnly)) {
    if (f.day) parts.push('ziua ' + f.day);
    if (gfTimeNarrowed()) parts.push('interval ' + fmtRange(TRIAGE.tsFrom, TRIAGE.tsTo));
  }
  return parts.length ? parts.join(', ') : 'tot logul';
}
function gfSetStatus(text, kind) {
  const el = $('#gfStatus');
  el.textContent = text || '';
  el.className = 'gfStatus' + (kind ? ' ' + kind : '');
}

function gfOnDatasetLoaded() {
  GF.history = []; GF.lastState = null; GF.lastKey = null; GF.showingFiltered = false;
  GF.summarySeq++; GF.overviewSeq++; GF.overview = null; GF.detailKey = ''; GF.detailPending = null;
  GF.fullSummary = CURRENT_SUMMARY;   // renderSummary(data.summary) a rulat deja la upload
  $('#globalFilterBar').style.display = 'block';
  // v46: fara panou andocat jos -- inregistrarile selectiei traiesc in
  // modulul "Raw Logs" si apar doar cand il deschizi.
  $('#selectionPanel').style.display = 'flex';
  $('#gfBackBtn').disabled = true;
  $('#gfGeoWarn').style.display = 'none';
  gfMarkDetailStale(false);
  gfSetStatus('Se indexeaza evenimentele -- filtrele devin active in cateva secunde. Taburile detaliate sunt deja utilizabile.', 'busy');
  spRenderKpis(null, true);
  spSetMsg('Se indexeaza evenimentele... sinteza si inregistrarile RAW apar automat.');
  gfRenderImportInfo();
}

function gfRenderGeoWarn() {
  const g = GF.geoip || {};
  const el = $('#gfGeoWarn');
  if (g.ipv4 === false) {
    el.innerHTML = `&#9888; <b>GeoIP indisponibil pe server</b>${(g.missing || []).length ? ' -- lipsesc fisierele: <code>' + tEsc(g.missing.join(', ')) + '</code>' : ' (baza nu s-a putut incarca)'}. ` +
      'Tara nu poate fi determinata pentru niciun IP: toate cererile apar ca "nedeterminata", iar filtrul pe o tara anume nu are ce selecta. Nu se ghicesc tari.';
    el.style.display = 'block';
  } else el.style.display = 'none';
}

async function gfAfterIndexReady() {
  gfRenderGeoWarn();
  const eng = TRIAGE.engine === 'columnar' ? 'index columnar in memorie' : 'index SQLite';
  gfSetStatus((window._lastUploadReused ? 'Fisier identic cu unul deja incarcat -- rezultatele au fost refolosite instant (fara reprocesare). ' : '')
    + `Gata (${eng}). Perioada si filtrele se aplica in toate modulele.`, 'ok');
  window._lastUploadReused = false;
  GF.lastState = gfSnapshot(); GF.lastKey = gfParams().toString();
  GF.detailKey = GF.lastKey;      // taburile arata deja tot logul
  gfUpdateScope();
  gfRefreshOverview();
  triageRenderMultiSelects();
  if (CURRENT_PAGE === 'ip') ipovEnsureFresh();
}

function gfOnFiltersChanged() {
  if (!TRIAGE.ready) return;
  const key = gfParams().toString();
  if (key === GF.lastKey) return;
  if (!GF.applying && GF.lastState) {
    GF.history.push(GF.lastState);
    if (GF.history.length > 40) GF.history.shift();
  }
  GF.lastState = gfSnapshot(); GF.lastKey = key;
  $('#gfBackBtn').disabled = GF.history.length === 0;
  const ds = $('#daySelect');
  if (ds && ds.value !== (TRIAGE.filters.day || 'ALL')) ds.value = TRIAGE.filters.day || 'ALL';
  gfUpdateScope();
  gfRefreshOverview();
  // Prezentare: recalculata acum daca e vizibila, altfel la urmatoarea deschidere
  if (CURRENT_PAGE === 'ip') ipovEnsureFresh(); else IPOV_STALE = true;
  gfSetStatus(gfIsActive()
    ? `Selectie: ${gfDescribe()}. Modulul curent e actualizat; celelalte se recalculeaza cand le deschizi.`
    : 'Fara filtre: toata aplicatia arata tot logul.', 'ok');
  // Taburile detaliate: recalculare doar daca unul e deschis (spec §4: fara
  // recalcularea inutila a tuturor statisticilor la fiecare interactiune)
  if (DETAIL_PAGES.includes(CURRENT_PAGE)) gfEnsureDetailedTabs();
  else gfMarkDetailStale(GF.detailKey !== key);
  // v45: toate componentele deja deschise (alerte, panoul de explorare,
  // ferestrele de drilldown, cronologia de securitate, Path Explorer,
  // Exploratorul de loguri) se actualizeaza pentru noua selectie.
  GF_LISTENERS.forEach(fn => { try { fn(key); } catch (e) { console.warn('listener selectie', e); } });
}
const GF_LISTENERS = [];

$('#gfBackBtn').addEventListener('click', () => {
  const prev = GF.history.pop();
  if (!prev) return;
  GF.applying = true;
  try {
    TRIAGE.filters = Object.assign(emptyTriageFilters(), prev.f); TRIAGE.tsFrom = prev.a; TRIAGE.tsTo = prev.b;
    $('#triageIpFilter').value = TRIAGE.filters.ip || '';
    $('#triagePathFilter').value = TRIAGE.filters.pathContains || '';
    if (TRIAGE.tsFrom != null) $('#triageFrom').value = epochToDtLocal(TRIAGE.tsFrom, TRIAGE.tzOffset);
    if (TRIAGE.tsTo != null) $('#triageTo').value = epochToDtLocal(TRIAGE.tsTo, TRIAGE.tzOffset);
    triageRenderMultiSelects();
    triageRenderActiveChips();
    GF.lastState = null;   // nu punem starea curenta inapoi in istoric cand revenim
    triageReloadAll();
  } finally { GF.applying = false; }
  $('#gfBackBtn').disabled = GF.history.length === 0;
});

function gfUpdateScope() {
  $('#spScope').textContent = gfIsActive() ? '-- ' + gfDescribe() : '-- tot logul';
}

// ---------- analiza detaliata (v42) pentru selectie -- LENESA ----------
function gfMarkDetailStale(on, html) {
  const el = $('#dashStale');
  if (!el) return;
  el.classList.toggle('on', !!on);
  $('#dash').classList.toggle('stale', !!on);
  if (on) el.innerHTML = html || `&#9888; Taburile detaliate arata inca <b>${GF.showingFiltered ? 'o selectie anterioara' : 'tot logul'}</b>, nu selectia curenta (${tEsc(gfDescribe())}). Se recalculeaza automat cand deschizi un tab detaliat.`;
}
function gfEnsureDetailedTabs() {
  if (!TRIAGE.ready) return;
  const key = gfParams().toString();
  if (key === GF.detailKey || key === GF.detailPending) return;
  gfRefreshSummary();
}
async function gfRefreshSummary() {
  const seq = ++GF.summarySeq;
  const key = gfParams().toString();
  if (!gfIsActive()) {
    GF.detailPending = null;
    if (GF.showingFiltered && GF.fullSummary) {
      renderSummary(GF.fullSummary); GF.showingFiltered = false;
    }
    GF.detailKey = key;
    gfMarkDetailStale(false);
    if (DETAIL_PAGES.includes(CURRENT_PAGE)) showPage(CURRENT_PAGE);
    return;
  }
  GF.detailPending = key;
  gfMarkDetailStale(true, `<span class="spBusy"></span>Recalculez analiza detaliata pentru selectie (${tEsc(gfDescribe())})... Pana termina, analiza detaliata de mai jos NU reflecta selectia; sumarul de sus al modulului e deja actualizat.`);
  for (;;) {
    let r, d;
    try { r = await fetch(`/api/dataset/${DATASET_ID}/summary_filtered?${key}`); d = await r.json(); }
    catch (e) {
      if (seq === GF.summarySeq) { GF.detailPending = null; gfMarkDetailStale(true, '&#9888; Eroare de retea la recalcularea taburilor detaliate: ' + tEsc(e.message) + '. Schimba tabul ca sa reincerci.'); }
      return;
    }
    if (seq !== GF.summarySeq) return;       // o selectie mai noua a inlocuit-o
    if (d.status === 'done' && d.summary) {
      GF.detailPending = null;
      GF.detailKey = key;
      renderSummary(d.summary); GF.showingFiltered = true;
      gfMarkDetailStale(false);
      if (DETAIL_PAGES.includes(CURRENT_PAGE)) showPage(CURRENT_PAGE);
      const fs = d.summary._filtered || {};
      gfSetStatus(`Taburile detaliate arata selectia: ${(d.summary.total || 0).toLocaleString('ro-RO')} cereri (${gfDescribe()})` +
        (fs.analyze_s != null ? ` -- recalculat in ${(fs.extract_s + fs.analyze_s).toFixed(1)}s.` : ' -- din cache.'), 'ok');
      return;
    }
    if (d.status === 'error' || !r.ok) {
      GF.detailPending = null;
      gfMarkDetailStale(true, '&#9888; Eroare la recalcularea taburilor detaliate: ' + tEsc(d.error || ('HTTP ' + r.status)));
      return;
    }
    const pct = d.status === 'waiting_index' ? 0 : (d.progress || 0);
    gfMarkDetailStale(true, `<span class="spBusy"></span>Recalculez analiza detaliata pentru selectie (${tEsc(gfDescribe())})... ${pct}%. Pana termina, analiza detaliata de mai jos NU reflecta selectia; sumarul de sus al modulului e deja actualizat.`);
    await new Promise(res => setTimeout(res, 700));
  }
}

// ---------- panoul inferior: sinteza + vederi ----------
function spSetMsg(text, kind) { const el = $('#spMsg'); el.textContent = text || ''; el.className = 'spMsg' + (kind ? ' ' + kind : ''); }
function fmtN(n) { return (n == null ? '-' : Number(n).toLocaleString('ro-RO')); }
function fmtEpoch(e) { return e == null ? '-' : fmtTimeShort(epochToDtLocalStr(e)); }

const SP_KPI_DEFS = [
  ['requests', 'Cereri', '', 'raw'], ['unique_ips', 'IP-uri unice', '', 'ips'], ['unique_paths', 'URL-uri distincte', '', 'paths'],
  ['err_4xx', 'Erori 4xx', 'warn', 'errors4'], ['err_5xx', 'Erori 5xx', 'bad', 'errors5'], ['unknown_country', 'Fara tara determinata', '', 'unknown'],
  ['wp_login_post', 'Login POST (wp-login)', 'warn', 'wplogin'], ['xmlrpc', 'xmlrpc.php', 'warn', 'xmlrpc'],
];
function spRenderKpis(d, loading) {
  if (loading || !d) {
    $('#spKpis').innerHTML = SP_KPI_DEFS.map(x => `<div class="spKpi skel"><div class="v">000</div><div class="l">${x[1]}</div></div>`).join('');
    return;
  }
  const wp = d.wordpress || {};
  const val = k => (k in d ? d[k] : wp[k]);
  $('#spKpis').innerHTML = SP_KPI_DEFS.map(([k, l, cls, act]) => {
    const v = val(k);
    return `<div class="spKpi clickable ${v && cls ? cls : ''}" data-kpi="${act}" title="Click: detalii"><div class="v">${fmtN(v)}</div><div class="l">${l}</div></div>`;
  }).join('') + `<div class="spKpi"><div class="v" style="font-size:12px">${fmtEpoch(d.ts_min)}<br>${fmtEpoch(d.ts_max)}</div><div class="l">Prima / ultima cerere</div></div>`;
}
$('#spKpis').addEventListener('click', (e) => {
  const k = e.target.closest('[data-kpi]');
  if (!k) return;
  const act = k.dataset.kpi;
  // v45: fiecare indicator deschide investigatia lui (aceeasi selectie)
  const map = { raw: ['sel', ''], errors4: ['sclass', '4xx'], errors5: ['sclass', '5xx'], unknown: ['country', '??'],
                wplogin: ['wp', 'wp_login_post'], xmlrpc: ['wp', 'xmlrpc'] };
  if (map[act]) { XP.open(map[act][0], map[act][1]); return; }
  GF.spTab = act; spRenderPane();
});

async function gfRefreshOverview() {
  if (!TRIAGE.ready) return;
  const seq = ++GF.overviewSeq;
  spRenderKpis(null, true);
  spSetMsg('Se calculeaza sinteza pentru selectie...');
  const t0 = performance.now();
  let r, d;
  try { r = await fetch(`/api/dataset/${DATASET_ID}/overview?${gfParams()}`); d = await r.json(); }
  catch (e) { if (seq === GF.overviewSeq) { spSetMsg('Eroare de retea la sinteza: ' + e.message + ' -- schimba un filtru ca sa reincerci.', 'err'); spRenderKpis({}); } return; }
  if (seq !== GF.overviewSeq) return;
  if (r.ok) GF.overviewDoneSeq = seq;
  if (r.status === 202) { spSetMsg('Indexarea e inca in curs -- sinteza apare automat.'); return; }
  if (!r.ok) { spSetMsg('Eroare la sinteza: ' + (d.error || ('HTTP ' + r.status)), 'err'); spRenderKpis({}); GF.overview = null; spRenderPane(); return; }
  GF.overview = d;
  spRenderKpis(d);
  const ms = Math.round(performance.now() - t0);
  if (!d.requests) {
    spSetMsg(`Nicio cerere nu corespunde selectiei (${gfDescribe()}). Elimina un filtru (x pe chip), apasa "Inapoi" sau "Reset filtre".` +
      (((TRIAGE.filters.countries || []).some(c => c !== '??') && GF.geoip && GF.geoip.ipv4 === false) ? ' GeoIP e indisponibil pe server -- nicio cerere nu are tara determinata.' : ''));
  } else if (d.unknown_country) {
    const why = GF.geoip && !GF.geoip.ipv6
      ? 'IP-uri IPv6 (baza GeoIP IPv6 lipseste pe server) sau IP-uri private/rezervate'
      : 'IP-uri private/rezervate sau absente din baza GeoIP';
    spSetMsg(`${fmtN(d.unknown_country)} cereri nu au tara determinata (${why}) -- apar ca "??", nu sunt atribuite niciunei tari. Sinteza: ${ms} ms.`);
  } else spSetMsg(`Sinteza pentru selectie: ${ms} ms.`);
  spRenderPane();
}

function spLink(field, value, label) {
  const kind = { ip: 'ip', path: 'path', country: 'country', status: 'status' }[field] || field;
  return (field === 'country' ? flagHtml(value) : '') + `<a class="spLink" data-spf="${tEscAttr(field)}" data-spv="${tEscAttr(value)}" data-ek="${tEscAttr(kind)}" data-ev="${tEscAttr(value)}" tabindex="0" title="Click: deschide in panoul de explorare · click dreapta: actiuni">${tEsc(label != null ? label : value)}</a>` + entQuick(kind, value);
}
function spBar(n, max) { return `<div class="spBar" style="width:${max ? Math.max(1, Math.round(100 * n / max)) : 0}%"></div>`; }
function spEmpty(msg) { return `<div class="spMsg">${tEsc(msg)}</div>`; }
const WP_CATS = [['wp_login_post', 'wp-login.php -- POST (incercari de autentificare)', 'wp-login.php', 'POST'],
  ['wp_login_get', 'wp-login.php -- GET (afisare formular)', 'wp-login.php', 'GET'],
  ['xmlrpc', 'xmlrpc.php (XML-RPC)', 'xmlrpc.php', ''], ['wp_admin', '/wp-admin/ (inclusiv admin-ajax)', '/wp-admin/', ''],
  ['admin_ajax', 'admin-ajax.php', 'admin-ajax.php', ''], ['wp_json', '/wp-json/ (REST API)', '/wp-json/', ''],
  ['wp_cron', 'wp-cron.php', 'wp-cron.php', '']];

function spRenderPane() {
  document.querySelectorAll('#spTabs .spTab').forEach(b => b.classList.toggle('active', b.dataset.sp === GF.spTab));
  document.querySelectorAll('#selectionPanel .spPane').forEach(p => { p.style.display = p.dataset.spPane === GF.spTab ? (GF.spTab === 'raw' ? 'flex' : '') : 'none'; });
  if (GF.spTab === 'raw') { setTimeout(triageRenderVisibleRows, 20); return; }
  const d = GF.overview;
  const pane = document.querySelector(`#selectionPanel .spPane[data-sp-pane="${GF.spTab}"]`);
  if (!TRIAGE.ready) { pane.innerHTML = spEmpty('Se indexeaza evenimentele -- vederea apare automat.'); return; }
  if (!d) { pane.innerHTML = spEmpty('Sinteza se incarca...'); return; }
  if (!d.requests) { pane.innerHTML = spEmpty('Nicio cerere in selectia curenta -- nimic de afisat aici. ' + triageEmptyReason()); return; }
  if (GF.spTab === 'ips') {
    const rows = d.top_ips || []; const max = rows.length ? rows[0].n : 0;
    pane.innerHTML = rows.length ? `<table class="spList"><tr><th>IP</th><th>Tara</th><th style="text-align:right">Cereri</th><th>Prima / ultima</th><th></th></tr>` +
      rows.map(r => `<tr><td>${spLink('ip', r.ip)}</td><td>${spLink('country', r.country || '??', r.country ? ccLabel(r.country) : '?? (nedeterminata)')}</td>
        <td class="num">${fmtN(r.n)}${spBar(r.n, max)}</td><td>${r.first_ts != null ? fmtEpoch(r.first_ts) + ' &rarr; ' + fmtEpoch(r.last_ts) : '-'}</td>
        <td><button class="spBtnMini" data-prof="${tEscAttr(r.ip)}">Profil</button></td></tr>`).join('') + '</table>' +
        `<div class="spMsg">Top ${rows.length} din ${fmtN(d.unique_ips)} IP-uri unice. Click pe IP: filtreaza toata aplicatia; "Profil": activitatea IP-ului cu justificarea semnalelor.</div>`
      : spEmpty('Niciun IP in selectie.');
  } else if (GF.spTab === 'paths') {
    const rows = d.top_paths || []; const max = rows.length ? rows[0].n : 0;
    pane.innerHTML = rows.length ? `<table class="spList"><tr><th>URL (fara query string)</th><th style="text-align:right">Cereri</th><th style="text-align:right">IP-uri</th></tr>` +
      rows.map(r => `<tr><td class="pathCell">${spLink('path', r.path)}</td><td class="num">${fmtN(r.n)}${spBar(r.n, max)}</td><td class="num">${fmtN(r.ips)}</td></tr>`).join('') + '</table>' +
      `<div class="spMsg">Top ${rows.length} din ${fmtN(d.unique_paths)} URL-uri distincte.</div>`
      : spEmpty('Niciun URL in selectie.');
  } else if (GF.spTab === 'countries') {
    const rows = d.countries || []; const max = rows.length ? rows[0].n : 0;
    const g = GF.geoip || {};
    const geoNote = g.ipv4 === false ? '<div class="spMsg err">GeoIP indisponibil pe server: toate IP-urile sunt "nedeterminate"; nu se ghicesc tari.</div>' : '';
    pane.innerHTML = geoNote + (rows.length ? `<table class="spList"><tr><th>Tara</th><th style="text-align:right">Cereri</th><th style="text-align:right">IP-uri unice</th><th style="text-align:right">% din selectie</th></tr>` +
      rows.map(r => `<tr><td>${spLink('country', r.country || '??', r.country ? ccLabel(r.country) : '?? (nedeterminata)')}</td><td class="num">${fmtN(r.n)}${spBar(r.n, max)}</td><td class="num">${fmtN(r.ips)}</td><td class="num">${(100 * r.n / d.requests).toFixed(1)}%</td></tr>`).join('') + '</table>' +
      '<div class="spMsg">Click pe o tara: filtreaza toata aplicatia. "??" = IP-uri fara tara in baza GeoIP (private/rezervate sau IPv6 fara baza IPv6).</div>'
      : spEmpty('Nicio tara in selectie.'));
  } else if (GF.spTab === 'wp') {
    const w = d.wordpress || {};
    const codes = {};
    (w.status_by_category || []).forEach(x => { (codes[x.cat] = codes[x.cat] || []).push(`${x.status}: ${fmtN(x.n)}`); });
    pane.innerHTML = `<div class="spMsg">Un acces la wp-admin/wp-login NU inseamna automat atac sau autentificare reusita: login-urile confirmate (POST 302 urmat de /wp-admin/ 200 in max 5 min) sunt marcate separat ("Login OK") in tabelul RAW si in alerte.</div>
      <table class="spList"><tr><th>Categorie</th><th style="text-align:right">Cereri</th><th style="text-align:right">IP-uri unice</th><th style="text-align:right" title="Cererile aceluiasi IP fara o pauza mai mare de 30 min = o sesiune. Estimare, nu sesiuni reale WordPress.">Sesiuni estimate</th><th>Coduri HTTP</th></tr>` +
      WP_CATS.map(([k, l, needle, meth]) => `<tr><td>${(w[k] || 0) ? `<a class="spLink" data-wpcat="${k}" data-needle="${tEscAttr(needle)}" data-meth="${meth}" title="click: filtreaza selectia pe aceasta categorie">${tEsc(l)}</a>${entQuick('wp', k)}` : tEsc(l)}</td><td class="num">${fmtN(w[k] || 0)}</td><td class="num">${w[k + '_ips'] != null ? fmtN(w[k + '_ips']) : '-'}</td><td class="num">${w[k + '_sessions'] != null ? fmtN(w[k + '_sessions']) : '-'}</td><td style="font-size:11.5px;color:var(--text-dim)">${tEsc((codes[k] || []).slice(0, 6).join(' · '))}</td></tr>`).join('') + '</table>' +
      '<div class="spMsg">Cereri &ne; IP-uri unice &ne; sesiuni: o sesiune estimata = cererile aceluiasi IP fara pauza mai mare de 30 de minute.</div>' +
      '<div class="ipProfSec">Surse principale (autentificare / XML-RPC)</div><div id="spWpSources" class="spMsg"><span class="spBusy">se calculeaza...</span></div>';
    spLoadWpSources(w);
  } else if (GF.spTab === 'errors') {
    const rows = d.error_paths || []; const max = rows.length ? rows[0].n : 0;
    const errSt = (d.statuses || []).filter(x => x.status >= 400).sort((a, b) => a.status - b.status);
    const chips = errSt.length ? '<div class="spMsg">' + errSt.map(x => `${spLink('status', x.status, String(x.status))}: ${fmtN(x.n)}`).join(' &middot; ') + '</div>' : '';
    pane.innerHTML = `<div class="spMsg">Erorile sunt doar corelate (cod, URL, IP-uri, interval). Un 404 nu e tratat automat ca atac.</div>` + chips + (rows.length
      ? `<table class="spList"><tr><th>Cod</th><th>URL</th><th style="text-align:right">Cereri</th><th style="text-align:right">IP-uri</th><th>Interval</th></tr>` +
        rows.map(r => `<tr><td>${spLink('status', r.status)}</td><td class="pathCell">${spLink('path', r.path)}</td><td class="num">${fmtN(r.n)}${spBar(r.n, max)}</td><td class="num">${fmtN(r.ips)}</td><td>${r.first_ts != null ? fmtEpoch(r.first_ts) + ' &rarr; ' + fmtEpoch(r.last_ts) : '-'}</td></tr>`).join('') + '</table>'
      : spEmpty('Nicio eroare 4xx/5xx in selectie.'));
  }
}
// Surse WordPress: top IP-uri pe POST wp-login si pe xmlrpc, in selectia
// curenta, cu nivel de incredere (spec §5: indicatori, nu certitudini).
async function spLoadWpSources(w) {
  const seq = ++GF.wpSeq;
  const el = () => $('#spWpSources');
  const jobs = [];
  if (w.wp_login_post) jobs.push(['POST wp-login.php', { path_contains: 'wp-login.php', method: 'POST' }]);
  if (w.xmlrpc) jobs.push(['xmlrpc.php', { path_contains: 'xmlrpc.php' }]);
  if (!jobs.length) { if (el()) el().textContent = 'Nicio cerere de autentificare sau XML-RPC in selectie.'; return; }
  const out = [];
  for (const [label, extra] of jobs) {
    const p = gfParams();
    Object.entries(extra).forEach(([k, v]) => { if (k === 'path_contains' && p.get('path_contains')) return; p.set(k, v); });
    try {
      const r = await fetch(`/api/dataset/${DATASET_ID}/overview?${p}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.status);
      const ips = (d.top_ips || []).slice(0, 6);
      out.push(`<b>${tEsc(label)}</b>: ${fmtN(d.requests)} cereri de la ${fmtN(d.unique_ips)} IP-uri` +
        (ips.length ? '<table class="spList">' + ips.map(x => {
          const lvl = x.n >= 100 ? ['high', 'incredere ridicata: automatizare (brute force)'] : x.n >= 20 ? ['medium', 'incredere medie: incercari repetate'] : ['low', 'volum mic: poate fi un utilizator real'];
          return `<tr><td>${spLink('ip', x.ip)}</td><td>${tEsc(x.country ? ccLabel(x.country) : '??')}</td><td class="num">${fmtN(x.n)}</td><td><span class="sigRow ${lvl[0]}" style="display:inline-block;margin:0">${tEsc(lvl[1])}</span></td><td>${x.first_ts != null ? fmtEpoch(x.first_ts) + ' &rarr; ' + fmtEpoch(x.last_ts) : ''}</td></tr>`;
        }).join('') + '</table>' : ''));
    } catch (e) { out.push(`<b>${tEsc(label)}</b>: eroare -- ${tEsc(e.message)}`); }
  }
  if (seq !== GF.wpSeq || !el()) return;
  el().innerHTML = out.join('<br>');
}

$('#spTabs').addEventListener('click', (e) => {
  const b = e.target.closest('.spTab'); if (!b) return;
  GF.spTab = b.dataset.sp; spRenderPane();
});
$('#selectionPanel').addEventListener('click', (e) => {
  const prof = e.target.closest('[data-prof]');
  if (prof) { XP.open('ip', prof.dataset.prof); return; }
  const wc = e.target.closest('[data-wpcat]');
  if (wc) { triageSetSingleFilter('wp', wc.dataset.wpcat); return; }
  // linkurile din panou (v45): IP -> profilul (panoul de explorare), URL ->
  // istoricul endpoint-ului; tara / cod / categorie WordPress -> filtru global
  // (ca in v44). Butoanele mici de la hover (+ / - / ...) si click dreapta
  // ofera mereu si celelalte actiuni.
  const a = e.target.closest('.spLink'); if (!a || !a.dataset.spf) return;
  const kind = { ip: 'ip', path: 'path' }[a.dataset.spf];
  if (kind) XP.open(kind, a.dataset.spv); else triageSetSingleFilter(a.dataset.spf, a.dataset.spv);
});

// ---------- panoul andocat: pliere + redimensionare ----------
const DOCK = { h: null, collapsed: null };
(function dockLoad() {
  try { const v = JSON.parse(localStorage.getItem('logscan.dock') || 'null'); if (v) { DOCK.h = v.h || null; DOCK.collapsed = !!v.collapsed; } } catch (e) {}
  if (DOCK.collapsed == null) DOCK.collapsed = window.innerWidth < 760;
})();
function dockSave() { try { localStorage.setItem('logscan.dock', JSON.stringify(DOCK)); } catch (e) {} }
function dockApply() {
  // v46: panoul nu mai e andocat; pastrat ca punct unic de re-randare a
  // tabelului virtualizat cand modulul Raw Logs devine vizibil.
  document.documentElement.style.setProperty('--dockOffset', '0px');
  requestAnimationFrame(() => triageRenderVisibleRows());
}

// v46: redimensionarea panoului andocat a fost eliminata odata cu panoul.

// ---------- profil IP (spec §5) ----------
async function openIpProfile(ip) {
  const seq = openDrawer('Profil IP -- ' + ip, 'Se incarca profilul...');
  const p = new URLSearchParams({ ip });
  if (gfTimeNarrowed()) { p.set('ts_from', Math.floor(TRIAGE.tsFrom)); p.set('ts_to', Math.floor(TRIAGE.tsTo)); }
  let r, d;
  try { r = await fetch(`/api/dataset/${DATASET_ID}/ip_profile?${p}`); d = await r.json(); }
  catch (e) { if (drawerStillMine(seq)) $('#adSubtitle').textContent = 'Eroare de retea: ' + e.message; return; }
  if (!drawerStillMine(seq)) return;
  if (!r.ok) { $('#adSubtitle').textContent = 'Eroare: ' + (d.error || r.status); return; }
  if (!d.requests) { $('#adSubtitle').textContent = 'Acest IP nu are cereri ' + (gfTimeNarrowed() ? 'in intervalul selectat.' : 'in log.'); return; }
  $('#adSubtitle').textContent = `${d.country ? ccLabel(d.country) : 'tara nedeterminata'} · ${gfTimeNarrowed() ? 'intervalul selectat' : 'tot logul'}`;
  const w = d.wordpress || {};
  const k = (v, l, cls) => `<div class="spKpi ${cls || ''}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
  const list = (rows, f) => rows.length ? '<table class="spList">' + rows.map(f).join('') + '</table>' : '<div class="spMsg">-</div>';
  const peak = d.peak_minute ? `${fmtEpoch(d.peak_minute.minute)} (${fmtN(d.peak_minute.n)} cereri)` : '-';
  const hasLogin = (d.actions || []).some(a => a.action_type === 'admin_login_success' || a.action_type === 'admin_login_post');
  const sig = (d.signals || []);
  $('#adBody').innerHTML = `
    <div class="evActions">
      <button class="ghost" id="ipProfFilter">&#128269; Filtreaza toata aplicatia pe acest IP</button>
      ${hasLogin ? '<button class="ghost" id="ipProfAudit">&#128273; Audit trail sesiune admin</button>' : ''}
    </div>
    <div class="ipProfGrid">
      ${k(fmtN(d.requests), 'Cereri')}${k(fmtN(d.unique_paths), 'URL-uri distincte')}
      ${k(fmtN(d.err_4xx), 'Erori 4xx', d.err_4xx ? 'warn' : '')}${k(fmtN(d.err_5xx), 'Erori 5xx', d.err_5xx ? 'bad' : '')}
      ${k(d.req_per_min, 'Cereri / minut (medie)')}${k(fmtN((w.wp_login_post || 0) + (w.xmlrpc || 0)), 'Login POST + xmlrpc', (w.wp_login_post || w.xmlrpc) ? 'warn' : '')}
    </div>
    <div class="spMsg">Prima aparitie: <b>${fmtEpoch(d.ts_min)}</b> · Ultima: <b>${fmtEpoch(d.ts_max)}</b> · Varf: <b>${peak}</b></div>
    <div class="ipProfSec">Comportament (indicatori, cu justificare)</div>
    ${sig.length ? sig.map(s => `<div class="sigRow ${tEscAttr(s.level)}"><b>${tEsc(s.label)}</b> <span class="tag ${s.level === 'high' ? 'HIGH' : s.level === 'medium' ? 'MEDIUM' : 'LOW'}">incredere ${s.level === 'high' ? 'ridicata' : s.level === 'medium' ? 'medie' : 'scazuta'}</span><div class="why">${tEsc(s.why)}</div></div>`).join('')
      : '<div class="spMsg">Niciun comportament neobisnuit dupa pragurile aplicate (volum, ritm, erori, autentificare, xmlrpc).</div>'}
    <div class="ipProfSec">Clasificari ale cererilor</div>
    ${list(d.actions || [], a => `<tr><td><span class="tag ${tEscAttr(a.severity)}">${tEsc(a.severity)}</span></td><td>${tEsc(a.label || a.action_type)}</td><td class="num">${fmtN(a.n)}</td></tr>`)}
    <div class="ipProfSec">URL-uri accesate</div>
    ${list(d.top_paths || [], r => `<tr><td class="pathCell">${tEsc(r.path)}</td><td class="num">${fmtN(r.n)}</td></tr>`)}
    <div class="ipProfSec">Coduri HTTP / metode</div>
    <div class="spMsg">${(d.statuses || []).map(x => `${tEsc(x.status)}: ${fmtN(x.n)}`).join(' · ')}<br>${(d.methods || []).map(x => `${tEsc(x.method)}: ${fmtN(x.n)}`).join(' · ')}</div>
    <div class="ipProfSec">User-Agent-uri</div>
    ${list(d.user_agents || [], r => `<tr><td style="font-size:11.5px;word-break:break-all">${tEsc(r.ua || '-')}</td><td class="num">${fmtN(r.n)}</td></tr>`)}
    <div class="ipProfSec">WordPress</div>
    <div class="spMsg">wp-login POST ${fmtN(w.wp_login_post || 0)} · wp-login GET ${fmtN(w.wp_login_get || 0)} · xmlrpc ${fmtN(w.xmlrpc || 0)} · wp-admin ${fmtN(w.wp_admin || 0)} · admin-ajax ${fmtN(w.admin_ajax || 0)} · wp-json ${fmtN(w.wp_json || 0)}</div>`;
  $('#ipProfFilter').onclick = () => { closeAuditDrawer(); triageSetSingleFilter('ip', ip); };
  const au = $('#ipProfAudit'); if (au) au.onclick = () => openAuditDrawer(ip, null);
}

// ---------- meniu de actiuni pe entitatile din taburile detaliate ----------
// Click pe un IP / o tara / un URL in tabelele v42: filtru GLOBAL (spec §6)
// sau actiunea veche (fereastra cu linii brute / detaliul IP) -- nimic pierdut.
function showEntityMenu(evt, kind, value, legacyLabel, legacyFn) {
  evt.stopPropagation();
  const m = $('#entityMenu');
  const head = kind === 'country' ? ccLabel(value) : value;
  const glob = { ip: 'Filtreaza toata aplicatia pe acest IP', country: 'Filtreaza toata aplicatia pe aceasta tara', path: 'Filtreaza toata aplicatia: URL contine asta' }[kind];
  m.innerHTML = `<div class="emHead">${tEsc(head)}</div>
    <div class="emItem" data-em="global">&#9881; ${tEsc(glob)}</div>
    ${kind === 'ip' ? '<div class="emItem" data-em="profile">&#128100; Profil IP (panou lateral)</div>' : ''}
    <div class="emItem" data-em="legacy">&#128196; ${tEsc(legacyLabel)}</div>`;
  const x = Math.max(4, Math.min(window.innerWidth - 260, evt.clientX));
  const y = Math.max(4, Math.min(window.innerHeight - 140, evt.clientY + 6));
  m.style.left = x + 'px'; m.style.top = y + 'px';
  m.classList.add('open');
  m.querySelector('[data-em="global"]').onclick = () => { m.classList.remove('open'); triageSetSingleFilter(kind, value); };
  const pr = m.querySelector('[data-em="profile"]'); if (pr) pr.onclick = () => { m.classList.remove('open'); openIpProfile(value); };
  m.querySelector('[data-em="legacy"]').onclick = () => { m.classList.remove('open'); legacyFn(); };
}
document.addEventListener('click', (e) => { if (!e.target.closest('#entityMenu')) $('#entityMenu').classList.remove('open'); });

// ---------- uneltele avansate (Explorator / Extractie) au filtre proprii
// (subnet, semnatura de atac, parametru query...) -- un click le aliniaza cu
// selectia globala, fara sa le suprascrie pe cele pe care bara nu le are.
document.addEventListener('click', (e) => {
  const b = e.target.closest('.gfPull');
  if (!b) return;
  const pre = b.dataset.pull === 'exp' ? '#expF' : '#ipovF';
  const f = TRIAGE.filters;
  const set = (id, v) => { const el = $(pre + id); if (el) el.value = v || ''; };
  set('Ip', f.ip); set('Path', f.pathContains); set('Ua', f.uaContains); set('Method', f.method);
  set('Country', (f.countries || []).length === 1 ? f.countries[0] : '');
  set('Status', (f.statuses || []).length === 1 ? f.statuses[0] : '');
  const multi = ((f.countries || []).length > 1 || (f.statuses || []).length > 1) ? ' (din tari/coduri multiple s-a preluat doar cand e o singura valoare)' : '';
  toast('Filtrele globale au fost copiate' + multi);
});

// ---------- bilantul importului + GeoIP (spec §8) ----------
function gfRenderImportInfo() {
  const s = GF.fullSummary || CURRENT_SUMMARY || {};
  const L = s.lines || { processed: s.total, invalid: s.bad, blank: 0, invalid_samples: [] };
  const samples = (L.invalid_samples || []).join('\n');
  $('#gfImportInfo').innerHTML = `Import: <b>${fmtN(L.processed)}</b> linii procesate · ` +
    (L.invalid ? `<span class="warnTxt" title="${tEscAttr('Linii ignorate (format sau timestamp invalid), neincluse in analiza. Exemple:\n' + samples)}">${fmtN(L.invalid)} invalide/ignorate</span>` : '0 invalide') +
    ` · ${fmtN(L.blank || 0)} goale`;
}

// ==========================================================================
// v45 -- INVESTIGATIE INTERACTIVA
//   * panoul de explorare (drawer lateral, NE-modal): orice entitate (IP,
//     endpoint, prefix URL, tara, cod / clasa HTTP, categorie WordPress, UA,
//     alerta) sau selectia curenta -- mereu in intersectie cu selectia
//     globala (perioada + filtre); taburi Sumar / In timp / Cereri RAW /
//     Corelate / Alerte; istoric inapoi/inainte; comparatie entitati si
//     perioade; navigare eveniment cu eveniment;
//   * meniuri contextuale (click dreapta sau "⋯") pe IP-uri, URL-uri, tari,
//     coduri, alerte si randuri RAW, plus actiuni rapide la hover;
//   * excluderi in selectie, preseturi, vizualizari salvate;
//   * cronologia de securitate (grupata, cu selectie de interval);
//   * spatiul de investigatie (salvat local, cu export);
//   * paleta de comenzi (Ctrl+K) si scurtaturi de tastatura (?).
// Toate se reincarca automat la schimbarea selectiei (GF_LISTENERS), iar
// raspunsurile depasite sunt ignorate (numar de secventa per vedere).
// ==========================================================================
const WP_CAT_LABEL = {
  wp_login_post: 'wp-login.php POST', wp_login_get: 'wp-login.php GET', xmlrpc: 'xmlrpc.php',
  wp_admin: '/wp-admin/', admin_ajax: 'admin-ajax.php', wp_json: '/wp-json/ (REST)', wp_cron: 'wp-cron.php',
  wp_any: 'orice ruta WordPress',
};
const KIND_LABEL = {
  sel: 'Selectia curenta', ip: 'IP', path: 'Endpoint', prefix: 'URL contine', country: 'Tara', status: 'Cod HTTP',
  sclass: 'Clasa HTTP', wp: 'WordPress', ua: 'User-Agent', action: 'Actiune', severity: 'Severitate',
  alert: 'Alerta', method: 'Metoda',
};
const EXCLUDABLE = { ip: 1, country: 1, status: 1, path: 1, prefix: 1, ua: 1 };

function entLabel(kind, value) {
  if (kind === 'country') return ccLabel(value || '??');
  if (kind === 'wp') return WP_CAT_LABEL[value] || value;
  if (kind === 'alert') { const [ip, act] = String(value).split('|'); return `${ip} · ${act}`; }
  if (kind === 'sel') return gfDescribe();
  return value;
}
function entQuick(kind, value) {
  if (!kind || kind === 'sel') return '';
  const a = `data-ek="${tEscAttr(kind)}" data-ev="${tEscAttr(value)}"`;
  return `<span class="entQ"><button type="button" data-eq="add" ${a} title="Adauga la selectie (filtru global)" aria-label="Filtreaza">&#8853;</button>` +
    (EXCLUDABLE[kind] ? `<button type="button" data-eq="excl" ${a} title="Exclude din selectie" aria-label="Exclude">&#8856;</button>` : '') +
    `<button type="button" data-eq="menu" ${a} title="Mai multe actiuni" aria-label="Mai multe actiuni">&#8943;</button></span>`;
}

// ---------- selectia globala: adauga / exclude o entitate ----------
function gfAddEntity(kind, value) {
  const map = { ip: 'ip', path: 'path_exact', prefix: 'path', country: 'country', status: 'status', sclass: 'sclass',
                wp: 'wp', ua: 'ua_exact', action: 'action', severity: 'severity', method: 'method' };
  if (kind === 'alert') {
    const [ip, act] = String(value).split('|');
    TRIAGE.filters.ip = ip; $('#triageIpFilter').value = ip; TRIAGE.filters.actions = [act];
    triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll();
  } else if (kind === 'sel') {
    return;
  } else if (map[kind]) triageSetSingleFilter(map[kind], value);
  toast('Filtru adaugat: ' + (KIND_LABEL[kind] || kind) + ' ' + entLabel(kind, value));
}
function gfExcludeEntity(kind, value) {
  const X = TRIAGE.filters.x || (TRIAGE.filters.x = { ips: [], countries: [], statuses: [], paths: [], uas: [] });
  const key = { ip: 'ips', country: 'countries', status: 'statuses', path: 'paths', prefix: 'paths', ua: 'uas' }[kind];
  if (!key) return;
  let v = String(value);
  if (kind === 'path') v = v.split('?')[0];
  if (kind === 'country' && v === '') v = '??';
  if (!X[key].includes(v)) X[key].push(v);
  // excluderea unei valori deja filtrate pozitiv ar goli selectia: o scoatem din filtrul pozitiv
  if (kind === 'ip' && TRIAGE.filters.ip === v) { TRIAGE.filters.ip = ''; $('#triageIpFilter').value = ''; }
  if (kind === 'country') TRIAGE.filters.countries = (TRIAGE.filters.countries || []).filter(c => c !== v);
  if (kind === 'status') TRIAGE.filters.statuses = (TRIAGE.filters.statuses || []).filter(c => String(c) !== v);
  triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll();
  toast('Exclus din selectie: ' + (KIND_LABEL[kind] || kind) + ' ' + entLabel(kind, value) + ' -- anulezi cu "Inapoi"');
}

// ---------- meniul contextual ----------
const CTX = { el: null };
function ctxClose() { const m = $('#ctxMenu'); if (m) m.classList.remove('open'); }
function ctxShow(x, y, title, items) {
  const m = $('#ctxMenu');
  m.innerHTML = `<div class="ctxHead">${tEsc(title)}</div>` + items.map((it, i) => it === '-' ? '<div class="ctxSep"></div>'
    : `<div class="ctxItem" role="menuitem" tabindex="-1" data-i="${i}">${it.icon ? `<span class="ctxIco">${it.icon}</span>` : '<span class="ctxIco"></span>'}${tEsc(it.label)}${it.hint ? `<span class="ctxHint">${tEsc(it.hint)}</span>` : ''}</div>`).join('');
  m.classList.add('open');
  const r = m.getBoundingClientRect();
  m.style.left = Math.max(4, Math.min(window.innerWidth - r.width - 6, x)) + 'px';
  m.style.top = Math.max(4, Math.min(window.innerHeight - r.height - 6, y)) + 'px';
  m.querySelectorAll('.ctxItem').forEach(el => {
    el.onclick = (e) => { e.stopPropagation(); ctxClose(); const it = items[+el.dataset.i]; try { it.run(); } catch (err) { showError(err.message); } };
  });
  const first = m.querySelector('.ctxItem'); if (first) first.focus();
}
$('#ctxMenu') && $('#ctxMenu').addEventListener('keydown', (e) => {
  const items = [...$('#ctxMenu').querySelectorAll('.ctxItem')];
  const i = items.indexOf(document.activeElement);
  if (e.key === 'ArrowDown') { e.preventDefault(); (items[i + 1] || items[0]).focus(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); (items[i - 1] || items[items.length - 1]).focus(); }
  else if (e.key === 'Enter' && i >= 0) { e.preventDefault(); items[i].click(); }
});
function entityMenuItems(kind, value, extra) {
  const lbl = entLabel(kind, value);
  const items = [
    { icon: '&#128269;', label: 'Deschide detalii (panoul de explorare)', run: () => XP.open(kind, value) },
    { icon: '&#9776;', label: 'Vezi cererile RAW asociate', run: () => XP.open(kind, value, 'raw') },
    { icon: '&#9888;', label: 'Vezi alertele asociate', run: () => XP.open(kind, value, 'alerts') },
    '-',
    { icon: '&#8853;', label: 'Filtreaza dupa aceasta valoare', hint: 'global', run: () => gfAddEntity(kind, value) },
  ];
  if (EXCLUDABLE[kind]) items.push({ icon: '&#8856;', label: 'Exclude din selectie', hint: 'global', run: () => gfExcludeEntity(kind, value) });
  items.push('-');
  if (XP.cmpA && !(XP.cmpA.kind === kind && XP.cmpA.value === value)) {
    items.push({ icon: '&#8646;', label: `Compara cu ${KIND_LABEL[XP.cmpA.kind] || ''} ${entLabel(XP.cmpA.kind, XP.cmpA.value)}`, run: () => XP.openCompare(XP.cmpA, { kind, value }) });
  }
  items.push({ icon: '&#8646;', label: 'Compara cu alta entitate...', hint: 'alege apoi a doua', run: () => { XP.cmpA = { kind, value }; toast(`Comparatie: ${lbl} retinut ca A -- click dreapta pe alta entitate -> "Compara cu"`); XP.renderCmpBanner(); } });
  items.push({ icon: '&#11015;', label: 'Exporta cererile (CSV)', run: () => xpExport(kind, value, 'csv') });
  items.push({ icon: '&#11015;', label: 'Exporta liniile originale (.log)', run: () => xpExport(kind, value, 'log') });
  items.push({ icon: '&#10697;', label: 'Copiaza valoarea', run: () => copyToClipboard(kind === 'alert' ? String(value).split('|')[0] : String(value)) });
  if (kind === 'ip') items.push({ icon: '&#128273;', label: 'Audit trail sesiune admin (in perioada)', run: () => openAuditDrawer(value, null) });
  if (kind === 'alert') items.push({ icon: '&#128273;', label: 'Audit trail sesiune admin', run: () => openAuditDrawer(String(value).split('|')[0], null) });
  (extra || []).forEach(x => items.push(x));
  return items;
}
function openEntityMenu(x, y, kind, value, extra) {
  ctxShow(x, y, `${KIND_LABEL[kind] || kind}: ${entLabel(kind, value)}`, entityMenuItems(kind, value, extra));
}
// legatura atributelor existente (tabelele v42, celulele din tabelul RAW) cu tipurile de entitati
function entityFromElement(el) {
  let t = el.closest('[data-ek]');
  if (t) return { kind: t.dataset.ek, value: t.dataset.ev, el: t };
  t = el.closest('.cellInteractive[data-field]');
  if (t) {
    const k = { ip: 'ip', country: 'country', path: 'path', http_status: 'status', ua: 'ua', method: 'method', action: 'action' }[t.dataset.field];
    if (k) return { kind: k, value: t.dataset.value, el: t };
  }
  t = el.closest('[data-ip],[data-path],[data-country],[data-alert-ip]');
  if (t) {
    if (t.dataset.alertIp) return { kind: 'alert', value: t.dataset.alertIp + '|' + t.dataset.action, el: t };
    if (t.dataset.ip) return { kind: 'ip', value: t.dataset.ip, el: t };
    if (t.dataset.path) return { kind: 'path', value: t.dataset.path, el: t };
    if (t.dataset.country) return { kind: 'country', value: t.dataset.country, el: t };
  }
  return null;
}
document.addEventListener('contextmenu', (e) => {
  if (!DATASET_ID || !TRIAGE.ready) return;
  if (e.target.closest('input,textarea,select')) return;
  const ent = entityFromElement(e.target);
  if (ent) { e.preventDefault(); openEntityMenu(e.clientX, e.clientY, ent.kind, ent.value); return; }
  const row = e.target.closest('.triageRow');
  if (row) {
    const ev = TRIAGE.rows[+row.dataset.idx];
    if (ev) { e.preventDefault(); openEventMenu(e.clientX, e.clientY, ev, { rows: TRIAGE.rows, label: 'Raw Logs', more: triageMoreForList }); }
  }
});
document.addEventListener('click', (e) => {
  const q = e.target.closest('[data-eq]');
  if (q) {
    e.preventDefault(); e.stopPropagation();
    const k = q.dataset.ek, v = q.dataset.ev;
    if (q.dataset.eq === 'add') gfAddEntity(k, v);
    else if (q.dataset.eq === 'excl') gfExcludeEntity(k, v);
    else { const r = q.getBoundingClientRect(); openEntityMenu(r.left, r.bottom + 2, k, v); }
    return;
  }
  if (!e.target.closest('#ctxMenu')) ctxClose();
}, true);
function openEventMenu(x, y, ev, list) {
  ctxShow(x, y, `Cererea ${fmtTimeShort(ev.ts_str)} · ${ev.ip}`, [
    { icon: '&#128196;', label: 'Detaliul cererii + linia originala', run: () => XP.openEvent(list, list.rows.indexOf(ev)) },
    { icon: '&#128269;', label: 'Activitatea IP-ului ' + ev.ip, run: () => XP.open('ip', ev.ip) },
    { icon: '&#128279;', label: 'Istoricul endpoint-ului', run: () => XP.open('path', (ev.path || '').split('?')[0]) },
    { icon: '&#9201;', label: 'Context: acest IP ±5 min', hint: 'schimba perioada', run: () => xpContextAround(ev) },
    '-',
    { icon: '&#8853;', label: 'Filtreaza pe IP', run: () => gfAddEntity('ip', ev.ip) },
    { icon: '&#8856;', label: 'Exclude IP-ul', run: () => gfExcludeEntity('ip', ev.ip) },
    { icon: '&#10697;', label: 'Copiaza randul (JSON)', run: () => copyToClipboard(JSON.stringify(ev, null, 2)) },
  ]);
}
function xpContextAround(ev) {
  triageSetRange(ev.ts - 300, ev.ts + 300);
  XP.open('ip', ev.ip, 'raw');
}
function xpExport(kind, value, format) {
  const p = new URLSearchParams({ kind, value: value == null ? '' : String(value), format });
  window.open(redactUrl(gfUrl(`/api/dataset/${DATASET_ID}/export_events?${p}`)), '_blank');
  toast('Export pornit: ' + (format === 'log' ? 'liniile originale' : 'CSV') + ' pentru selectia curenta' + (kind !== 'sel' ? ' + ' + entLabel(kind, value) : ''));
}
// suprascrie meniul vechi din tabelele v42: acelasi meniu contextual peste tot,
// cu actiunea veche (fereastra din analiza detaliata) pastrata ca ultima optiune
function showEntityMenu(evt, kind, value, legacyLabel, legacyFn) {
  evt.stopPropagation();
  openEntityMenu(evt.clientX, evt.clientY, kind, value, ['-', { icon: '&#128450;', label: legacyLabel, run: legacyFn }]);
}

// ---------- utilitare de afisare ----------
function xpKpi(v, l, cls, act) { return `<div class="spKpi ${cls || ''}${act ? ' clickable' : ''}"${act ? ` data-xact="${tEscAttr(act)}"` : ''}><div class="v">${v}</div><div class="l">${l}</div></div>`; }
function xpPct(n, d) { return d ? (100 * n / d).toFixed(1) + '%' : '-'; }
function xpBars(rows, opts) {
  // rows: [{label, n, kind, value, sub}] -- bare orizontale clickabile
  if (!rows || !rows.length) return `<div class="spMsg">${tEsc(opts && opts.empty || 'Nimic in selectie.')}</div>`;
  const max = Math.max(1, ...rows.map(r => r.n));
  return '<table class="spList xpList">' + rows.map(r => {
    const link = r.kind ? `${r.kind === 'country' ? flagHtml(r.value) : ''}<a class="spLink" data-ek="${tEscAttr(r.kind)}" data-ev="${tEscAttr(r.value)}" data-xopen="1" tabindex="0">${tEsc(r.label)}</a>${entQuick(r.kind, r.value)}` : tEsc(r.label);
    return `<tr><td class="${opts && opts.mono ? 'pathCell' : ''}">${link}${r.badges || ''}</td><td class="num">${fmtN(r.n)}${spBar(r.n, max)}</td>${r.sub != null ? `<td class="num xpSub">${r.sub}</td>` : ''}</tr>`;
  }).join('') + '</table>';
}
function xpBusy(msg) { return `<div class="xpBusy"><span class="spBusy"></span>${tEsc(msg || 'Se incarca...')}</div>`; }
function xpErr(msg) { return `<div class="spMsg err">${tEsc(msg)}</div>`; }

// ---------- graficul de timp reutilizabil (click = bara, tragere = interval) ----------
// selectia pe grafic restrange perioada curenta (capetele intervalelor nu o depasesc)
function xpPickRange(a, b) {
  const lo = Math.max(a, TRIAGE.tsFrom ?? a), hi = Math.min(b, TRIAGE.tsTo ?? b);
  triageSetRange(lo, Math.max(lo, hi));
  toast('Perioada globala: ' + fmtRange(lo, Math.max(lo, hi)));
}
// seria vine doar cu intervalele nenule: completam cu zero ca axa timpului sa fie continua
function xpFillBuckets(d) {
  const bs = d.bucket_seconds, out = [];
  if (!d.buckets.length || !d.range) return d.buckets;
  const by = new Map(d.buckets.map(b => [b.bucket, b]));
  const a = Math.floor(d.range[0] / bs) * bs, z = Math.floor(d.range[1] / bs) * bs;
  if ((z - a) / bs > 2000) return d.buckets;
  for (let t = a; t <= z; t += bs) out.push(by.get(t) || { bucket: t, total: 0, c2: 0, c3: 0, c4: 0, c5: 0, critical: 0, high: 0, medium: 0 });
  return out;
}
function xpRangeChart(canvas, buckets, bsec, mode, onRange) {
  const labels = buckets.map(b => fmtTimeShort(epochToDtLocalStr(b.bucket)));
  const ds = mode === 'errors'
    ? [
        { label: '4xx', data: buckets.map(b => b.c4 || 0), backgroundColor: '#E08A1E' },
        { label: '5xx', data: buckets.map(b => b.c5 || 0), backgroundColor: '#D2384C' },
      ]
    : mode === 'sev'
    ? [
        { label: 'CRITICAL', data: buckets.map(b => b.critical || 0), backgroundColor: '#D2384C' },
        { label: 'HIGH', data: buckets.map(b => b.high || 0), backgroundColor: '#E08A1E' },
        { label: 'MEDIUM', data: buckets.map(b => b.medium || 0), backgroundColor: '#C9A227' },
      ]
    : [
        { label: '2xx', data: buckets.map(b => b.c2 || 0), backgroundColor: '#2E9E6B' },
        { label: '3xx', data: buckets.map(b => b.c3 || 0), backgroundColor: '#3A6FD8' },
        { label: '4xx', data: buckets.map(b => b.c4 || 0), backgroundColor: '#E08A1E' },
        { label: '5xx', data: buckets.map(b => b.c5 || 0), backgroundColor: '#D2384C' },
        { label: 'altele', data: buckets.map(b => Math.max(0, b.total - (b.c2 || 0) - (b.c3 || 0) - (b.c4 || 0) - (b.c5 || 0))), backgroundColor: '#A3ADBA' },
      ];
  const chart = new Chart(canvas.getContext('2d'), {
    type: 'bar', data: { labels, datasets: ds },
    options: {
      animation: false, maintainAspectRatio: false, responsive: true,
      interaction: { mode: 'index', intersect: false },
      datasets: { bar: { barPercentage: 1, categoryPercentage: 1 } },
      plugins: { legend: { display: true, position: 'bottom', labels: { color: '#5D6A79', boxWidth: 10, font: { size: 10 } } },
                 tooltip: { callbacks: { footer: (it) => 'Total: ' + fmtN(buckets[it[0].dataIndex].total) } } },
      scales: { x: { stacked: true, ticks: { color: '#5D6A79', font: { size: 10 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 }, grid: { display: false } },
                y: { stacked: true, ticks: { color: '#5D6A79', font: { size: 10 } }, grid: { color: 'rgba(21,33,46,.07)' }, beginAtZero: true } },
    },
  });
  let drag = null;
  const idxAt = (e) => {
    const r = canvas.getBoundingClientRect();
    const v = chart.scales.x.getValueForPixel(e.clientX - r.left);
    return v == null ? null : Math.max(0, Math.min(buckets.length - 1, Math.round(v)));
  };
  canvas.onmousedown = (e) => { const i = idxAt(e); if (i != null) drag = { a: i, b: i }; };
  canvas.onmousemove = (e) => { if (drag) { const i = idxAt(e); if (i != null) drag.b = i; } };
  canvas.onmouseup = () => {
    if (!drag) return;
    const lo = Math.min(drag.a, drag.b), hi = Math.max(drag.a, drag.b);
    drag = null;
    if (buckets[lo] && buckets[hi]) onRange(buckets[lo].bucket, buckets[hi].bucket + bsec - 1);
  };
  canvas.onmouseleave = () => { drag = null; };
  canvas.style.cursor = 'crosshair';
  canvas.title = 'Click pe o bara sau trage peste mai multe: seteaza perioada globala';
  return chart;
}

// ==========================================================================
// PANOUL DE EXPLORARE
// ==========================================================================
const XP = {
  stack: [], pos: -1, seq: 0, charts: [], cache: new Map(), cmpA: null, evCache: {},
  isOpen() { return $('#xpDrawer').classList.contains('open'); },
  cur() { return this.stack[this.pos]; },
  push(v) {
    this.stack = this.stack.slice(0, this.pos + 1);
    this.stack.push(v);
    if (this.stack.length > 60) this.stack.shift();
    this.pos = this.stack.length - 1;
    this.show(); this.render();
  },
  open(kind, value, tab) {
    if (!DATASET_ID || !TRIAGE.ready) { showError('Indexarea nu e gata -- panoul de explorare devine disponibil in cateva secunde.'); return; }
    if (kind === 'country' && (value === '' || value == null)) value = '??';
    if (kind === 'path') value = String(value).split('?')[0];
    const c = this.cur();
    if (this.isOpen() && c && c.type === 'ent' && c.kind === kind && c.value === String(value ?? '')) { if (tab) { c.tab = tab; this.render(); } return; }
    this.push({ type: 'ent', kind, value: String(value ?? ''), tab: tab || 'sum', evSort: 'ts_desc', rawLines: false });
  },
  openEvent(list, index) { if (index < 0) index = 0; this.push({ type: 'ev', list, index }); },
  openCompare(a, b) { this.push({ type: 'cmp', a, b }); },
  openSecurity() { this.push({ type: 'sec' }); },
  openWorkspace() { showPage('investigations'); },
  back() { if (this.pos > 0) { this.pos--; this.render(); } },
  fwd() { if (this.pos < this.stack.length - 1) { this.pos++; this.render(); } },
  show() {
    $('#xpDrawer').classList.add('open');
    document.body.classList.add('xpOpen');
    if (typeof dockApply === 'function') dockApply();
  },
  close() {
    $('#xpDrawer').classList.remove('open');
    document.body.classList.remove('xpOpen');
    this.seq++;
    if (typeof dockApply === 'function') dockApply();
  },
  destroyCharts() { this.charts.forEach(c => { try { c.destroy(); } catch (e) {} }); this.charts = []; },
  refresh() { if (this.isOpen()) { this.cache.clear(); this.render(); } },
  renderCmpBanner() {
    const el = $('#xpCmpBanner');
    if (!this.cmpA) { el.style.display = 'none'; return; }
    el.style.display = 'flex';
    el.innerHTML = `<span>&#8646; A = ${tEsc(KIND_LABEL[this.cmpA.kind] || '')} <b>${tEsc(entLabel(this.cmpA.kind, this.cmpA.value))}</b> -- click dreapta pe alta entitate &rarr; "Compara cu"</span>` +
      `<button class="ghost" id="xpCmpClear">&times; renunta</button>`;
    $('#xpCmpClear').onclick = () => { this.cmpA = null; this.renderCmpBanner(); };
  },
  render() {
    const v = this.cur();
    if (!v) return;
    this.destroyCharts();
    const seq = ++this.seq;
    $('#xpBack').disabled = this.pos <= 0;
    $('#xpFwd').disabled = this.pos >= this.stack.length - 1;
    this.renderCmpBanner();
    $('#xpScope').innerHTML = `<span class="xpScopeLbl">Selectie:</span> <b>${tEsc(gfDescribe())}</b>` +
      (gfIsActive() ? ' <a href="#" data-xreset="1">arata tot logul</a>' : '');
    if (v.type === 'ent') return xpRenderEntity(v, seq);
    if (v.type === 'ev') return xpRenderEvent(v, seq);
    if (v.type === 'cmp') return xpRenderCompare(v, seq);
    if (v.type === 'sec') return xpRenderSecurityView(v, seq);
    if (v.type === 'ws') return WS.render(seq);
  },
  stillMine(seq) { return seq === this.seq && this.isOpen(); },
};
$('#xpBack').onclick = () => XP.back();
$('#xpFwd').onclick = () => XP.fwd();
$('#xpClose').onclick = () => XP.close();
$('#xpDrawer').addEventListener('click', (e) => {
  if (e.target.closest('[data-xreset]')) { e.preventDefault(); $('#triageResetBtn').click(); return; }
  const o = e.target.closest('[data-xopen]');
  if (o && o.dataset.ek) { e.preventDefault(); XP.open(o.dataset.ek, o.dataset.ev); return; }
  const k = e.target.closest('[data-xact]');
  if (k) {
    const [kind, value, tab] = k.dataset.xact.split('::');
    if (kind === 'tab') { const v = XP.cur(); if (v) { v.tab = value; XP.render(); } return; }
    XP.open(kind, value || '', tab);
  }
});

function xpFetchJSON(url) {
  return fetch(url).then(async r => {
    const d = await r.json().catch(() => ({ error: 'raspuns invalid (HTTP ' + r.status + ')' }));
    if (r.status === 202) throw new Error(d.error || 'Indexarea e inca in curs.');
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    return d;
  });
}
function xpExploreData(kind, value, extra) {
  const p = new URLSearchParams({ kind, value: value || '', ...(extra || {}) });
  const url = gfUrl(`/api/dataset/${DATASET_ID}/explore?${p}`);
  if (!XP.cache.has(url)) {
    const pr = xpFetchJSON(url);
    XP.cache.set(url, pr);
    pr.catch(() => XP.cache.delete(url));
  }
  return XP.cache.get(url);
}

const XP_TABS = [['sum', 'Sumar'], ['time', 'In timp'], ['raw', 'Cereri RAW'], ['rel', 'Corelate'], ['alerts', 'Alerte']];
function xpRenderEntity(v, seq) {
  const head = $('#xpTitle');
  head.innerHTML = `<span class="xpKind">${tEsc(KIND_LABEL[v.kind] || v.kind)}</span><span class="xpVal" title="${tEscAttr(v.value)}">${tEsc(v.kind === 'sel' ? 'tot ce trece de filtre' : entLabel(v.kind, v.value))}</span>`;
  const canX = EXCLUDABLE[v.kind];
  $('#xpActions').innerHTML = (v.kind !== 'sel' ? `<button class="ghost" data-xa="add" title="Adauga entitatea la selectia globala">&#8853; Filtreaza</button>` : '') +
    (canX ? `<button class="ghost" data-xa="excl" title="Exclude entitatea din selectia globala">&#8856; Exclude</button>` : '') +
    (v.kind !== 'sel' ? `<button class="ghost" data-xa="cmp" title="Compara cu alta entitate">&#8646; Compara</button>` : '') +
    `<button class="ghost" data-xa="csv" title="Exporta cererile (CSV)">&#11015; CSV</button>` +
    `<button class="ghost" data-xa="log" title="Exporta liniile originale">&#11015; .log</button>` +
    (v.kind !== 'sel' ? `<button class="ghost" data-xa="copy" title="Copiaza valoarea">&#10697;</button>` : '') +
    `<button class="ghost" data-xa="more" title="Toate actiunile">&#8943;</button>`;
  $('#xpActions').querySelectorAll('[data-xa]').forEach(b => b.onclick = (e) => {
    const a = b.dataset.xa;
    if (a === 'add') gfAddEntity(v.kind, v.value);
    else if (a === 'excl') gfExcludeEntity(v.kind, v.value);
    else if (a === 'cmp') {
      if (XP.cmpA && !(XP.cmpA.kind === v.kind && XP.cmpA.value === v.value)) XP.openCompare(XP.cmpA, { kind: v.kind, value: v.value });
      else { XP.cmpA = { kind: v.kind, value: v.value }; XP.renderCmpBanner(); toast('Retinut ca A -- deschide alta entitate si apasa "Compara"'); }
    }
    else if (a === 'csv' || a === 'log') xpExport(v.kind, v.value, a);
    else if (a === 'copy') copyToClipboard(v.kind === 'alert' ? v.value.split('|')[0] : v.value);
    else if (a === 'more') { const r = b.getBoundingClientRect(); openEntityMenu(r.left - 200, r.bottom + 2, v.kind, v.value); }
  });
  $('#xpTabs').innerHTML = XP_TABS.map(([k, l]) => `<button class="spTab${v.tab === k ? ' active' : ''}" data-xtab="${k}">${l}<span class="xpTabN" id="xpTabN_${k}"></span></button>`).join('');
  $('#xpTabs').querySelectorAll('[data-xtab]').forEach(b => b.onclick = () => { v.tab = b.dataset.xtab; XP.render(); });
  const body = $('#xpBody');
  body.innerHTML = xpBusy('Se calculeaza pentru selectia curenta...');
  body.scrollTop = 0;
  const p = xpExploreData(v.kind, v.value);
  p.then(d => {
    if (!XP.stillMine(seq)) return;
    const nAlerts = (d.alerts || []).reduce((a, b) => a + b.hits, 0);
    const tn = (k, t) => { const el = $('#xpTabN_' + k); if (el) el.textContent = t; };
    tn('raw', d.requests ? ' ' + fmtN(d.requests) : ' 0');
    tn('alerts', nAlerts ? ' ' + fmtN(nAlerts) : '');
    if (v.kind === 'ip' && d.country !== undefined) head.innerHTML += `<span class="xpSub2">${tEsc(d.country ? ccLabel(d.country) : 'tara nedeterminata')}</span>`;
  }).catch(() => {});
  if (v.tab === 'raw') return xpRenderRaw(v, seq, body);
  if (v.tab === 'time') return xpRenderTime(v, seq, body);
  p.then(d => {
    if (!XP.stillMine(seq)) return;
    if (!d.requests) {
      body.innerHTML = `<div class="xpEmpty"><b>Nicio cerere.</b> ${tEsc(d.empty_reason || '')}</div>` +
        `<div class="spMsg">Selectia curenta: ${tEsc(d.selection_label)} (${fmtN(d.selection_requests)} cereri). Panoul NU revine automat la tot logul -- schimba perioada sau filtrele, ori apasa "arata tot logul" de mai sus.</div>`;
      return;
    }
    if (v.tab === 'rel') body.innerHTML = xpRelHtml(v, d);
    else if (v.tab === 'alerts') xpRenderAlerts(v, seq, body, d);
    else body.innerHTML = xpSumHtml(v, d);
  }).catch(e => { if (XP.stillMine(seq)) body.innerHTML = xpErr('Eroare: ' + e.message); });
}

function xpUnusualBadges(t, d) {
  const b = [];
  const share = d.requests ? t.n / d.requests : 0;
  if (share >= 0.2 && d.requests >= 50 && d.unique_ips > 1) b.push(['concentrare', `${(100 * share).toFixed(0)}% din cererile entitatii vin de la acest IP`]);
  if (t.n >= 20 && (t.err_4xx + t.err_5xx) / t.n >= 0.5) b.push(['erori', `${t.err_4xx + t.err_5xx} din ${t.n} cereri cu 4xx/5xx`]);
  if (t.per_min >= 30) b.push(['ritm', `${t.per_min} cereri/minut in medie (intre prima si ultima cerere)`]);
  return b.map(([l, why]) => `<span class="xpBadge" title="${tEscAttr(why)}">${l}</span>`).join('');
}
function xpSumHtml(v, d) {
  const w = d.wordpress || {};
  const share = v.kind !== 'sel' ? `<div class="l">${xpPct(d.requests, d.selection_requests)} din selectie</div>` : '';
  let h = `<div class="ipProfGrid">` +
    `<div class="spKpi clickable" data-xact="tab::raw"><div class="v">${fmtN(d.requests)}</div><div class="l">Cereri</div>${share}</div>` +
    xpKpi(fmtN(d.unique_ips), 'IP-uri unice', '', v.kind === 'ip' ? '' : 'tab::rel') +
    xpKpi(fmtN(d.unique_paths), 'URL-uri distincte', '', 'tab::rel') +
    xpKpi(fmtN(d.sessions_est), 'Sesiuni estimate') +
    xpKpi(fmtN(d.err_4xx), 'Erori 4xx', d.err_4xx ? 'warn' : '', v.kind === 'sclass' ? '' : 'sclass::4xx') +
    xpKpi(fmtN(d.err_5xx), 'Erori 5xx', d.err_5xx ? 'bad' : '', v.kind === 'sclass' ? '' : 'sclass::5xx') +
    xpKpi(d.req_per_min, 'Cereri / minut') +
    xpKpi(d.peak_minute ? fmtN(d.peak_minute.n) : '-', 'Varf / minut' + (d.peak_minute ? ' · ' + fmtEpoch(d.peak_minute.minute) : '')) +
    `</div><div class="spMsg">Prima cerere: <b>${fmtEpoch(d.ts_min)}</b> · ultima: <b>${fmtEpoch(d.ts_max)}</b> · UA-uri distincte: ${fmtN(d.unique_uas)}` +
    (v.kind !== 'sel' ? ` · ${xpPct(d.requests, d.selection_requests)} din ${fmtN(d.selection_requests)} cereri ale selectiei` : '') + `</div>`;
  if ((d.signals || []).length) {
    h += `<div class="ipProfSec">Comportament (indicatori, cu justificare)</div>` + d.signals.map(s => `<div class="sigRow ${tEscAttr(s.level)}"><b>${tEsc(s.label)}</b> <span class="tag ${s.level === 'high' ? 'HIGH' : s.level === 'medium' ? 'MEDIUM' : 'LOW'}">incredere ${s.level === 'high' ? 'ridicata' : s.level === 'medium' ? 'medie' : 'scazuta'}</span><div class="why">${tEsc(s.why)}</div></div>`).join('');
  } else if (v.kind === 'ip') h += `<div class="ipProfSec">Comportament</div><div class="spMsg">Niciun prag depasit (volum, ritm, erori, autentificare, xmlrpc) in selectie.</div>`;
  const st = (d.statuses || []).slice().sort((a, b) => a.status - b.status);
  h += `<div class="ipProfSec">Coduri HTTP <span class="xpHint">click: investigheaza codul · &#8853;/&#8856; filtreaza / exclude</span></div>` +
    xpBars(st.map(x => ({ label: String(x.status), n: x.n, kind: 'status', value: String(x.status), sub: xpPct(x.n, d.requests) })));
  h += `<div class="ipProfSec">Metode</div><div class="spMsg">${(d.methods || []).map(x => `<a class="spLink" data-ek="method" data-ev="${tEscAttr(x.method)}" data-xopen="1">${tEsc(x.method)}</a>: ${fmtN(x.n)}`).join(' · ')}</div>`;
  const wpRows = Object.keys(WP_CAT_LABEL).filter(k => k !== 'wp_any' && w[k]).map(k => ({ label: WP_CAT_LABEL[k], n: w[k], kind: 'wp', value: k, sub: `${fmtN(w[k + '_ips'])} IP · ${fmtN(w[k + '_sessions'])} ses.` }));
  if (wpRows.length || v.kind === 'wp') {
    h += `<div class="ipProfSec">WordPress <span class="xpHint">cereri · IP-uri unice · sesiuni estimate (pauza &gt; 30 min = sesiune noua)</span></div>` + xpBars(wpRows, { empty: 'Nicio cerere WordPress.' });
    const codes = {};
    (w.status_by_category || []).forEach(x => { (codes[x.cat] = codes[x.cat] || []).push(`${x.status}: ${fmtN(x.n)}`); });
    const cl = Object.entries(codes).map(([c, l]) => `<div><b>${tEsc(WP_CAT_LABEL[c] || c)}</b>: ${tEsc(l.slice(0, 8).join(' · '))}</div>`).join('');
    if (cl) h += `<div class="spMsg">${cl}</div>`;
    h += `<div class="spMsg">Un acces la wp-admin / wp-login NU inseamna automat atac sau autentificare reusita. Login-urile deduse (POST 302 + /wp-admin/ 200 in 5 min) apar ca "Login OK" in cereri si in alerte.</div>`;
  }
  if ((d.wp_routes || []).length) {
    h += `<div class="ipProfSec">Rute plugin / tema <span class="xpHint">2xx = servite · 4xx = inexistente</span></div>` +
      xpBars(d.wp_routes.slice(0, 12).map(r => ({ label: r.route, n: r.n, kind: 'prefix', value: '/wp-content/' + r.route + '/', sub: `${fmtN(r.ips)} IP · 2xx ${fmtN(r.ok_2xx)} · 4xx ${fmtN(r.err_4xx)}` })), { mono: true });
  }
  if (v.kind !== 'ip') h += `<div class="ipProfSec">Top IP-uri</div>` + xpIpRows(d, 8);
  if (v.kind !== 'path') h += `<div class="ipProfSec">Top endpoint-uri</div>` + xpBars((d.top_paths || []).slice(0, 8).map(r => ({ label: r.path, n: r.n, kind: 'path', value: r.path, sub: fmtN(r.ips) + ' IP' })), { mono: true });
  return h;
}
function xpIpRows(d, n) {
  return xpBars((d.top_ips || []).slice(0, n).map(t => ({
    label: t.ip, n: t.n, kind: 'ip', value: t.ip, badges: xpUnusualBadges(t, d),
    sub: `${tEsc(t.country || '??')} · 4xx ${fmtN(t.err_4xx)} · ${t.per_min}/min`,
  })));
}
function xpRelHtml(v, d) {
  let h = `<div class="spMsg">Entitatile care apar impreuna cu aceasta, in selectia curenta. Click: deschide entitatea (Inapoi revine aici) · &#8853;/&#8856;: filtreaza / exclude · click dreapta: toate actiunile.</div>`;
  if (v.kind !== 'ip') h += `<div class="ipProfSec">IP-uri (${fmtN(d.unique_ips)}) <span class="xpHint">etichetele = comportament neobisnuit pentru aceasta entitate</span></div>` + xpIpRows(d, 15);
  if (v.kind !== 'path') h += `<div class="ipProfSec">Endpoint-uri (${fmtN(d.unique_paths)})</div>` + xpBars((d.top_paths || []).map(r => ({ label: r.path, n: r.n, kind: 'path', value: r.path, sub: fmtN(r.ips) + ' IP' })), { mono: true });
  if (v.kind !== 'country') h += `<div class="ipProfSec">Tari</div>` + xpBars((d.countries || []).slice(0, 12).map(r => ({ label: r.country ? ccLabel(r.country) : '?? (nedeterminata)', n: r.n, kind: 'country', value: r.country || '??', sub: fmtN(r.ips) + ' IP' })));
  h += `<div class="ipProfSec">User-Agent</div>` + xpBars((d.user_agents || []).map(r => ({ label: r.ua || '(gol)', n: r.n, kind: 'ua', value: r.ua })), { mono: true });
  if ((d.error_paths || []).length) h += `<div class="ipProfSec">Erori pe URL</div>` + xpBars(d.error_paths.slice(0, 12).map(r => ({ label: `${r.status} ${r.path}`, n: r.n, kind: 'path', value: r.path, sub: `${fmtN(r.ips)} IP · ${fmtEpoch(r.first_ts)}` })), { mono: true });
  return h;
}

// ---------- tab "In timp": distributie + comparatie de perioade ----------
async function xpRenderTime(v, seq, body) {
  body.innerHTML = `<div class="xpChartWrap"><canvas id="xpTimeChart"></canvas></div><div class="spMsg" id="xpTimeNote">${xpBusy('Se calculeaza distributia in timp...')}</div>` +
    `<div class="ipProfSec">Compara cu alta perioada <span class="xpHint">aceleasi filtre + aceeasi entitate</span></div>` +
    `<div class="xpCmpCtl"><button class="ghost" data-cmpp="prev">perioada precedenta (aceeasi durata)</button><button class="ghost" data-cmpp="day">aceeasi perioada, cu o zi inainte</button>` +
    `<span class="xpCmpCustom"><input type="datetime-local" step="1" id="xpCmpFrom"> &rarr; <input type="datetime-local" step="1" id="xpCmpTo"> <button class="ghost" data-cmpp="custom">compara</button></span></div><div id="xpCmpOut"></div>`;
  const p = new URLSearchParams({ kind: v.kind, value: v.value });
  try {
    const d = await xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?${p}`));
    if (!XP.stillMine(seq)) return;
    const unit = d.bucket_seconds % 3600 === 0 ? (d.bucket_seconds / 3600) + ' h' : (d.bucket_seconds / 60) + ' min';
    if (!d.buckets.length) { $('#xpTimeNote').textContent = 'Nicio cerere in perioada selectata pentru aceasta entitate.'; }
    else {
      XP.charts.push(xpRangeChart($('#xpTimeChart'), xpFillBuckets(d), d.bucket_seconds, 'classes', xpPickRange));
      const tot = d.buckets.reduce((a, b) => a + b.total, 0);
      const peak = d.buckets.reduce((a, b) => b.total > a.total ? b : a, d.buckets[0]);
      $('#xpTimeNote').innerHTML = `Intervale de ${unit} pe perioada selectata (${fmtEpoch(d.range[0])} &rarr; ${fmtEpoch(d.range[1])}); ${fmtN(tot)} cereri; varf ${fmtN(peak.total)} la ${fmtEpoch(peak.bucket)}. Click / tragere pe grafic = seteaza perioada globala (panoul se actualizeaza; "Inapoi" revine).`;
    }
  } catch (e) { if (XP.stillMine(seq)) $('#xpTimeNote').innerHTML = xpErr('Eroare: ' + e.message); }
  const span = () => { const a = TRIAGE.tsFrom, b = TRIAGE.tsTo; return [a, b, b - a + 1]; };
  const [a0, b0] = span();
  $('#xpCmpFrom').value = epochToDtLocal(a0 - (b0 - a0 + 1), TRIAGE.tzOffset);
  $('#xpCmpTo').value = epochToDtLocal(a0 - 1, TRIAGE.tzOffset);
  body.querySelectorAll('[data-cmpp]').forEach(btn => btn.onclick = () => {
    const [a, b, len] = span();
    let ca, cb;
    if (btn.dataset.cmpp === 'prev') { ca = a - len; cb = a - 1; }
    else if (btn.dataset.cmpp === 'day') { ca = a - 86400; cb = b - 86400; }
    else { ca = dtLocalToEpoch($('#xpCmpFrom').value, TRIAGE.tzOffset); cb = dtLocalToEpoch($('#xpCmpTo').value, TRIAGE.tzOffset); }
    if (ca == null || cb == null || cb < ca) { $('#xpCmpOut').innerHTML = xpErr('Interval de comparatie invalid.'); return; }
    xpRunPeriodCompare(v, seq, a, b, ca, cb);
  });
}
async function xpRunPeriodCompare(v, seq, a, b, ca, cb) {
  const out = $('#xpCmpOut');
  out.innerHTML = xpBusy('Se compara...');
  try {
    const d = await xpExploreData(v.kind, v.value, { cmp_from: ca, cmp_to: cb });
    if (!XP.stillMine(seq)) return;
    const B = d.compare || {};
    const rate = (n, x, y) => n ? (n * 60 / Math.max(60, y - x + 1)).toFixed(2) : '0';
    const delta = (x, y, worseUp) => {
      if (!x && !y) return '<td>-</td>';
      if (!x) return '<td class="num">nou</td>';
      const pc = Math.round(100 * (y - x) / x);
      return `<td class="num ${pc === 0 ? '' : ((pc > 0) === worseUp ? 'up' : 'down')}">${pc > 0 ? '+' : ''}${pc}%</td>`;
    };
    const row = (l, x, y, worse) => `<tr><td>${l}</td><td class="num">${fmtN(x)}</td><td class="num">${fmtN(y)}</td>${worse === null ? '<td></td>' : delta(y, x, worse)}</tr>`;
    const A = d, ta = gfTimeNarrowed() ? [TRIAGE.tsFrom, TRIAGE.tsTo] : [d.ts_min, d.ts_max];
    out.innerHTML = `<table class="cmpTbl"><thead><tr><th></th><th>Selectia: ${fmtEpoch(ta[0])} &rarr; ${fmtEpoch(ta[1])}</th><th>Comparatie: ${fmtEpoch(ca)} &rarr; ${fmtEpoch(cb)}</th><th>selectie fata de comparatie</th></tr></thead><tbody>` +
      row('Cereri', A.requests, B.requests, null) +
      `<tr><td>Cereri / minut</td><td class="num">${rate(A.requests, ta[0], ta[1])}</td><td class="num">${rate(B.requests, ca, cb)}</td>${delta(+rate(B.requests, ca, cb), +rate(A.requests, ta[0], ta[1]), true)}</tr>` +
      row('IP-uri unice', A.unique_ips, B.unique_ips, true) + row('URL-uri distincte', A.unique_paths, B.unique_paths, null) +
      row('Erori 4xx', A.err_4xx || 0, B.err_4xx || 0, true) + row('Erori 5xx', A.err_5xx || 0, B.err_5xx || 0, true) +
      row('wp-login POST', (A.wordpress || {}).wp_login_post || 0, (B.wordpress || {}).wp_login_post || 0, true) +
      row('xmlrpc.php', (A.wordpress || {}).xmlrpc || 0, (B.wordpress || {}).xmlrpc || 0, true) +
      `<tr><td>Top IP-uri</td><td>${(A.top_ips || []).slice(0, 5).map(x => tEsc(x.ip) + ' ' + fmtN(x.n)).join('<br>')}</td><td>${(B.top_ips || []).slice(0, 5).map(x => tEsc(x.ip) + ' ' + fmtN(x.n)).join('<br>')}</td><td></td></tr>` +
      `<tr><td>Top endpoint-uri</td><td class="pathCell">${(A.top_paths || []).slice(0, 5).map(x => tEsc(x.path) + ' ' + fmtN(x.n)).join('<br>')}</td><td class="pathCell">${(B.top_paths || []).slice(0, 5).map(x => tEsc(x.path) + ' ' + fmtN(x.n)).join('<br>')}</td><td></td></tr>` +
      `</tbody></table><div class="note">Rosu = mai mult in selectie decat in perioada de comparatie (pentru indicatorii unde "mai mult" e mai rau). Compara ratele, nu totalurile, cand perioadele au lungimi diferite.</div>`;
  } catch (e) { if (XP.stillMine(seq)) out.innerHTML = xpErr('Eroare: ' + e.message); }
}

// ---------- tab "Cereri RAW": lista paginata + liniile originale ----------
function xpEventsLoader(v) {
  const list = { rows: [], total: null, done: false, label: `${KIND_LABEL[v.kind]} ${entLabel(v.kind, v.value)}`, loading: null };
  list.more = async () => {
    if (list.done) return false;
    if (list.loading) return list.loading;
    const p = new URLSearchParams({ kind: v.kind, value: v.value, limit: 100, offset: list.rows.length, sort: v.evSort, raw: 'true' });
    if (list.total == null) p.set('with_count', 'true');
    list.loading = xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/events?${p}`)).then(d => {
      if (typeof d.total === 'number') list.total = d.total;
      list.rows.push(...(d.events || []));
      if ((d.events || []).length < 100) list.done = true;
      list.loading = null;
      return true;
    }, e => { list.loading = null; throw e; });
    return list.loading;
  };
  return list;
}
async function xpRenderRaw(v, seq, body) {
  const list = xpEventsLoader(v);
  v.list = list;
  body.innerHTML = `<div class="xpRawBar"><span id="xpRawCount">${xpBusy('Se incarca cererile...')}</span><span class="spacer"></span>` +
    `<label><input type="checkbox" id="xpRawLines" ${v.rawLines ? 'checked' : ''}> linii originale</label>` +
    `<select id="xpRawSort"><option value="ts_desc">cele mai noi primele</option><option value="ts_asc">cele mai vechi primele</option><option value="risk_desc">risc descrescator</option></select></div>` +
    `<div id="xpRawList" class="xpRawList"></div><div id="xpRawMore"></div>`;
  $('#xpRawSort').value = v.evSort;
  $('#xpRawSort').onchange = () => { v.evSort = $('#xpRawSort').value; XP.render(); };
  $('#xpRawLines').onchange = () => { v.rawLines = $('#xpRawLines').checked; draw(); };
  const draw = () => {
    if (!XP.stillMine(seq)) return;
    const el = $('#xpRawList');
    if (!list.rows.length) {
      el.innerHTML = `<div class="xpEmpty">Nicio cerere pentru aceasta entitate in selectia curenta (${tEsc(gfDescribe())}).</div>`;
      $('#xpRawCount').textContent = '0 cereri'; $('#xpRawMore').innerHTML = ''; return;
    }
    el.innerHTML = list.rows.map((r, i) => v.rawLines
      ? `<pre class="xpRawLine sev-${tEscAttr(r.severity)}" data-xev="${i}" title="click: detaliul cererii">${tEsc(r.raw_line || '')}</pre>`
      : `<div class="xpEvRow sev-${tEscAttr(r.severity)}" data-xev="${i}" tabindex="0"><span class="t">${tEsc(fmtTimeShort(r.ts_str))}</span><span class="ip">${tEsc(r.ip)}</span><span class="st s${String(r.http_status)[0]}">${tEsc(r.http_status)}</span><span class="m">${tEsc(r.method)}</span><span class="p" title="${tEscAttr(r.path)}">${tEsc(r.path)}</span>${r.severity !== 'INFO' ? `<span class="tag ${tEscAttr(r.severity)}">${tEsc(r.severity)}</span>` : ''}</div>`).join('');
    $('#xpRawCount').textContent = `${fmtN(list.rows.length)} din ${fmtN(list.total)} cereri`;
    $('#xpRawMore').innerHTML = list.done ? '' : `<button class="ghost" id="xpRawMoreBtn">incarca inca 100</button>`;
    const mb = $('#xpRawMoreBtn'); if (mb) mb.onclick = () => list.more().then(draw).catch(e => { $('#xpRawMore').innerHTML = xpErr(e.message); });
  };
  $('#xpRawList') && $('#xpRawList').addEventListener('click', (e) => {
    const r = e.target.closest('[data-xev]'); if (r) XP.openEvent(list, +r.dataset.xev);
  });
  $('#xpRawList').addEventListener('contextmenu', (e) => {
    const r = e.target.closest('[data-xev]'); if (!r) return;
    e.preventDefault(); e.stopPropagation(); openEventMenu(e.clientX, e.clientY, list.rows[+r.dataset.xev], list);
  });
  try { await list.more(); draw(); }
  catch (e) { if (XP.stillMine(seq)) body.innerHTML = xpErr('Eroare: ' + e.message); }
}

// ---------- tab "Alerte" ----------
async function xpRenderAlerts(v, seq, body, d) {
  const al = d.alerts || [];
  let h = `<div class="spMsg">Alertele CRITICAL/HIGH din selectia curenta pentru aceasta entitate. Etichetele sunt indicatori calculati din reguli (URL, cod, tara), nu confirmari de atac.</div>`;
  h += al.length ? '<table class="spList">' + al.map(a => `<tr><td><span class="tag ${tEscAttr(a.severity)}">${tEsc(a.severity)}</span></td>` +
    `<td><a class="spLink" data-ek="alert" data-ev="${tEscAttr(a.ip + '|' + a.action_type)}" data-xopen="1">${tEsc(a.label || a.action_type)}</a><div class="xpSub">${tEsc(a.ip)} · ${tEsc(a.country || '??')} · ${tEsc(a.sample_path)}</div></td>` +
    `<td class="num">&times;${fmtN(a.hits)}</td><td class="xpSub">${fmtEpoch(a.first_ts)}<br>${fmtEpoch(a.last_ts)}</td></tr>`).join('') + '</table>'
    : '<div class="xpEmpty">Nicio alerta CRITICAL/HIGH pentru aceasta entitate in selectie.</div>';
  h += `<div class="ipProfSec">Cronologie (inclusiv MEDIUM, grupata)</div><div id="xpSecBox">${xpBusy()}</div>`;
  body.innerHTML = h;
  secRender($('#xpSecBox'), { kind: v.kind, value: v.value, compact: true, seq, owner: 'xp' });
}

// ---------- vederea unui eveniment: toate campurile + linia originala + navigare ----------
const STATUS_HINT2 = { 2: 'succes', 3: 'redirect', 4: 'eroare client', 5: 'eroare server' };
async function xpRenderEvent(v, seq) {
  const list = v.list;
  if (v.index >= list.rows.length && !list.done && list.more) { try { await list.more(); } catch (e) {} }
  if (!XP.stillMine(seq)) return;
  const ev = list.rows[v.index];
  if (!ev) { $('#xpBody').innerHTML = xpErr('Evenimentul nu mai e in lista.'); return; }
  TRIAGE.selId = ev.id; _rowPool.forEach(r => { r._evId = null; }); triageRenderVisibleRows();
  $('#xpTitle').innerHTML = `<span class="xpKind">Cerere</span><span class="xpVal">${tEsc(fmtTimeShort(ev.ts_str))} · ${tEsc(ev.ip)}</span>`;
  const tot = list.total != null ? list.total : list.rows.length;
  $('#xpActions').innerHTML = `<button class="ghost" id="xpEvPrev" title="Cererea anterioara ( [ sau k )" ${v.index <= 0 ? 'disabled' : ''}>&#9664; anterioara</button>` +
    `<span class="xpEvPos">${fmtN(v.index + 1)} / ${fmtN(tot)} <span class="xpSub">(${tEsc(list.label || '')})</span></span>` +
    `<button class="ghost" id="xpEvNext" title="Cererea urmatoare ( ] sau j )" ${(v.index >= list.rows.length - 1 && list.done !== false && !list.more) || (v.index + 1 >= tot) ? 'disabled' : ''}>urmatoarea &#9654;</button>` +
    '';
  $('#xpEvPrev').onclick = () => xpEvStep(-1);
  $('#xpEvNext').onclick = () => xpEvStep(1);
  $('#xpTabs').innerHTML = '';
  const body = $('#xpBody');
  const row = (k, val) => `<div class="k">${tEsc(k)}</div><div class="v">${tEsc(val == null || val === '' ? '-' : val)}</div>`;
  const render = (d, raw, loading) => {
    const cc = d.country || '';
    const st = +d.http_status;
    body.innerHTML = `<div class="evActions">
        <button class="ghost" data-xact="ip::${tEscAttr(d.ip)}">&#128269; IP ${tEsc(d.ip)}</button>
        <button class="ghost" data-xact="path::${tEscAttr((d.path || '').split('?')[0])}">&#128279; istoricul endpoint-ului</button>
        <button class="ghost" data-xact="country::${tEscAttr(cc || '??')}">&#127758; ${tEsc(cc || '??')}</button>
        <button class="ghost" data-xact="status::${tEscAttr(d.http_status)}">cod ${tEsc(d.http_status)}</button>
        <button class="ghost" id="xpEvCtx" title="Seteaza perioada la ±5 min si deschide cererile acestui IP">&#9201; context ±5 min</button>
      </div>
      <div class="evGrid">${row('Timp', d.ts_str)}${row('IP', d.ip)}${row('Tara', cc ? ccLabel(cc) : 'nedeterminata (GeoIP nu are tara pentru acest IP -- nu e ghicita)')}
        ${row('Metoda', d.method)}${row('URL', d.path)}${d.path_decoded && d.path_decoded !== d.path ? row('URL decodat', d.path_decoded) : ''}${d.query ? row('Query string', d.query) : ''}
        ${row('Cod HTTP', `${d.http_status}${STATUS_HINT2[Math.floor(st / 100)] ? ' (' + STATUS_HINT2[Math.floor(st / 100)] + ')' : ''}`)}${row('Marime', d.size != null ? fmtBytes(+d.size) : '-')}
        ${row('Referer', d.referer)}${row('User-Agent', d.ua)}${row('Severitate', d.severity)}${row('Clasificare', d.label || d.action_type)}${d.domain ? row('Domeniu', d.domain) : ''}</div>
      ${d.severity && d.severity !== 'INFO' ? `<div class="spMsg">Clasificarea (${tEsc(d.severity)}) e un INDICATOR calculat din reguli pe URL/cod/tara, nu o confirmare de atac.</div>` : ''}
      <div class="ipProfSec">Linia originala din log <button class="spBtnMini" id="xpCopyRaw">&#10697; copiaza linia</button><button class="spBtnMini" id="xpCopyJson">{ } JSON</button></div>
      <div class="evRaw">${loading ? '<span class="spBusy">se citeste din fisier...</span>' : tEsc(raw || '(linia originala nu mai e disponibila)')}</div>
      <div class="ipProfSec">Aceeasi sursa, in jurul acestei cereri</div><div id="xpEvNear">${xpBusy()}</div>`;
    $('#xpCopyRaw').onclick = () => copyToClipboard(raw || '');
    $('#xpCopyJson').onclick = () => copyToClipboard(JSON.stringify(d, null, 2));
    $('#xpEvCtx').onclick = () => xpContextAround(d);
  };
  render(ev, ev.raw_line || '', !ev.raw_line);
  try {
    const d = XP.evCache[ev.id] || await xpFetchJSON(`/api/dataset/${DATASET_ID}/event?id=${encodeURIComponent(ev.id)}`);
    XP.evCache[ev.id] = d;
    if (!XP.stillMine(seq)) return;
    render(d, d.raw_line, false);
    // vecinii: cererile aceluiasi IP la +/- 2 minute, in selectia curenta
    const p = new URLSearchParams({ kind: 'ip', value: d.ip, limit: 12, sort: 'ts_asc', with_count: 'true' });
    const g = gfObject();
    g.ts_from = Math.max(g.ts_from ?? -Infinity, d.ts - 120); g.ts_to = Math.min(g.ts_to ?? Infinity, d.ts + 120);
    p.set('gf', JSON.stringify(g));
    const n = await xpFetchJSON(`/api/dataset/${DATASET_ID}/events?${p}`);
    if (!XP.stillMine(seq)) return;
    $('#xpEvNear').innerHTML = (n.events || []).length
      ? (n.events.map(r => `<div class="xpEvRow${r.id === d.id ? ' cur' : ''}"><span class="t">${tEsc(fmtTimeShort(r.ts_str))}</span><span class="st s${String(r.http_status)[0]}">${tEsc(r.http_status)}</span><span class="m">${tEsc(r.method)}</span><span class="p" title="${tEscAttr(r.path)}">${tEsc(r.path)}</span></div>`).join('') +
         `<div class="spMsg">${fmtN(n.total)} cereri ale ${tEsc(d.ip)} intre ${fmtEpoch(d.ts - 120)} si ${fmtEpoch(d.ts + 120)} (in selectie).</div>`)
      : '<div class="spMsg">Nicio alta cerere a acestui IP in +/-2 minute (in selectie).</div>';
  } catch (e) { if (XP.stillMine(seq)) $('#xpEvNear').innerHTML = xpErr('Eroare: ' + e.message); }
}
async function xpEvStep(dir) {
  const v = XP.cur();
  if (!v || v.type !== 'ev') return;
  const ni = v.index + dir;
  if (ni < 0) return;
  if (ni >= v.list.rows.length) {
    if (v.list.done || !v.list.more) return;
    try { await v.list.more(); } catch (e) { return; }
    if (ni >= v.list.rows.length) return;
  }
  v.index = ni;   // navigarea nu umple istoricul: aceeasi vedere, alt eveniment
  XP.render();
}

// ---------- comparatie intre doua entitati ----------
async function xpRenderCompare(v, seq) {
  const { a, b } = v;
  $('#xpTitle').innerHTML = `<span class="xpKind">Comparatie</span><span class="xpVal">${tEsc(entLabel(a.kind, a.value))} &harr; ${tEsc(entLabel(b.kind, b.value))}</span>`;
  $('#xpActions').innerHTML = `<button class="ghost" data-xact="${tEscAttr(a.kind + '::' + a.value)}">deschide A</button><button class="ghost" data-xact="${tEscAttr(b.kind + '::' + b.value)}">deschide B</button>`;
  $('#xpTabs').innerHTML = '';
  const body = $('#xpBody');
  body.innerHTML = xpBusy('Se calculeaza ambele entitati in selectia curenta...');
  try {
    const [A, B] = await Promise.all([xpExploreData(a.kind, a.value), xpExploreData(b.kind, b.value)]);
    if (!XP.stillMine(seq)) return;
    const r = (l, x, y) => `<tr><td>${l}</td><td class="num">${x}</td><td class="num">${y}</td></tr>`;
    const lst = (d, f) => (d || []).slice(0, 6).map(f).join('<br>') || '-';
    const wp = (d, k) => fmtN((d.wordpress || {})[k] || 0);
    body.innerHTML = `<div class="spMsg">Ambele calculate pe aceeasi selectie: ${tEsc(gfDescribe())}.</div><table class="cmpTbl"><thead><tr><th></th><th>A: ${tEsc(KIND_LABEL[a.kind])} ${tEsc(entLabel(a.kind, a.value))}</th><th>B: ${tEsc(KIND_LABEL[b.kind])} ${tEsc(entLabel(b.kind, b.value))}</th></tr></thead><tbody>` +
      r('Cereri', fmtN(A.requests), fmtN(B.requests)) + r('% din selectie', xpPct(A.requests, A.selection_requests), xpPct(B.requests, B.selection_requests)) +
      r('IP-uri unice', fmtN(A.unique_ips), fmtN(B.unique_ips)) + r('URL-uri distincte', fmtN(A.unique_paths), fmtN(B.unique_paths)) +
      r('Sesiuni estimate', fmtN(A.sessions_est), fmtN(B.sessions_est)) + r('Cereri / minut', A.req_per_min, B.req_per_min) +
      r('Erori 4xx', fmtN(A.err_4xx), fmtN(B.err_4xx)) + r('Erori 5xx', fmtN(A.err_5xx), fmtN(B.err_5xx)) +
      r('wp-login POST', wp(A, 'wp_login_post'), wp(B, 'wp_login_post')) + r('xmlrpc.php', wp(A, 'xmlrpc'), wp(B, 'xmlrpc')) +
      r('Prima / ultima', fmtEpoch(A.ts_min) + '<br>' + fmtEpoch(A.ts_max), fmtEpoch(B.ts_min) + '<br>' + fmtEpoch(B.ts_max)) +
      r('Top endpoint-uri', lst(A.top_paths, x => tEsc(x.path) + ' ' + fmtN(x.n)), lst(B.top_paths, x => tEsc(x.path) + ' ' + fmtN(x.n))) +
      r('Top IP-uri', lst(A.top_ips, x => tEsc(x.ip) + ' ' + fmtN(x.n)), lst(B.top_ips, x => tEsc(x.ip) + ' ' + fmtN(x.n))) +
      r('Coduri', lst(A.statuses, x => x.status + ': ' + fmtN(x.n)), lst(B.statuses, x => x.status + ': ' + fmtN(x.n))) +
      r('Alerte CRITICAL/HIGH', fmtN((A.alerts || []).reduce((s, x) => s + x.hits, 0)), fmtN((B.alerts || []).reduce((s, x) => s + x.hits, 0))) +
      '</tbody></table>';
  } catch (e) { if (XP.stillMine(seq)) body.innerHTML = xpErr('Eroare: ' + e.message); }
}

// ==========================================================================
// CRONOLOGIA DE SECURITATE (card in Triaj + vedere in panoul de explorare)
// ==========================================================================
const SEC = { seq: 0, minSev: 'HIGH', gap: 600 };
function secControlsHtml(o) {
  return `<div class="secCtl"><label>Severitate minima <select data-sec="sev"><option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option></select></label>` +
    `<label>Grupeaza daca pauza &le; <select data-sec="gap"><option value="120">2 min</option><option value="600">10 min</option><option value="1800">30 min</option><option value="3600">1 h</option></select></label>` +
    `<span class="xpHint">acelasi IP + aceeasi actiune = un grup · click pe grup: dovezile · &#9201; = perioada grupului</span></div>`;
}
async function secRender(box, o) {
  if (!box) return;
  ++SEC.seq;
  // secventa PER container: o randare mai veche a aceluiasi card (ex. intrarea
  // in modul + schimbarea perioadei imediat dupa) nu mai scrie peste cea noua
  // si nu mai incearca sa refoloseasca acelasi canvas
  const mine = box._secSeq = (box._secSeq || 0) + 1;
  const ownerOk = () => box._secSeq === mine && (o.owner === 'xp' ? XP.stillMine(o.seq) : document.body.contains(box));
  box.innerHTML = (o.compact ? '' : secControlsHtml(o)) + (o.compact ? '' : '<div class="xpChartWrap sm"><canvas></canvas></div>') + `<div class="secList">${xpBusy('Se grupeaza evenimentele...')}</div>`;
  box.querySelectorAll('[data-sec]').forEach(s => {
    s.value = s.dataset.sec === 'sev' ? SEC.minSev : String(SEC.gap);
    s.onchange = () => { if (s.dataset.sec === 'sev') SEC.minSev = s.value; else SEC.gap = +s.value; secRender(box, o); };
  });
  const p = new URLSearchParams({ min_severity: o.compact ? 'MEDIUM' : SEC.minSev, gap: SEC.gap, limit: 300, kind: o.kind || 'sel', value: o.value || '' });
  try {
    const reqs = [xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/security_timeline?${p}`))];
    if (!o.compact) reqs.push(xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?kind=sel&value=`)));
    const [d, tl] = await Promise.all(reqs);
    if (!ownerOk()) return;
    if (!o.compact && tl && tl.buckets.length) {
      const c = xpRangeChart(box.querySelector('canvas'), xpFillBuckets(tl), tl.bucket_seconds, 'sev', xpPickRange);
      if (o.owner === 'xp') XP.charts.push(c); else { if (SEC.chart) try { SEC.chart.destroy(); } catch (e) {} SEC.chart = c; }
    }
    const sev = d.by_severity || {};
    const sum = `${fmtN(d.total_events)} evenimente in ${fmtN(d.total_groups)} grupuri` +
      ['CRITICAL', 'HIGH', 'MEDIUM'].filter(k => sev[k]).map(k => ` · <span class="tag ${k}">${k}</span> ${fmtN(sev[k])}`).join('') +
      (d.groups.length < d.total_groups ? ` · afisate cele mai recente ${d.groups.length}` : '') + ` · ${d.elapsed_ms} ms`;
    const list = box.querySelector('.secList');
    if (!d.groups.length) { list.innerHTML = `<div class="xpEmpty">Niciun eveniment de securitate (prag ${tEsc(o.compact ? 'MEDIUM' : SEC.minSev)}) in selectia curenta: ${tEsc(d.selection_label)}.</div>`; return; }
    list.innerHTML = `<div class="spMsg">${sum}</div><div class="secRows">` + d.groups.map((g, i) => {
      const dur = g.last_ts - g.first_ts;
      const stc = Object.entries(g.statuses).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, n]) => `${k}:${fmtN(n)}`).join(' ');
      return `<div class="secRow sev-${tEscAttr(g.severity)}" data-gi="${i}" tabindex="0" data-ek="alert" data-ev="${tEscAttr(g.ip + '|' + g.action_type)}">` +
        `<div class="secT">${fmtEpoch(g.first_ts)}${dur ? `<br><span class="xpSub">+${dur >= 3600 ? (dur / 3600).toFixed(1) + ' h' : Math.round(dur / 60) + ' min'}</span>` : ''}</div>` +
        `<div class="secM"><span class="tag ${tEscAttr(g.severity)}">${tEsc(g.severity)}</span> <b>${tEsc(g.label || g.action_type)}</b> <span class="xpSub">&times;${fmtN(g.n)}</span>` +
        `<div class="xpSub">${tEsc(g.ip)} · ${tEsc(g.country || '??')} · ${tEsc(g.sample_path)}${g.paths > 1 ? ` (+${g.paths - 1} URL)` : ''} · ${tEsc(stc)}</div></div>` +
        `<div class="secB"><button class="spBtnMini" data-secr="${i}" title="Seteaza perioada globala la intervalul acestui grup">&#9201;</button><button class="spBtnMini" data-secc="${i}" title="Corelare: perioada ±10 min in jurul grupului (toate sursele)">±10m</button></div></div>`;
    }).join('') + '</div>';
    list.onclick = (e) => {
      const r = e.target.closest('[data-secr]'), c = e.target.closest('[data-secc]');
      if (r) { e.stopPropagation(); const g = d.groups[+r.dataset.secr]; triageSetRange(g.first_ts - 30, g.last_ts + 30); return; }
      if (c) { e.stopPropagation(); const g = d.groups[+c.dataset.secc]; triageSetRange(g.first_ts - 600, g.last_ts + 600); XP.openSecurity(); return; }
      const row = e.target.closest('[data-gi]');
      if (row) XP.open('alert', d.groups[+row.dataset.gi].ip + '|' + d.groups[+row.dataset.gi].action_type, 'raw');
    };
  } catch (e) { if (ownerOk()) box.querySelector('.secList').innerHTML = xpErr('Eroare: ' + e.message); }
}
function xpRenderSecurityView(v, seq) {
  $('#xpTitle').innerHTML = `<span class="xpKind">Cronologie de securitate</span><span class="xpVal">${tEsc(gfDescribe())}</span>`;
  $('#xpActions').innerHTML = `<button class="ghost" data-xact="sel::">&#128269; explorare selectie</button>`;
  $('#xpTabs').innerHTML = '';
  $('#xpBody').innerHTML = '<div id="xpSecFull"></div>';
  secRender($('#xpSecFull'), { owner: 'xp', seq });
}
function secCardRefresh() { if ($('#secCardBody') && TRIAGE.ready) secRender($('#secCardBody'), { owner: 'card' }); }

// ==========================================================================
// SPATIUL DE INVESTIGATIE -- salvat DOAR in acest browser (localStorage),
// pe fisier (amprenta continutului). Nu exista persistenta pe server:
// exporta (Markdown / JSON) ca sa-l pastrezi sau sa-l partajezi.
// ==========================================================================
const WS = {
  data: null, key: null,
  storageOk() { try { localStorage.setItem('__t', '1'); localStorage.removeItem('__t'); return true; } catch (e) { return false; } },
  bind() {
    this.key = 'logscan.ws.' + (TRIAGE.contentSha || ((TRIAGE.filename || DATASET_ID) + ':' + (TRIAGE.boundsFrom || '')));
    let d = null;
    try { d = JSON.parse(localStorage.getItem(this.key) || 'null'); } catch (e) { d = null; }
    this.data = d && Array.isArray(d.items) ? d : { items: [], notes: '', conclusions: '', created: new Date().toISOString() };
    // v52: nu pastram linii brute in localStorage (pot contine date sensibile).
    let changed = false;
    this.data.items.forEach(it => { if ('raw' in it || 'raw_line' in it) { delete it.raw; delete it.raw_line; changed = true; } });
    if (changed) this.save();
    this.badge();
  },
  save() {
    if (!this.data) return;
    this.data.updated = new Date().toISOString();
    try { localStorage.setItem(this.key, JSON.stringify(this.data)); this.saveErr = null; }
    catch (e) { this.saveErr = e.message; }
    this.badge();
  },
  badge() { const b = $('#wsBadge'); if (b) b.textContent = this.data && this.data.items.length ? String(this.data.items.length) : ''; },
  snap() { return { filters: JSON.parse(JSON.stringify(TRIAGE.filters)), a: TRIAGE.tsFrom, b: TRIAGE.tsTo, label: gfDescribe() }; },
  add(item) {
    if (!this.data) this.bind();
    item.id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    item.added = new Date().toISOString();
    item.ctx = this.snap();
    item.note = item.note || '';
    this.data.items.push(item);
    this.save();
    toast('Adaugat la investigatie' + (this.saveErr ? ' (ATENTIE: nu s-a putut salva in browser -- ' + this.saveErr + ')' : ''));
    if (CURRENT_PAGE === 'investigations') WS.render();
  },
  addEntity(kind, value) { this.add({ type: 'entity', kind, value: String(value ?? ''), label: `${KIND_LABEL[kind] || kind}: ${entLabel(kind, value)}` }); },
  addEvent(ev) { this.add({ type: 'event', id_ev: ev.id, label: `${fmtTimeShort(ev.ts_str)} ${ev.ip} ${ev.method} ${ev.path} -> ${ev.http_status}` }); },
  addSelection() { this.add({ type: 'selection', label: 'Selectie: ' + gfDescribe() }); },
  restore(it) {
    const c = it.ctx;
    if (!c) return;
    TRIAGE.filters = Object.assign(emptyTriageFilters(), JSON.parse(JSON.stringify(c.filters)));
    $('#triageIpFilter').value = TRIAGE.filters.ip || ''; $('#triagePathFilter').value = TRIAGE.filters.pathContains || '';
    if (c.a != null) triageSetRange(c.a, c.b, true);
    triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll();
  },
  open(it) {
    this.restore(it);
    if (it.type === 'entity') XP.open(it.kind, it.value);
    else if (it.type === 'event') XP.openEvent({ rows: [{ id: it.id_ev, ts_str: '', ip: '' }], total: 1, done: true, label: 'investigatie' }, 0);
    else XP.open('sel', '');
  },
  md() {
    const d = this.data;
    const L = [`# Investigatie logscan -- ${TRIAGE.filename || ''}`, '', `Generat: ${new Date().toLocaleString('ro-RO')}`, '', '## Elemente', ''];
    d.items.forEach(it => {
      L.push(`- **${it.label}** _(adaugat ${new Date(it.added).toLocaleString('ro-RO')}; selectie: ${it.ctx ? it.ctx.label : '-'})_`);
      if (it.note) L.push(`  - Nota: ${it.note}`);
      // v52: liniile brute nu sunt stocate in investigatii; exportul Markdown
      // ramane fara ele (se pot revedea in app cat timp datasetul e incarcat).
    });
    L.push('', '## Notite', '', d.notes || '-', '', '## Concluzii', '', d.conclusions || '-', '');
    return L.join('\n');
  },
  async render(seq) {
    if (!$('#invBody')) return;
    if (!this.data) this.bind();
    const d = this.data;
    $('#invTitle').innerHTML = `<span class="xpKind">Investigatie</span><span class="xpVal">${tEsc(TRIAGE.filename || '')}</span>`;
    $('#invActions').innerHTML = `<button class="ghost" id="wsAddSel">&#9733; salveaza selectia curenta</button><button class="ghost" id="wsMd">&#11015; Markdown</button><button class="ghost" id="wsJson">&#11015; JSON</button>` +
      `<label class="ghost wsImp">&#11014; importa<input type="file" id="wsImport" accept=".json" hidden></label><button class="ghost" id="wsClear">goleste</button>`;
    const ok = this.storageOk();
    const icon = { entity: '&#128269;', event: '&#128196;', selection: '&#9881;' };
    $('#invBody').innerHTML = `<div class="spMsg${ok ? '' : ' err'}">${ok ? 'Salvat automat DOAR in acest browser, pentru acest fisier (nu pe server, nu se sincronizeaza intre calculatoare). Exporta ca sa-l pastrezi sau sa-l trimiti.' : 'Browserul nu permite salvarea locala (mod privat / stocare blocata): investigatia exista doar cat e deschisa pagina -- exporta inainte sa inchizi.'}${this.saveErr ? ' Ultima salvare a esuat: ' + tEsc(this.saveErr) : ''}</div>` +
      `<div class="ipProfSec">Perioada investigata</div><div class="spMsg">Selectia curenta: <b>${tEsc(gfDescribe())}</b>. Fiecare element retine selectia in care a fost adaugat -- "deschide" o restaureaza.</div>` +
      `<div class="ipProfSec">Elemente (${d.items.length})</div>` +
      (d.items.length ? '<div class="wsItems">' + d.items.map((it, i) => `<div class="wsItem" data-wi="${i}"><div class="wsTop"><span>${icon[it.type] || ''}</span><b>${tEsc(it.label)}</b><span class="spacer"></span>` +
        `<button class="spBtnMini" data-wo="${i}">deschide</button><button class="spBtnMini" data-wd="${i}" title="sterge">&times;</button></div>` +
        `<div class="xpSub">adaugat ${new Date(it.added).toLocaleString('ro-RO')} · selectie: ${tEsc(it.ctx ? it.ctx.label : '-')}</div>` +
        (it.raw ? `<pre class="evRaw">${tEsc(it.raw)}</pre>` : '') +
        `<textarea class="wsNote" data-wn="${i}" placeholder="nota pentru acest element...">${tEsc(it.note || '')}</textarea></div>`).join('') + '</div>'
        : '<div class="xpEmpty">Nimic adaugat inca. Foloseste "&#9733; Investigatie" din panoul de explorare, din meniul contextual (click dreapta) sau din detaliul unei cereri.</div>') +
      `<div class="ipProfSec">Notite</div><textarea id="wsNotes" class="wsBig" placeholder="ce s-a verificat, ipoteze, pasi urmatori...">${tEsc(d.notes || '')}</textarea>` +
      `<div class="ipProfSec">Concluzii</div><textarea id="wsConc" class="wsBig" placeholder="concluzia investigatiei (ce s-a intamplat, impact, masuri)...">${tEsc(d.conclusions || '')}</textarea>`;
    const saveSoon = debounce(() => this.save(), 400);
    $('#wsNotes').oninput = () => { d.notes = $('#wsNotes').value; saveSoon(); };
    $('#wsConc').oninput = () => { d.conclusions = $('#wsConc').value; saveSoon(); };
    $('#invBody').querySelectorAll('[data-wn]').forEach(t => t.oninput = () => { d.items[+t.dataset.wn].note = t.value; saveSoon(); });
    $('#invBody').querySelectorAll('[data-wo]').forEach(b => b.onclick = () => this.open(d.items[+b.dataset.wo]));
    $('#invBody').querySelectorAll('[data-wd]').forEach(b => b.onclick = () => { d.items.splice(+b.dataset.wd, 1); this.save(); WS.render(); });
    $('#wsAddSel').onclick = () => this.addSelection();
    $('#wsMd').onclick = () => downloadFile('investigatie-logscan.md', this.md(), 'text/markdown;charset=utf-8');
    $('#wsJson').onclick = () => downloadFile('investigatie-logscan.json', JSON.stringify(d, null, 2), 'application/json');
    $('#wsClear').onclick = () => { if (confirm('Stergi toate elementele, notitele si concluziile acestei investigatii?')) { this.data = { items: [], notes: '', conclusions: '', created: new Date().toISOString() }; this.save(); WS.render(); } };
    $('#wsImport').onchange = async () => {
      const f = $('#wsImport').files[0]; if (!f) return;
      try { const j = JSON.parse(await f.text()); if (!Array.isArray(j.items)) throw new Error('fisier fara "items"'); this.data = j; this.save(); WS.render(); toast('Investigatie importata'); }
      catch (e) { showError('Import esuat: ' + e.message); }
    };
  },
};

// ==========================================================================
// PRESETURI, VIZUALIZARI SALVATE, PALETA DE COMENZI, SCURTATURI
// ==========================================================================
function presetApply(fn, label) {
  TRIAGE.filters = emptyTriageFilters();
  $('#triageIpFilter').value = ''; $('#triagePathFilter').value = '';
  if (TRIAGE.boundsFrom != null) triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo, true);
  fn(TRIAGE.filters);
  $('#triagePathFilter').value = TRIAGE.filters.pathContains || '';
  $('#triageIpFilter').value = TRIAGE.filters.ip || '';
  triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll();
  toast('Preset: ' + label);
}
const PRESETS = [
  { label: 'Ultima ora din log', run: () => { triageSetRange(TRIAGE.boundsTo - 3599, TRIAGE.boundsTo); toast('Perioada: ultima ora din log'); } },
  { label: 'Ultimele 24 h din log', run: () => { triageSetRange(TRIAGE.boundsTo - 86399, TRIAGE.boundsTo); toast('Perioada: ultimele 24 h din log'); } },
  { label: 'Brute force wp-login (POST)', run: () => presetApply(f => { f.wpCat = 'wp_login_post'; }, 'POST wp-login.php') },
  { label: 'XML-RPC', run: () => presetApply(f => { f.wpCat = 'xmlrpc'; }, 'xmlrpc.php') },
  { label: 'Activitate wp-admin', run: () => presetApply(f => { f.wpCat = 'wp_admin'; }, '/wp-admin/') },
  { label: 'REST API (wp-json)', run: () => presetApply(f => { f.wpCat = 'wp_json'; }, '/wp-json/') },
  { label: 'Erori server 5xx', run: () => presetApply(f => { f.statusClass = ['5xx']; }, '5xx') },
  { label: 'Toate erorile client 4xx', run: () => presetApply(f => { f.statusClass = ['4xx']; }, '4xx') },
  { label: '403 / 429 (blocate / limitate)', run: () => presetApply(f => { f.statuses = ['403', '429']; }, '403 + 429') },
  { label: 'Doar CRITICAL / HIGH', run: () => presetApply(f => { f.severities = ['CRITICAL', 'HIGH']; }, 'CRITICAL + HIGH') },
  { label: 'Atac confirmat (CRITICAL/HIGH servit 2xx)', run: () => presetApply(f => { f.severities = ['CRITICAL', 'HIGH']; f.statusClass = ['2xx']; }, 'atac confirmat (CRITICAL/HIGH + 2xx)') },
  { label: 'Trafic non-RO', run: () => presetApply(f => { f.countries = ['__NON_RO__']; }, 'non-RO') },
  { label: 'Tara nedeterminata', run: () => presetApply(f => { f.countries = ['??']; }, 'tara nedeterminata') },
  { label: 'Fara boti declarati (UA cu bot/crawl/spider)', hint: 'aproximativ', run: () => presetApply(f => { f.x.uas = ['bot', 'crawl', 'spider']; }, 'fara boti declarati') },
  { label: 'User-Agent personalizat (contine)...', hint: 'scrii tu UA', run: () => { const v = prompt('User-Agent (sau o parte din el):', ''); if (v) presetApply(f => { f.uaContains = v; }, 'UA contine "' + v + '"'); } },
  { label: 'Exclude un User-Agent...', hint: 'scrii tu UA', run: () => { const v = prompt('Exclude cererile al caror User-Agent contine:', ''); if (v) presetApply(f => { f.x.uas = [v]; }, 'fara UA "' + v + '"'); } },
  { label: 'Doar facebookexternalhit (Meta)', run: () => presetApply(f => { f.uaContains = 'facebookexternalhit'; }, 'facebookexternalhit') },
  { label: 'Doar Googlebot', run: () => presetApply(f => { f.uaContains = 'googlebot'; }, 'Googlebot') },
  { label: 'Fara Meta / Google / Bing', run: () => presetApply(f => { f.x.uas = ['facebookexternalhit', 'meta-externalagent', 'googlebot', 'bingbot']; }, 'fara Meta/Google/Bing') },
  { label: 'Workplace: filtre avansate pe orice combinatie...', hint: 'modul', run: () => showPage('workplace') },
];
const VIEWS = {
  list() { try { return JSON.parse(localStorage.getItem('logscan.views') || '[]'); } catch (e) { return []; } },
  saveAll(v) { try { localStorage.setItem('logscan.views', JSON.stringify(v)); return true; } catch (e) { showError('Browserul nu permite salvarea locala: ' + e.message); return false; } },
  saveCurrent() {
    const name = prompt('Nume pentru vizualizarea curenta (filtrele; perioada se salveaza relativ la sfarsitul logului):', gfDescribe().slice(0, 60));
    if (!name) return;
    const v = this.list().filter(x => x.name !== name);
    v.push({ name, filters: JSON.parse(JSON.stringify(TRIAGE.filters)), rel: gfTimeNarrowed() ? [TRIAGE.boundsTo - TRIAGE.tsFrom, TRIAGE.boundsTo - TRIAGE.tsTo] : null });
    if (this.saveAll(v)) toast('Vizualizare salvata in acest browser: ' + name);
  },
  apply(v) {
    TRIAGE.filters = Object.assign(emptyTriageFilters(), JSON.parse(JSON.stringify(v.filters)));
    $('#triageIpFilter').value = TRIAGE.filters.ip || ''; $('#triagePathFilter').value = TRIAGE.filters.pathContains || '';
    if (v.rel) triageSetRange(TRIAGE.boundsTo - v.rel[0], TRIAGE.boundsTo - v.rel[1], true);
    else triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo, true);
    triageRenderMultiSelects(); triageRenderActiveChips(); triageReloadAll();
    toast('Vizualizare: ' + v.name);
  },
  remove(name) { this.saveAll(this.list().filter(x => x.name !== name)); },
};
function openPresetsMenu(btn) {
  const r = btn.getBoundingClientRect();
  const views = VIEWS.list();
  const items = PRESETS.map(p => ({ icon: '&#9881;', label: p.label, hint: p.hint, run: p.run }));
  items.push('-', { icon: '&#128190;', label: 'Salveaza vizualizarea curenta...', run: () => VIEWS.saveCurrent() });
  views.forEach(v => items.push({ icon: '&#9733;', label: v.name, hint: 'salvata', run: () => VIEWS.apply(v) }));
  if (views.length) items.push({ icon: '&#128465;', label: 'Sterge o vizualizare salvata...', run: () => { const n = prompt('Numele vizualizarii de sters:\n' + views.map(v => '- ' + v.name).join('\n')); if (n) { VIEWS.remove(n); toast('Stearsa: ' + n); } } });
  ctxShow(r.left, r.bottom + 4, 'Preseturi de investigatie', items);
}

const CMD = { items: [], sel: 0 };
function cmdNorm(s) { return String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, ''); }
function cmdBuild(q) {
  const out = [];
  const t = q.trim();
  if (t) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(t)) out.push({ label: `Deschide IP ${t}`, hint: 'explorer', run: () => XP.open('ip', t) }, { label: `Filtreaza pe IP ${t}`, run: () => gfAddEntity('ip', t) });
    if (t.startsWith('/')) out.push({ label: `Istoricul endpoint-ului ${t}`, hint: 'explorer', run: () => XP.open('path', t) }, { label: `URL-uri care contin ${t}`, hint: 'explorer', run: () => XP.open('prefix', t) });
    if (/^[a-z]{2}$/i.test(t)) out.push({ label: `Tara ${ccLabel(t.toUpperCase())}`, hint: 'explorer', run: () => XP.open('country', t.toUpperCase()) });
    if (/^\d{3}$/.test(t)) out.push({ label: `Cod HTTP ${t}`, hint: 'explorer', run: () => XP.open('status', t) }, { label: `Filtreaza pe codul ${t}`, run: () => gfAddEntity('status', t) });
    if (/^[1-5]xx$/i.test(t)) out.push({ label: `Clasa ${t.toLowerCase()}`, hint: 'explorer', run: () => XP.open('sclass', t.toLowerCase()) });
  }
  const pages = Object.entries(MODULES).map(([k, m]) => [k, m.title]);
  const stat = [
    { label: 'Exploreaza selectia curenta', hint: 'E', run: () => XP.open('sel', '') },
    { label: 'Cronologie de securitate', hint: 'S', run: () => XP.openSecurity() },
    { label: 'WordPress: toate rutele', hint: 'explorer', run: () => XP.open('wp', 'wp_any') },
    ...Object.keys(WP_CAT_LABEL).filter(k => k !== 'wp_any').map(k => ({ label: 'WordPress: ' + WP_CAT_LABEL[k], hint: 'explorer', run: () => XP.open('wp', k) })),
    { label: 'Erori 4xx (explorer)', run: () => XP.open('sclass', '4xx') }, { label: 'Erori 5xx (explorer)', run: () => XP.open('sclass', '5xx') },
    { label: 'Reset filtre', run: () => $('#triageResetBtn').click() },
    { label: 'Inapoi la selectia precedenta', hint: 'Alt+←', run: () => $('#gfBackBtn').click() },
    { label: 'Exporta selectia (CSV)', run: () => xpExport('sel', '', 'csv') }, { label: 'Exporta selectia (.log original)', run: () => xpExport('sel', '', 'log') },
    { label: 'Raw Logs: cererile selectiei', hint: 'R', run: () => showPage('raw') },
    { label: 'Scurtaturi de tastatura', hint: '?', run: () => shortcutsHelp() },
    { label: 'Salveaza vizualizarea curenta...', run: () => VIEWS.saveCurrent() },
    ...VIEWS.list().map(v => ({ label: 'Vizualizare salvata: ' + v.name, run: () => VIEWS.apply(v) })),
    ...PRESETS.map(p => ({ label: 'Preset: ' + p.label, run: p.run })),
    ...pages.map(([k, l]) => ({ label: 'Mergi la: ' + l, run: () => showPage(k) })),
  ];
  const nq = cmdNorm(t);
  return out.concat(nq ? stat.filter(c => nq.split(/\s+/).every(w => cmdNorm(c.label).includes(w))) : stat).slice(0, 40);
}
function cmdOpen() {
  if (!DATASET_ID || !TRIAGE.ready) return;
  $('#cmdk').classList.add('open');
  $('#cmdkIn').value = ''; cmdRender(); $('#cmdkIn').focus();
}
function cmdClose() { $('#cmdk').classList.remove('open'); }
function cmdRender() {
  CMD.items = cmdBuild($('#cmdkIn').value); CMD.sel = 0;
  $('#cmdkList').innerHTML = CMD.items.length ? CMD.items.map((c, i) => `<div class="cmdItem${i === 0 ? ' sel' : ''}" data-ci="${i}">${tEsc(c.label)}${c.hint ? `<span class="ctxHint">${tEsc(c.hint)}</span>` : ''}</div>`).join('')
    : '<div class="cmdEmpty">Nicio comanda. Scrie un IP, un URL (/...), un cod de tara (RO), un cod HTTP (404) sau o actiune.</div>';
}
function cmdRun(i) { const c = CMD.items[i]; if (!c) return; cmdClose(); c.run(); }
$('#cmdkIn').addEventListener('input', cmdRender);
$('#cmdkIn').addEventListener('keydown', (e) => {
  const n = CMD.items.length;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault(); if (!n) return;
    CMD.sel = (CMD.sel + (e.key === 'ArrowDown' ? 1 : -1) + n) % n;
    $('#cmdkList').querySelectorAll('.cmdItem').forEach((el, i) => el.classList.toggle('sel', i === CMD.sel));
    const s = $('#cmdkList').querySelector('.cmdItem.sel'); if (s) s.scrollIntoView({ block: 'nearest' });
  } else if (e.key === 'Enter') { e.preventDefault(); cmdRun(CMD.sel); }
  else if (e.key === 'Escape') { e.preventDefault(); cmdClose(); }
});
$('#cmdkList').addEventListener('click', (e) => { const it = e.target.closest('[data-ci]'); if (it) cmdRun(+it.dataset.ci); });
$('#cmdk').addEventListener('click', (e) => { if (e.target.id === 'cmdk') cmdClose(); });

function triageMoveSel(delta) {
  if (!TRIAGE.rows.length || CURRENT_PAGE !== 'raw' || TRIAGE.rawView === 'lines') return;
  let idx = TRIAGE.rows.findIndex(ev => ev.id === TRIAGE.selId);
  if (idx < 0) idx = delta > 0 ? -1 : TRIAGE.rows.length;
  idx = Math.max(0, Math.min(TRIAGE.rows.length - 1, idx + delta));
  TRIAGE.selId = TRIAGE.rows[idx].id;
  const vp = $('#triageViewport');
  if (vp) {
    const top = idx * ROW_H;
    if (top < vp.scrollTop) vp.scrollTop = top;
    else if (top + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = top + ROW_H - vp.clientHeight;
  }
  triageRenderVisibleRows();
}
function triageToggleSelId() {
  if (TRIAGE.selId == null) return;
  const idx = TRIAGE.rows.findIndex(ev => ev.id === TRIAGE.selId);
  if (idx < 0) return;
  rawToggleSelectedById(TRIAGE.selId);
  TRIAGE.lastSelIdx = idx;
  rawUpdateRowSelectionVisuals();
  rawSyncBulk();
}
const SHORTCUTS = [
  ['Ctrl+K  sau  /', 'paleta de comenzi (cauta IP, URL, tara, cod, actiune)'], ['?', 'aceasta lista'],
  ['E', 'exploreaza selectia curenta'], ['S', 'cronologia de securitate'],
  ['R / O', 'Raw Logs / Overview'], ['Alt+←  /  Alt+→', 'inapoi / inainte (in panoul de explorare, altfel selectia precedenta)'],
  ['[  ]  sau  k  j', 'cererea anterioara / urmatoare (in detaliul unei cereri)'], ['Esc', 'inchide meniul / paleta / panoul de explorare'],
  ['↑ / ↓', 'randul anterior / urmator in Raw Logs'], ['Enter / Space', 'deschide / selecteaza randul curent din Raw Logs'],
  ['Click dreapta', 'actiuni pe orice IP, URL, tara, cod, alerta sau rand RAW'],
];
function shortcutsHelp() {
  ctxShow(window.innerWidth / 2 - 220, 90, 'Scurtaturi de tastatura', SHORTCUTS.map(([k, d]) => ({ label: d, hint: k, run: () => {} })));
}
document.addEventListener('keydown', (e) => {
  const typing = e.target.closest && e.target.closest('input,textarea,select,[contenteditable]');
  if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); cmdOpen(); return; }
  if (e.key === 'Escape') {
    if ($('#cmdk').classList.contains('open')) { cmdClose(); return; }
    const colsMenu = $('#rawColsMenu');
    if (colsMenu && colsMenu.open) { colsMenu.open = false; return; }
    if ($('#ctxMenu').classList.contains('open')) { ctxClose(); return; }
    if (XP.isOpen() && !modalIsOpen() && !$('#auditDrawer').classList.contains('open')) { XP.close(); return; }
    return;
  }
  if (e.altKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) {
    e.preventDefault();
    if (XP.isOpen()) { e.key === 'ArrowLeft' ? XP.back() : XP.fwd(); }
    else if (e.key === 'ArrowLeft') $('#gfBackBtn').click();
    return;
  }
  if (typing || e.ctrlKey || e.metaKey || e.altKey || !DATASET_ID || !TRIAGE.ready) return;
  const v = XP.isOpen() ? XP.cur() : null;
  if (v && v.type === 'ev' && (e.key === '[' || e.key === 'k')) { e.preventDefault(); xpEvStep(-1); return; }
  if (v && v.type === 'ev' && (e.key === ']' || e.key === 'j')) { e.preventDefault(); xpEvStep(1); return; }
  const rawNav = CURRENT_PAGE === 'raw' && !v && !modalIsOpen() && TRIAGE.rawView !== 'lines'
    && !$('#auditDrawer').classList.contains('open') && !e.target.closest('button,a,summary');
  if (rawNav && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
    e.preventDefault(); triageMoveSel(e.key === 'ArrowDown' ? 1 : -1); return;
  }
  if (rawNav && e.key === 'Enter' && TRIAGE.selId != null) {
    const ev = TRIAGE.rows.find(r => r.id === TRIAGE.selId);
    if (ev) { e.preventDefault(); openEventDetail(ev); return; }
  }
  if (rawNav && e.key === ' ' && TRIAGE.selId != null) {
    e.preventDefault(); triageToggleSelId(); return;
  }
  if (e.key === '/') { e.preventDefault(); cmdOpen(); }
  else if (e.key === '?') { e.preventDefault(); shortcutsHelp(); }
  else if (e.key === 'e' || e.key === 'E') XP.open('sel', '');
  else if (e.key === 's' || e.key === 'S') XP.openSecurity();
  else if (e.key === 'r' || e.key === 'R') showPage('raw');
  else if (e.key === 'o' || e.key === 'O') showPage('overview');
});

// ---------- bara de unelte a selectiei ----------
$('#selTools').addEventListener('click', (e) => {
  const b = e.target.closest('[data-st]'); if (!b) return;
  const a = b.dataset.st;
  if (a === 'explore') XP.open('sel', '');
  else if (a === 'sec') XP.openSecurity();
  else if (a === 'presets') openPresetsMenu(b);
  else if (a === 'cmd') cmdOpen();
  else if (a === 'export') {
    const r = b.getBoundingClientRect();
    const ov = GF.overview, loading = !ov || GF.overviewSeq !== GF.overviewDoneSeq;
    if (loading) { toast('Selectia se recalculeaza -- exportul devine disponibil cand cifrele sunt actualizate.'); return; }
    const n = fmtNum(ov.requests || 0);
    const sumar = (t, lbl) => ({ icon: '&#11015;', label: `Sumar: ${lbl} (CSV)`, run: () => window.open(redactUrl(gfUrl(`/api/dataset/${DATASET_ID}/export.csv?day=ALL&type=${t}`)), '_blank') });
    ctxShow(r.left, r.bottom + 4, `Exporta selectia curenta (${n} cereri)`, [
      { icon: '&#11015;', label: `Cereri brute: liniile originale (.log) -- toate cele ${n}`, run: () => xpExport('sel', '', 'log') },
      { icon: '&#11015;', label: `Cereri: CSV cu campurile indexului -- toate cele ${n}`, run: () => xpExport('sel', '', 'csv') },
      { icon: '&#11015;', label: 'Sumar: analiza detaliata a selectiei (JSON)', run: () => window.open(redactUrl(gfUrl(`/api/dataset/${DATASET_ID}/export.json?day=ALL`)), '_blank') },
      sumar('findings', 'findings'), sumar('anomalies', 'anomalii'), sumar('ips', 'IP-uri'), sumar('crawlers', 'crawlere'), sumar('paths', 'path-uri'),
    ]);
  }
});

// ---------- inlocuiri ale functiilor v44: profil IP / detaliu cerere -> panoul de explorare ----------
function openIpProfile(ip) { XP.open('ip', ip); }
function triageMoreForList() {
  return new Promise(async (res) => {
    const before = TRIAGE.rows.length;
    if (!TRIAGE.allLoaded) await triageLoadMoreEvents(false);
    res(TRIAGE.rows.length > before);
  });
}
function openEventDetail(ev) {
  const list = { get rows() { return TRIAGE.rows; }, get total() { return TRIAGE.total; }, get done() { return TRIAGE.allLoaded; }, label: 'Raw Logs', more: triageMoreForList };
  XP.openEvent(list, TRIAGE.rows.indexOf(ev));
}
// celulele tabelului RAW: meniul complet (explorer + filtreaza + exclude + ...)
function showCellPopover(anchorEl, field, value, ev) {
  const r = anchorEl.getBoundingClientRect();
  if (field === 'ts_str') {
    ctxShow(r.left, r.bottom + 2, value, [
      { icon: '&#9201;', label: 'Restrange perioada la minutul acestei cereri', run: () => triageSetSingleFilter('ts_minute', anchorEl.dataset.ts) },
      { icon: '&#9201;', label: 'Context: acest IP ±5 min', run: () => ev && xpContextAround(ev) },
      { icon: '&#128196;', label: 'Detaliul cererii', run: () => ev && openEventDetail(ev) },
      { icon: '&#10697;', label: 'Copiaza', run: () => copyToClipboard(value || '') },
    ]);
    return;
  }
  const kind = { ip: 'ip', country: 'country', path: 'path', http_status: 'status', ua: 'ua', method: 'method', action: 'action' }[field];
  if (!kind) { copyToClipboard(value || ''); return; }
  const extra = ev ? ['-', { icon: '&#128196;', label: 'Detaliul acestei cereri', run: () => openEventDetail(ev) }] : [];
  openEntityMenu(r.left, r.bottom + 2, kind, kind === 'path' ? String(value).split('?')[0] : value, extra);
}

// ---------- click pe graficele din taburile detaliate -> perioada globala ----------
const _origRenderSummary = renderSummary;
renderSummary = function (s) {
  _origRenderSummary(s);
  try {
    const gran = s && s.timeline_granularity;
    const hook = (chart) => {
      if (!chart || !chart.canvas || !chart.canvas.isConnected) return;
      chart.options.onClick = (evt, els) => {
        if (!els.length || !TRIAGE.ready) return;
        const lbl = chart.data.labels[els[0].index];
        const m = /^(\d{2}\/\w{3}\/\d{4})(?: (\d{2}):(\d{2}))?$/.exec(lbl || '');
        if (!m) return;
        let a, b;
        if (!m[2]) { a = _dayHmsToEpoch(m[1], '00:00:00'); b = a + 86399; }
        else if (gran === 'hour') { a = _dayHmsToEpoch(m[1], `${m[2]}:00:00`); b = a + 3599; }
        else { a = _dayHmsToEpoch(m[1], `${m[2]}:${m[3]}:00`); b = a + 59; }
        triageSetRange(a, b);
        toast('Perioada globala: ' + lbl);
      };
      chart.options.onHover = (evt, els) => { evt.native.target.style.cursor = els.length ? 'pointer' : 'default'; };
      chart.options.interaction = { mode: 'index', intersect: false };
      chart.update('none');
    };
    hook(timelineChart); hook(errorChart);
    if (statusChart && statusChart.canvas && statusChart.canvas.isConnected) {
      statusChart.options.onClick = (evt, els) => { if (els.length) XP.open('sclass', statusChart.data.labels[els[0].index]); };
      statusChart.options.onHover = (evt, els) => { evt.native.target.style.cursor = els.length ? 'pointer' : 'default'; };
      statusChart.update('none');
    }
    document.querySelectorAll('#timelineChart, #errorChart').forEach(c => c.title = 'Click pe un punct: seteaza perioada globala (zi / ora / minut)');
    const sc = $('#statusChart'); if (sc) sc.title = 'Click pe o felie: investigheaza clasa de cod in panoul de explorare';
  } catch (e) { console.warn('hook grafice', e); }
};

// ---------- alertele din Triaj urmeaza selectia ----------
const _origLoadAlerts = triageLoadAlerts;
triageLoadAlerts = async function () {
  await _origLoadAlerts();
  const h = $('#triageAlertsCount');
  if (h && gfIsActive()) h.textContent += ' · doar in selectia curenta';
  document.querySelectorAll('#triageAlertsRow .alertCard').forEach(c => {
    if (!c.querySelector('[data-eq]')) c.insertAdjacentHTML('beforeend', `<div class="acQ">${entQuick('alert', c.dataset.alertIp + '|' + c.dataset.action)}</div>`);
  });
};

// ---------- toate componentele urmeaza selectia (deja deschise inclusiv) ----------
GF_LISTENERS.push(() => triageLoadAlerts());
GF_LISTENERS.push(() => { if (AUDIT_LAST && $('#auditDrawer').classList.contains('open')) openAuditDrawer(AUDIT_LAST[0], AUDIT_LAST[1]); });
$('#heatmapWrap') && $('#heatmapWrap').addEventListener('click', (e) => {
  const td = e.target.closest('[data-hm-day]');
  if (!td || !TRIAGE.ready) return;
  const a = _dayHmsToEpoch(td.dataset.hmDay, td.dataset.hmH + ':00:00');
  if (a == null) return;
  triageSetRange(a, a + 3599);
  toast('Perioada globala: ' + td.dataset.hmDay + ' ' + td.dataset.hmH + ':00');
});
GF_LISTENERS.push(() => XP.refresh());
GF_LISTENERS.push(() => { if (modalIsOpen()) { modalUpdateScope(); if (MODAL_REFRESH) MODAL_REFRESH(); } });
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') secCardRefresh(); else SEC.stale = true; });
GF_LISTENERS.push(() => {
  if (PATH_EXPLORER.loaded) { if (CURRENT_PAGE === 'endpoints') loadPathExplorer(); else PATH_EXPLORER.stale = true; }
  if (EXP_STATE) { if (CURRENT_PAGE === 'raw') $('#expAnalyzeBtn').click(); else EXP_STATE.stale = true; }
});
const _origShowPage = showPage;
showPage = function (page) {
  _origShowPage(page);
  if (CURRENT_PAGE === 'security' && SEC.stale) { SEC.stale = false; secCardRefresh(); }
  if (CURRENT_PAGE === 'endpoints' && PATH_EXPLORER.stale) { PATH_EXPLORER.stale = false; loadPathExplorer(); }
  if (CURRENT_PAGE === 'raw' && EXP_STATE && EXP_STATE.stale) { EXP_STATE.stale = false; $('#expAnalyzeBtn').click(); }
};
const _origAfterIndexReady = gfAfterIndexReady;
gfAfterIndexReady = async function () {
  await _origAfterIndexReady();
  WS.bind();
  secCardRefresh();
  $('#selTools').style.display = 'flex';
};


// ==========================================================================
// v46 -- MODULELE NOI (Overview, Traffic, Countries, Endpoints, HTTP Errors,
// WordPress) + panglica perioadei + bara de sus. Toate citesc DOAR din index
// (explore / timeline / security_timeline), cu selectia globala (gf) -- deci
// aceleasi cifre ca panoul de explorare si ca Raw Logs. Raspunsurile vechi
// sunt ignorate (numar de secventa per modul).
// ==========================================================================
if (window.Chart) {
  Chart.defaults.font.family = '"IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif';
  Chart.defaults.font.size = 11;
  Chart.defaults.color = '#5D6A79';
  Chart.defaults.borderColor = '#E4E8EE';
}
const MOD = { seq: {}, charts: {} };
const MON_RO = ['ian', 'feb', 'mar', 'apr', 'mai', 'iun', 'iul', 'aug', 'sep', 'oct', 'nov', 'dec'];
function fmtLong(e, withSec) {
  if (e == null) return '-';
  const d = new Date((e + TRIAGE.tzOffset) * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getUTCDate()} ${MON_RO[d.getUTCMonth()]} ${d.getUTCFullYear()}, ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}${withSec ? ':' + p(d.getUTCSeconds()) : ''}`;
}
function fmtShortTs(e) {
  const d = new Date((e + TRIAGE.tzOffset) * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getUTCDate()} ${MON_RO[d.getUTCMonth()]} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}
function fmtDur(sec) {
  if (sec == null || sec < 0) return '-';
  if (sec < 120) return sec + ' s';
  const m = Math.round(sec / 60);
  if (m < 120) return m + ' min';
  const h = Math.floor(m / 60), mm = m % 60;
  if (h < 48) return h + ' h' + (mm ? ' ' + mm + ' min' : '');
  return Math.floor(h / 24) + ' zile ' + (h % 24) + ' h';
}
function pct(n, d, digits) { return d ? (100 * n / d).toFixed(digits == null ? 1 : digits).replace('.', ',') + ' %' : '0 %'; }
function modStart(key) { MOD.seq[key] = (MOD.seq[key] || 0) + 1; return MOD.seq[key]; }
function modMine(key, seq) { return MOD.seq[key] === seq && CURRENT_PAGE === key; }
function modChart(id, make) {
  if (MOD.charts[id]) { try { MOD.charts[id].destroy(); } catch (e) {} MOD.charts[id] = null; }
  if (typeof make === 'function') { const c = make(); MOD.charts[id] = c; return c; }
  const cv = document.getElementById(id); if (cv) { const old = Chart.getChart && Chart.getChart(cv); if (old) old.destroy(); }
}
function tile(v, l, opts) {
  opts = opts || {};
  return `<button type="button" class="tile${opts.tone ? ' ' + opts.tone : ''}"${opts.go ? ` data-goto="${opts.go}"` : ''}${opts.xact ? ` data-xopenk="${tEscAttr(opts.xact)}"` : ''}>` +
    `<span class="tileV">${v}</span><span class="tileL">${l}</span>${opts.sub ? `<span class="tileS">${opts.sub}</span>` : ''}</button>`;
}
function modEmpty(msg) { return `<div class="xpEmpty">${msg}</div>`; }
function modBusy() { return xpBusy('Se calculează pentru selecția curentă...'); }
function modEmptySel(d) {
  return modEmpty(`<b>Nicio cerere în selecția curentă.</b> ${tEsc(d && d.empty_reason || '')} Lărgește perioada sau scoate un filtru; nu se revine automat la tot logul.`);
}
function selData() { return xpExploreData('sel', '', { top_n: 60 }); }

// ---------- panglica perioadei + pastila din bara de sus ----------
function ribbonRender() {
  if (!TRIAGE.ready || TRIAGE.boundsFrom == null) return;
  const narrowed = gfTimeNarrowed();
  const a = narrowed ? TRIAGE.tsFrom : TRIAGE.boundsFrom, b = narrowed ? TRIAGE.tsTo : TRIAGE.boundsTo;
  $('#gfRibPeriod').innerHTML = `${tEsc(fmtLong(a, true))} <span class="gfArrow">până la</span> ${tEsc(fmtLong(b, true))}`;
  const ov = GF.overview;
  const nf = gfFilterCount();
  const bits = [];
  if (ov) bits.push(`<b>${fmtN(ov.requests)}</b> cereri`, `<b>${fmtN(ov.unique_ips)}</b> IP-uri`);
  bits.push(`durata ${fmtDur(b - a + 1)}`);
  bits.push(narrowed ? 'perioadă restrânsă' : 'tot logul');
  if (nf) bits.push(`<b>${nf}</b> ${nf === 1 ? 'filtru activ' : 'filtre active'}`);
  $('#gfRibStats').innerHTML = bits.map(x => `<span>${x}</span>`).join('<span class="sep"></span>');
  $('.gfRibbon').classList.toggle('narrowed', narrowed || nf > 0);
  const tb = $('#tbSel');
  tb.style.display = 'inline-flex';
  tb.innerHTML = `<span class="tbDot${narrowed || nf ? ' on' : ''}"></span><span>${tEsc(fmtShortTs(a))} &ndash; ${tEsc(fmtShortTs(b))}</span>` +
    (ov ? `<b>${fmtN(ov.requests)}</b>` : '') + (nf ? `<span class="tbF">${nf} ${nf === 1 ? 'filtru' : 'filtre'}</span>` : '');
  tb.title = 'Selecția curentă: ' + gfDescribe() + ' -- click: perioada și filtrele';
}
function gfFilterCount() {
  const f = TRIAGE.filters, x = f.x || {};
  let n = 0;
  ['countries', 'statuses', 'severities', 'actions', 'statusClass'].forEach(k => { if ((f[k] || []).length) n++; });
  ['ip', 'pathContains', 'uaContains', 'method', 'pathExact', 'wpCat', 'uaExact', 'day'].forEach(k => { if (f[k]) n++; });
  ['ips', 'countries', 'statuses', 'paths', 'uas'].forEach(k => { if ((x[k] || []).length) n++; });
  return n;
}
$('#tbSel').addEventListener('click', () => { window.scrollTo({ top: 0, behavior: 'smooth' }); });
const _origGfRefreshOverview = gfRefreshOverview;
gfRefreshOverview = async function () { ribbonRender(); const r = await _origGfRefreshOverview.apply(this, arguments); ribbonRender(); return r; };

// ---------- Overview ----------
async function renderOverview() {
  if (!TRIAGE.ready) { $('#ovLeadText').innerHTML = 'Se indexează evenimentele -- situația apare în câteva secunde.'; return; }
  const seq = modStart('overview');
  ['#ovSecBody', '#ovCountries', '#ovIps', '#ovPaths', '#ovWp', '#ovCodes'].forEach(id => { $(id).innerHTML = modBusy(); });
  let d, tl, sec;
  try {
    [d, tl, sec] = await Promise.all([
      selData(),
      xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?kind=sel&value=`)),
      xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/security_timeline?min_severity=MEDIUM&gap=600&limit=6&kind=sel&value=`)),
    ]);
  } catch (e) { if (modMine('overview', seq)) $('#ovLeadText').innerHTML = `<span class="errTxt">Nu s-a putut calcula situația: ${tEsc(e.message)}</span>`; return; }
  if (!modMine('overview', seq)) return;
  if (!d.requests) {
    $('#ovLeadText').innerHTML = `Selecția curentă (<b>${tEsc(gfDescribe())}</b>) nu conține nicio cerere. Lărgește perioada din bara de mai sus sau scoate un filtru.`;
    $('#ovKpis').innerHTML = '';
    ['#ovSecBody', '#ovCountries', '#ovIps', '#ovPaths', '#ovWp', '#ovCodes'].forEach(id => { $(id).innerHTML = modEmpty('Nicio cerere în selecție.'); });
    modChart('ovTrend', null); $('#ovTrendNote').textContent = '';
    return;
  }
  const w = d.wordpress || {};
  const sv = sec.by_severity || {};
  const span = (d.ts_max || 0) - (d.ts_min || 0) + 1;
  const e5 = d.err_5xx || 0, e4 = d.err_4xx || 0;
  const lines = [];
  lines.push(`Între <b>${tEsc(fmtLong(d.ts_min))}</b> și <b>${tEsc(fmtLong(d.ts_max))}</b> (${fmtDur(span)}) au fost <b>${fmtN(d.requests)}</b> cereri de la <b>${fmtN(d.unique_ips)}</b> IP-uri, în medie ${String(d.req_per_min).replace('.', ',')} pe minut` +
    (d.peak_minute ? `, cu vârf de ${fmtN(d.peak_minute.n)} la ${tEsc(fmtShortTs(d.peak_minute.minute))}.` : '.'));
  lines.push(`${pct(e5, d.requests)} din răspunsuri sunt erori de server (5xx) și ${pct(e4, d.requests)} erori client (4xx).`);
  const crit = sv.CRITICAL || 0, high = sv.HIGH || 0;
  lines.push(crit || high
    ? `Securitate: <b class="${crit ? 'tCrit' : 'tHigh'}">${fmtN(crit)} evenimente CRITICAL</b> și <b>${fmtN(high)} HIGH</b>, în ${fmtN(sec.total_groups)} episoade (același IP și aceeași acțiune).`
    : 'Securitate: niciun eveniment CRITICAL sau HIGH în selecție.');
  if (w.wp_login_post || w.xmlrpc) lines.push(`WordPress: ${fmtN(w.wp_login_post || 0)} încercări de autentificare (POST wp-login) de la ${fmtN(w.wp_login_post_ips || 0)} IP-uri și ${fmtN(w.xmlrpc || 0)} cereri xmlrpc.`);
  $('#ovLeadText').innerHTML = lines.map(l => `<p>${l}</p>`).join('');
  $('#ovKpis').innerHTML =
    tile(fmtN(d.requests), 'cereri', { go: 'raw' }) +
    tile(fmtN(d.unique_ips), 'IP-uri unice', { go: 'ip' }) +
    tile(fmtN(d.unique_paths), 'URL-uri distincte', { go: 'endpoints' }) +
    tile(pct(e5, d.requests), 'erori 5xx', { tone: e5 / d.requests > .05 ? 'bad' : '', sub: fmtN(e5) + ' cereri', go: 'errors' }) +
    tile(pct(e4, d.requests), 'erori 4xx', { tone: e4 / d.requests > .15 ? 'warn' : '', sub: fmtN(e4) + ' cereri', go: 'errors' }) +
    tile(fmtN(crit + high), 'evenimente CRITICAL / HIGH', { tone: crit ? 'bad' : high ? 'warn' : '', go: 'security' }) +
    tile(fmtN(d.unknown_country || 0), 'cereri fără țară', { go: 'countries' });
  const nav = $('#navN_security'); if (nav) nav.textContent = crit + high ? fmtN(crit + high) : '';
  // tendinta
  if (tl.buckets.length) {
    modChart('ovTrend', () => xpRangeChart($('#ovTrendChart'), xpFillBuckets(tl), tl.bucket_seconds, 'classes', xpPickRange));
    const unit = tl.bucket_seconds % 3600 === 0 ? (tl.bucket_seconds / 3600) + ' h' : (tl.bucket_seconds / 60) + ' min';
    $('#ovTrendNote').textContent = `Intervale de ${unit}. Click sau tragere: restrânge perioada pentru toată aplicația.`;
  }
  // securitate
  const sevBar = ['CRITICAL', 'HIGH', 'MEDIUM'].map(k => `<div class="sevRow sev-${k}"><span class="tag ${k}">${k}</span><span class="sevN">${fmtN(sv[k] || 0)}</span></div>`).join('');
  $('#ovSecBody').innerHTML = `<div class="sevRows">${sevBar}</div>` + (sec.groups.length
    ? '<div class="ovSecList">' + sec.groups.slice(0, 6).map((g, i) => `<button type="button" class="ovSecItem sev-${tEscAttr(g.severity)}" data-gi="${i}" data-ek="alert" data-ev="${tEscAttr(g.ip + '|' + g.action_type)}">` +
        `<span class="ovSecT">${tEsc(fmtShortTs(g.first_ts))}</span><span class="ovSecM"><b>${tEsc(g.label || g.action_type)}</b><span>${tEsc(g.ip)} &middot; ${tEsc(g.country || '??')} &middot; &times;${fmtN(g.n)}</span></span></button>`).join('') + '</div>'
    : modEmpty('Niciun eveniment de securitate în selecție.'));
  $('#ovSecBody').querySelectorAll('[data-gi]').forEach(b => b.onclick = () => { const g = sec.groups[+b.dataset.gi]; XP.open('alert', g.ip + '|' + g.action_type, 'raw'); });
  // tari / IP-uri / endpoint-uri
  $('#ovCountries').innerHTML = xpBars((d.countries || []).slice(0, 8).map(r => ({ label: r.country ? ccLabel(r.country) : 'nedeterminată', n: r.n, kind: 'country', value: r.country || '??', sub: fmtN(r.ips) + ' IP' })));
  $('#ovIps').innerHTML = xpIpRows(d, 8);
  $('#ovPaths').innerHTML = xpBars((d.top_paths || []).slice(0, 8).map(r => ({ label: r.path, n: r.n, kind: 'path', value: r.path, sub: fmtN(r.ips) + ' IP' })), { mono: true });
  // WordPress
  const cats = Object.keys(WP_CAT_LABEL).filter(k => k !== 'wp_any');
  $('#ovWp').innerHTML = cats.some(k => w[k])
    ? '<div class="wpTiles">' + cats.map(k => `<button type="button" class="wpTile${w[k] ? '' : ' zero'}" data-xopenk="wp::${k}"><span class="wpTileL">${tEsc(WP_CAT_LABEL[k])}</span><span class="wpTileV">${fmtN(w[k] || 0)}</span><span class="wpTileS">${fmtN(w[k + '_ips'] || 0)} IP</span></button>`).join('') + '</div>'
    : modEmpty('Nicio cerere WordPress în selecție.');
  // coduri
  $('#ovCodes').innerHTML = codesBlock(d);
}
function codesBlock(d) {
  const cls = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, 'altele': 0 };
  (d.statuses || []).forEach(x => { const k = x.status >= 200 && x.status < 600 ? Math.floor(x.status / 100) + 'xx' : 'altele'; cls[k] += x.n; });
  const tot = d.requests || 1;
  const bar = Object.entries(cls).filter(([, n]) => n).map(([k, n]) => `<span class="clsSeg c${k[0]}" style="flex:${n}" title="${k}: ${fmtN(n)} (${pct(n, tot)})"></span>`).join('');
  const legend = Object.entries(cls).filter(([, n]) => n).map(([k, n]) => `<button type="button" class="clsLeg" data-xopenk="${k === 'altele' ? '' : 'sclass::' + k}"><span class="clsSw c${k[0]}"></span>${k} <b>${pct(n, tot)}</b></button>`).join('');
  const top = (d.statuses || []).slice().sort((a, b) => b.n - a.n).slice(0, 8);
  return `<div class="clsBar">${bar}</div><div class="clsLegend">${legend}</div>` +
    xpBars(top.map(x => ({ label: String(x.status), n: x.n, kind: 'status', value: String(x.status), sub: pct(x.n, tot) })));
}

// ---------- Traffic ----------
async function renderTraffic() {
  const box = $('#trMod'); if (!TRIAGE.ready) { box.innerHTML = modBusy(); return; }
  const seq = modStart('traffic');
  box.innerHTML = modBusy();
  let d, tl;
  try { [d, tl] = await Promise.all([selData(), xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?kind=sel&value=`))]); }
  catch (e) { if (modMine('traffic', seq)) box.innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (!modMine('traffic', seq)) return;
  if (!d.requests) { box.innerHTML = modEmptySel(d); return; }
  const span = (d.ts_max || 0) - (d.ts_min || 0) + 1;
  box.innerHTML = `<div class="tiles">` +
      tile(fmtN(d.requests), 'cereri') + tile(String(d.req_per_min).replace('.', ','), 'cereri pe minut', { sub: 'medie pe ' + fmtDur(span) }) +
      tile(d.peak_minute ? fmtN(d.peak_minute.n) : '-', 'vârf pe minut', { sub: d.peak_minute ? fmtShortTs(d.peak_minute.minute) : '' }) +
      tile(fmtN(d.unique_ips), 'IP-uri unice', { go: 'ip' }) + tile(fmtN(d.sessions_est), 'sesiuni estimate', { sub: 'pauză peste 30 min = sesiune nouă' }) +
      tile(fmtN(d.unique_uas), 'User-Agent-uri distincte') +
    `</div>
    <section class="card"><div class="cardHead"><h2>Volum în timp</h2><span class="cardHint">pe clase de cod HTTP &middot; trage peste grafic ca să alegi perioada</span></div>
      <div class="xpChartWrap tall"><canvas id="trChart"></canvas></div></section>
    <div class="ovGrid">
      <section class="card"><div class="cardHead"><h2>User-Agent-uri</h2></div>${xpBars((d.user_agents || []).map(r => ({ label: r.ua || '(gol)', n: r.n, kind: 'ua', value: r.ua, sub: pct(r.n, d.requests) })), { mono: true })}</section>
      <section class="card"><div class="cardHead"><h2>Metode HTTP</h2></div>${xpBars((d.methods || []).map(r => ({ label: r.method, n: r.n, kind: 'method', value: r.method, sub: pct(r.n, d.requests) })))}</section>
    </div>
    <div class="modSub">Compoziție, bursturi, crawlere și distribuția pe ore</div>`;
  if (tl.buckets.length) modChart('trChart', () => xpRangeChart($('#trChart'), xpFillBuckets(tl), tl.bucket_seconds, 'classes', xpPickRange));
}

// ---------- Countries ----------
async function renderCountries() {
  const box = $('#ctyMod'); if (!TRIAGE.ready) { box.innerHTML = modBusy(); return; }
  const seq = modStart('countries');
  box.innerHTML = modBusy();
  let d; try { d = await selData(); } catch (e) { if (modMine('countries', seq)) box.innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (!modMine('countries', seq)) return;
  if (!d.requests) { box.innerHTML = modEmptySel(d); return; }
  const cs = d.countries || [];
  const ro = (cs.find(c => c.country === 'RO') || { n: 0, ips: 0 });
  const unk = d.unknown_country || 0;
  const nonro = d.requests - ro.n - unk;
  const max = Math.max(1, ...cs.map(c => c.n));
  box.innerHTML = `<div class="tiles">` +
      tile(fmtN(cs.filter(c => c.country).length), 'țări') +
      tile(pct(ro.n, d.requests), 'din România', { sub: fmtN(ro.n) + ' cereri · ' + fmtN(ro.ips) + ' IP', xact: 'country::RO' }) +
      tile(pct(nonro, d.requests), 'din afara României', { sub: fmtN(nonro) + ' cereri' }) +
      tile(fmtN(unk), 'fără țară determinată', { sub: 'IP-uri private sau absente din GeoIP', xact: 'country::??', tone: unk ? '' : '' }) +
    `</div>
    <section class="card"><div class="cardHead"><h2>Cereri pe țară</h2><span class="cardHint">click: detaliile țării &middot; &#8853; / &#8856; la hover: filtrează sau exclude</span></div>
      <table class="dataTbl"><thead><tr><th>Țară</th><th class="num">Cereri</th><th class="barCol"></th><th class="num">Pondere</th><th class="num">IP-uri</th><th class="num">Cereri / IP</th></tr></thead><tbody>` +
      cs.map(c => `<tr><td>${flagHtml(c.country)}<a class="spLink" data-ek="country" data-ev="${tEscAttr(c.country || '??')}" data-xopen="1" tabindex="0">${tEsc(c.country ? ccLabel(c.country) : 'nedeterminată (??)')}</a>${entQuick('country', c.country || '??')}</td>` +
        `<td class="num">${fmtN(c.n)}</td><td class="barCol"><span class="hbar" style="width:${Math.max(1, Math.round(100 * c.n / max))}%"></span></td><td class="num">${pct(c.n, d.requests)}</td><td class="num">${fmtN(c.ips)}</td><td class="num">${(c.n / Math.max(1, c.ips)).toFixed(1).replace('.', ',')}</td></tr>`).join('') +
      `</tbody></table>${cs.length >= 60 ? '<div class="note">Primele 60 de țări după numărul de cereri.</div>' : ''}</section>`;
}

// ---------- Endpoints ----------
async function renderEndpoints() {
  const box = $('#epMod'); if (!TRIAGE.ready) { box.innerHTML = modBusy(); return; }
  const seq = modStart('endpoints');
  box.innerHTML = modBusy();
  let d; try { d = await selData(); } catch (e) { if (modMine('endpoints', seq)) box.innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (!modMine('endpoints', seq)) return;
  if (!d.requests) { box.innerHTML = modEmptySel(d); return; }
  const tp = d.top_paths || [];
  const top1 = tp[0];
  box.innerHTML = `<div class="tiles">` +
      tile(fmtN(d.unique_paths), 'URL-uri distincte', { sub: 'fără query string' }) +
      tile(top1 ? pct(top1.n, d.requests) : '-', 'cel mai accesat URL', { sub: top1 ? tEsc(top1.path.slice(0, 40)) : '', xact: top1 ? 'path::' + top1.path : '' }) +
      tile(fmtN((d.error_paths || []).length), 'URL-uri cu erori', { go: 'errors' }) +
      tile(fmtN((d.wp_routes || []).length), 'rute plugin / temă', { go: 'wordpress' }) +
    `</div>
    <div class="ovGrid">
      <section class="card"><div class="cardHead"><h2>Cele mai accesate URL-uri</h2><span class="cardHint">click: istoricul endpoint-ului</span></div>
        ${xpBars(tp.slice(0, 40).map(r => ({ label: r.path, n: r.n, kind: 'path', value: r.path, sub: fmtN(r.ips) + ' IP' })), { mono: true })}</section>
      <section class="card"><div class="cardHead"><h2>URL-uri cu erori</h2><span class="cardHint">cod, cereri, IP-uri</span></div>
        ${xpBars((d.error_paths || []).slice(0, 25).map(r => ({ label: `${r.status}  ${r.path}`, n: r.n, kind: 'path', value: r.path, sub: fmtN(r.ips) + ' IP' })), { mono: true, empty: 'Niciun URL cu erori în selecție.' })}</section>
    </div>`;
}

// ---------- HTTP Errors ----------
async function renderErrors() {
  const box = $('#errMod'); if (!TRIAGE.ready) { box.innerHTML = modBusy(); return; }
  const seq = modStart('errors');
  box.innerHTML = modBusy();
  let d, tl, d4, d5;
  try {
    [d, tl, d4, d5] = await Promise.all([selData(), xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?kind=sel&value=`)),
      xpExploreData('sclass', '4xx'), xpExploreData('sclass', '5xx')]);
  } catch (e) { if (modMine('errors', seq)) box.innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (!modMine('errors', seq)) return;
  if (!d.requests) { box.innerHTML = modEmptySel(d); return; }
  const errs = (d.statuses || []).filter(x => x.status >= 400).sort((a, b) => b.n - a.n);
  const e4 = d.err_4xx || 0, e5 = d.err_5xx || 0;
  box.innerHTML = `<div class="tiles">` +
      tile(pct(e4 + e5, d.requests), 'rata erorilor', { sub: fmtN(e4 + e5) + ' din ' + fmtN(d.requests), tone: (e4 + e5) / d.requests > .2 ? 'warn' : '' }) +
      tile(fmtN(e4), 'erori client (4xx)', { xact: 'sclass::4xx', tone: e4 ? 'warn' : '' }) +
      tile(fmtN(e5), 'erori server (5xx)', { xact: 'sclass::5xx', tone: e5 ? 'bad' : '' }) +
      tile(errs[0] ? String(errs[0].status) : '-', 'cel mai frecvent cod de eroare', { sub: errs[0] ? fmtN(errs[0].n) + ' cereri' : '', xact: errs[0] ? 'status::' + errs[0].status : '' }) +
    `</div>
    <section class="card"><div class="cardHead"><h2>Erori în timp</h2><span class="cardHint">4xx și 5xx &middot; trage peste grafic ca să alegi perioada</span></div>
      <div class="xpChartWrap tall"><canvas id="errChart"></canvas></div></section>
    <div class="ovGrid3">
      <section class="card"><div class="cardHead"><h2>Coduri de eroare</h2><span class="cardHint">click: cererile cu acel cod</span></div>
        ${xpBars(errs.map(x => ({ label: String(x.status), n: x.n, kind: 'status', value: String(x.status), sub: pct(x.n, d.requests) })), { empty: 'Nicio eroare în selecție.' })}</section>
      <section class="card"><div class="cardHead"><h2>IP-uri cu erori 4xx</h2></div>${d4.requests ? xpIpRows(d4, 10) : modEmpty('Nicio eroare 4xx.')}</section>
      <section class="card"><div class="cardHead"><h2>IP-uri cu erori 5xx</h2></div>${d5.requests ? xpIpRows(d5, 10) : modEmpty('Nicio eroare 5xx.')}</section>
    </div>
    <section class="card"><div class="cardHead"><h2>URL-uri care produc erori</h2><span class="cardHint">cod, URL, cereri, IP-uri, prima apariție</span></div>
      ${xpBars((d.error_paths || []).slice(0, 40).map(r => ({ label: `${r.status}  ${r.path}`, n: r.n, kind: 'path', value: r.path, sub: `${fmtN(r.ips)} IP · ${fmtShortTs(r.first_ts)}` })), { mono: true, empty: 'Niciun URL cu erori.' })}</section>`;
  if (tl.buckets.length) modChart('errChart', () => xpRangeChart($('#errChart'), xpFillBuckets(tl), tl.bucket_seconds, 'errors', xpPickRange));
}

// ---------- WordPress ----------
async function renderWordpress() {
  const box = $('#wpMod'); if (!TRIAGE.ready) { box.innerHTML = modBusy(); return; }
  const seq = modStart('wordpress');
  box.innerHTML = modBusy();
  let d, tl, lp, xr, sd;
  try {
    [d, tl, lp, xr, sd] = await Promise.all([xpExploreData('wp', 'wp_any'), xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/timeline?kind=wp&value=wp_any`)),
      xpExploreData('wp', 'wp_login_post'), xpExploreData('wp', 'xmlrpc'), selData()]);
  } catch (e) { if (modMine('wordpress', seq)) box.innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (!modMine('wordpress', seq)) return;
  if (!d.requests) { box.innerHTML = modEmpty(`<b>Nicio cerere WordPress în selecția curentă</b> (${tEsc(gfDescribe())}).`) + '<div class="modSub">Analiza detaliată WordPress</div>'; return; }
  const w = d.wordpress || {};
  const cats = Object.keys(WP_CAT_LABEL).filter(k => k !== 'wp_any');
  const codes = {};
  (w.status_by_category || []).forEach(x => { (codes[x.cat] = codes[x.cat] || []).push(x); });
  const nAl = (d.alerts || []).reduce((a, b) => a + b.hits, 0);
  box.innerHTML = `<div class="tiles">` +
      tile(fmtN(d.requests), 'cereri WordPress', { sub: fmtN(d.unique_ips) + ' IP-uri', xact: 'wp::wp_any' }) +
      tile(fmtN(w.wp_login_post || 0), 'autentificări (POST wp-login)', { sub: fmtN(w.wp_login_post_ips || 0) + ' IP · ' + fmtN(w.wp_login_post_sessions || 0) + ' sesiuni', xact: 'wp::wp_login_post', tone: (w.wp_login_post || 0) > 50 ? 'warn' : '' }) +
      tile(fmtN(w.xmlrpc || 0), 'cereri xmlrpc.php', { sub: fmtN(w.xmlrpc_ips || 0) + ' IP', xact: 'wp::xmlrpc', tone: (w.xmlrpc || 0) > 20 ? 'warn' : '' }) +
      tile(fmtN(nAl), 'alerte CRITICAL / HIGH', { tone: nAl ? 'bad' : '', xact: 'wp::wp_any::alerts' }) +
    `</div>
    <section class="card"><div class="cardHead"><h2>Activitate pe categorii</h2><span class="cardHint">cereri, IP-uri, sesiuni estimate și coduri de răspuns &middot; click: detaliile categoriei</span></div>
      <table class="dataTbl"><thead><tr><th>Categorie</th><th class="num">Cereri</th><th class="num">IP-uri</th><th class="num">Sesiuni</th><th>Coduri de răspuns</th></tr></thead><tbody>` +
      cats.map(k => `<tr class="${w[k] ? '' : 'mutedRow'}"><td>${w[k] ? `<a class="spLink" data-ek="wp" data-ev="${k}" data-xopen="1" tabindex="0">${tEsc(WP_CAT_LABEL[k])}</a>${entQuick('wp', k)}` : tEsc(WP_CAT_LABEL[k])}</td>` +
        `<td class="num">${fmtN(w[k] || 0)}</td><td class="num">${fmtN(w[k + '_ips'] || 0)}</td><td class="num">${fmtN(w[k + '_sessions'] || 0)}</td>` +
        `<td class="codesCell">${(codes[k] || []).sort((a, b) => b.n - a.n).slice(0, 6).map(x => `<span class="codePill c${String(x.status)[0]}">${x.status} <b>${fmtN(x.n)}</b></span>`).join('')}</td></tr>`).join('') +
      `</tbody></table>
      <div class="note">Un acces la wp-admin sau wp-login nu înseamnă automat atac sau autentificare reușită. Login-urile deduse (POST 302 urmat de /wp-admin/ 200 în 5 minute) apar ca „Login OK” în cereri și în alerte.</div></section>
    <section class="card"><div class="cardHead"><h2>Cereri WordPress în timp</h2><span class="cardHint">trage peste grafic ca să alegi perioada</span></div><div class="xpChartWrap"><canvas id="wpChart"></canvas></div></section>
    <div class="ovGrid3">
      <section class="card"><div class="cardHead"><h2>IP-uri pe wp-login (POST)</h2></div>${lp.requests ? xpIpRows(lp, 10) : modEmpty('Nicio autentificare în selecție.')}</section>
      <section class="card"><div class="cardHead"><h2>IP-uri pe xmlrpc.php</h2></div>${xr.requests ? xpIpRows(xr, 10) : modEmpty('Nicio cerere xmlrpc în selecție.')}</section>
      <section class="card"><div class="cardHead"><h2>Rute de plugin-uri și teme</h2><span class="cardHint">2xx servite &middot; 4xx inexistente</span></div>
        ${xpBars((sd.wp_routes || []).slice(0, 15).map(r => ({ label: r.route, n: r.n, kind: 'prefix', value: '/wp-content/' + r.route + '/', sub: `${fmtN(r.ips)} IP · 4xx ${fmtN(r.err_4xx)}` })), { mono: true, empty: 'Nicio rută de plugin sau temă.' })}</section>
    </div>`;
  if (tl.buckets.length) modChart('wpChart', () => xpRangeChart($('#wpChart'), xpFillBuckets(tl), tl.bucket_seconds, 'classes', xpPickRange));
}

// ---------- legaturi, hook-uri, sincronizare cu selectia ----------
Object.assign(MOD_HOOKS, {
  overview: renderOverview, traffic: renderTraffic, countries: renderCountries, endpoints: renderEndpoints,
  errors: renderErrors, wordpress: renderWordpress,
  raw: () => { setTimeout(() => { triageRenderVisibleRows(); }, 30); },
});
GF_LISTENERS.push(() => {
  XP.cache.clear();
  ribbonRender();
  if (['overview', 'traffic', 'countries', 'endpoints', 'errors', 'wordpress'].includes(CURRENT_PAGE)) MOD_HOOKS[CURRENT_PAGE]();
});
document.addEventListener('click', (e) => {
  const g = e.target.closest('[data-goto]');
  if (g && g.dataset.goto) { e.preventDefault(); showPage(g.dataset.goto); return; }
  const o = e.target.closest('[data-xopen]');
  if (o && o.dataset.ek && !e.target.closest('#xpDrawer')) { e.preventDefault(); XP.open(o.dataset.ek, o.dataset.ev); return; }
  const x = e.target.closest('[data-xopenk]');
  if (x && x.dataset.xopenk && !e.target.closest('#xpDrawer')) {
    const [k, v, t] = x.dataset.xopenk.split('::');
    if (k) XP.open(k, v || '', t);
  }
});
$('#sbCmd').onclick = () => cmdOpen();
$('#sbKeys').onclick = () => shortcutsHelp();
window.addEventListener('popstate', () => { const h = (location.hash || '').slice(1).split('?')[0]; if (DATASET_ID && h && h !== CURRENT_PAGE && MODULES[h]) showPage(h); });
window.addEventListener('hashchange', () => { const h = (location.hash || '').slice(1).split('?')[0]; if (DATASET_ID && h && h !== CURRENT_PAGE && MODULES[h]) showPage(h); });
const _origAfterIndexReady46 = gfAfterIndexReady;
gfAfterIndexReady = async function () {
  await _origAfterIndexReady46();
  ribbonRender();
  if (MOD_HOOKS[CURRENT_PAGE] && CURRENT_PAGE !== 'raw') MOD_HOOKS[CURRENT_PAGE]();
};
const _origWsBadge = WS.badge;
WS.badge = function () { _origWsBadge.call(this); const n = $('#navN_investigations'); if (n) n.textContent = this.data && this.data.items.length ? String(this.data.items.length) : ''; };


// ==========================================================================
// v47 -- WORKPLACE: filtrare combinata pe orice camp, cu numarul exact de
// cereri pe fiecare conditie, fatete clicabile si liniile brute.
// ==========================================================================
const WK = { guideOpen: (() => { try { return localStorage.getItem('logscan.wk.guide') !== '0'; } catch (e) { return true; } })(), meta: null, metaFor: null, conds: [], period: 'global', from: null, to: null, sort: 'ts_desc', limit: 100,
             offset: 0, view: 'table', res: null, seq: 0, timer: null, nextId: 1, open: {}, busy: false, err: '' };
const WK_OPS = { in: 'este', contains: 'contine', regex: 'regex', prefix: 'incepe cu', suffix: 'se termina cu', exact: 'exact',
                 cidr: 'in subnet', has: 'are', param: 'are parametrul', empty: 'e gol / "-"', range: 'intre' };
const WK_GROUPS = [
  ['Sursa', [['ip', 'in', 'IP exact'], ['ip', 'cidr', 'Subnet / CIDR'], ['ip', 'prefix', 'IP incepe cu'], ['country', 'in', 'Tara'],
             ['asn', 'in', 'Furnizor (ASN)'], ['asn', 'contains', 'Furnizor contine']]],
  ['Cerere', [['method', 'in', 'Metoda'], ['path', 'contains', 'URL contine'], ['path', 'regex', 'URL regex'], ['path_only', 'exact', 'URL exact (fara query)'],
              ['path_only', 'prefix', 'URL incepe cu'], ['ext', 'in', 'Extensie fisier'], ['query', 'has', 'Are query string'], ['query', 'param', 'Parametru in query']]],
  ['Raspuns', [['status', 'in', 'Cod / clasa HTTP'], ['size', 'range', 'Marime raspuns (B)']]],
  ['User-Agent', [['ua', 'contains', 'UA contine'], ['ua', 'exact', 'UA exact'], ['ua', 'prefix', 'UA incepe cu'], ['ua', 'regex', 'UA regex'],
                  ['ua', 'empty', 'UA gol'], ['ua_cat', 'in', 'Categorie UA'], ['crawler', 'in', 'Crawler verificat DNS']]],
  ['Securitate', [['severity', 'in', 'Severitate'], ['action', 'in', 'Actiune / regula'], ['wp', 'in', 'Zona WordPress']]],
  ['Timp', [['hour', 'range', 'Interval orar'], ['weekday', 'in', 'Zi din saptamana']]],
  ['Comportament IP', [['ip_hits', 'range', 'Cereri per IP'], ['ip_paths', 'range', 'URL-uri unice per IP'], ['ip_rpm', 'range', 'Vârf cereri / minut per IP'],
                       ['ip_err', 'range', '% erori 4xx per IP'], ['ip_uas', 'range', 'User-Agent-uri diferite per IP'], ['subnet_hits', 'range', 'Cereri per subnet']]],
];
const WK_VAL_LABEL = {
  crawler: { verified: 'crawler verificat DNS', fake: 'UA fals de crawler', unverified: 'crawler neverificat', none: 'nu e crawler' },
  ua_cat: { 'Human/Browser': 'Browser (uman)', 'Legitimate crawler': 'Motor de cautare', 'AI crawler': 'AI crawler', 'SEO/monitoring': 'SEO / monitorizare',
            'Social media crawler': 'Social media (preview)', 'Script/tool': 'Script / tool', 'Other crawler/bot': 'Alt bot', 'Suspicious automation': 'Automatizare suspecta',
            'Unknown/unidentified': 'Neidentificat' },
  query: { da: 'cu query string', nu: 'fara query string' },
};
const WK_PH = { ip: '86.124.0.1', country: 'RO', path: '/wp-login.php', path_only: '/produse/', ua: 'facebookexternalhit', query: 'filter_culoare' };
const C = (field, op, values, not) => ({ field, op, values: values || [], not: !!not });
const WK_PATTERN_ACTIONS = ['pattern_sqli', 'pattern_sqli_union', 'pattern_sqli_error_blind', 'pattern_sqli_time_blind', 'pattern_sqli_exfil', 'pattern_lfi_rfi', 'pattern_xss_tag', 'pattern_xss_payload', 'pattern_xss_html_entity'];
const WK_PRESETS = [
  ['Boți, scanări și scraping', [
    ['Scraping (multe pagini, UA de browser)', [C('ip_paths', 'range', [150, null]), C('ua_cat', 'in', ['Human/Browser']), C('ext', 'in', ['img', 'js', 'css', 'font', 'media'], true)]],
    ['Scraping catalog produse', [C('path_only', 'regex', ['/(produs|product|produse|shop|magazin|categorie-produs|product-category)/']), C('ip_hits', 'range', [200, null]), C('crawler', 'in', ['verified'], true)]],
    ['Rafale rapide (60+ cereri / minut)', [C('ip_rpm', 'range', [60, null]), C('crawler', 'in', ['verified'], true)]],
    ['Scanare automată (majoritar 4xx)', [C('ip_err', 'range', [50, null]), C('ip_hits', 'range', [30, null])]],
    ['Rotație de User-Agent (5+ / IP)', [C('ip_uas', 'range', [5, null])]],
    ['Atac distribuit pe subnet', [C('subnet_hits', 'range', [500, null]), C('ip_hits', 'range', [null, 50])]],
    ['Atac pe filtre (Woo / Presta)', [C('path', 'regex', ['[?&](filter_[^=&]*|query_type_[^=&]*|min_price|max_price|orderby|pa_[^=&]*|selected_filters)=|[?&]q=[^&=/]{2,60}-|[?&]order=product\\.']), C('crawler', 'in', ['verified'], true)]],
    ['Atac pe filtre distribuit (1-3 cereri / IP)', [C('path', 'regex', ['[?&](filter_[^=&]*|query_type_[^=&]*|pa_[^=&]*|selected_filters)=|[?&]q=[^&=/]{2,60}-|[?&]order=product\\.']), C('ip_hits', 'range', [null, 3])]],
    ['Scanare plugin-uri / teme WP (404)', [C('path_only', 'regex', ['^/wp-content/(plugins|themes)/']), C('status', 'in', ['404'])]],
    ['Enumerare utilizatori WP', [C('path', 'regex', ['[?&]author=\\d|/wp-json/wp/v2/users|/author/'])]],
    ['xmlrpc.php (brute force / pingback)', [C('path_only', 'suffix', ['xmlrpc.php'])]],
    ['Scanere de vulnerabilități', [C('path_only', 'regex', ['(phpunit|/cgi-bin/|/vendor/|/\\.env|/\\.git|actuator|/solr/|boaform|hnap1|/\\.well-known/.*\\.php|eval-stdin)'])]],
    ['Unelte de scanare (sqlmap, nikto, nuclei...)', [C('ua', 'regex', ['sqlmap|nikto|nuclei|zgrab|masscan|nmap|wpscan|acunetix|dirbuster|gobuster|ffuf|httpx|python-requests|go-http-client'])]],
    ['Scripturi cu volum mare (50+ cereri)', [C('ua_cat', 'in', ['Script/tool', 'Suspicious automation']), C('ip_hits', 'range', [50, null])]],
    ['admin-ajax.php în rafală (30+ / min)', [C('path_only', 'suffix', ['admin-ajax.php']), C('ip_rpm', 'range', [30, null])]],
    ['Boți declarați, neverificați DNS', [C('crawler', 'in', ['fake', 'unverified'])]],
  ]],
  ['User-Agent', [
    ['UA personalizat (contine)...', [C('ua', 'contains', [])], 'focus'],
    ['Exclude un UA...', [C('ua', 'contains', [], true)], 'focus'],
    ['Doar trafic uman', [C('ua_cat', 'in', ['Human/Browser']), C('crawler', 'in', ['fake'], true)]],
    ['Crawlere verificate DNS', [C('crawler', 'in', ['verified'])]],
    ['UA fals de crawler', [C('crawler', 'in', ['fake'])]],
    ['Crawlere neverificate', [C('crawler', 'in', ['unverified'])]],
    ['Facebook / Meta', [C('ua', 'contains', ['facebookexternalhit', 'meta-externalagent', 'facebookcatalog'])]],
    ['Googlebot', [C('ua', 'contains', ['googlebot', 'google-inspectiontool', 'adsbot-google'])]],
    ['Bingbot', [C('ua', 'contains', ['bingbot', 'msnbot'])]],
    ['AI crawlere', [C('ua_cat', 'in', ['AI crawler'])]],
    ['SEO (Ahrefs, Semrush...)', [C('ua_cat', 'in', ['SEO/monitoring'])]],
    ['curl / python / wget / Go', [C('ua', 'regex', ['^(curl|wget|python|go-http|java|okhttp|libwww|php|guzzle|axios|node-fetch)'])]],
    ['Headless / automatizare', [C('ua_cat', 'in', ['Suspicious automation'])]],
    ['UA gol sau "-"', [C('ua', 'empty', [])]],
    ['Fara Meta / Google / Bing', [C('ua', 'contains', ['facebookexternalhit', 'meta-externalagent', 'googlebot', 'bingbot'], true)]],
    ['Browsere vechi (MSIE)', [C('ua', 'regex', ['msie [1-9]\\.|windows nt 5\\.'])]],
  ]],
  ['Securitate', [
    ['Doar CRITICAL / HIGH', [C('severity', 'in', ['CRITICAL', 'HIGH'])]],
    ['Tipare de atac (SQLi/LFI/XSS)', [C('action', 'in', ['pattern_sqli', 'pattern_sqli_union', 'pattern_sqli_error_blind', 'pattern_sqli_time_blind', 'pattern_sqli_exfil', 'pattern_lfi_rfi', 'pattern_xss_tag', 'pattern_xss_payload', 'pattern_xss_html_entity', 'pattern_webshell_name'])]],
    ['Atacuri reusite (2xx)', [C('action', 'in', ['pattern_sqli', 'pattern_sqli_union', 'pattern_sqli_error_blind', 'pattern_sqli_time_blind', 'pattern_sqli_exfil', 'pattern_lfi_rfi', 'pattern_xss_tag', 'pattern_xss_payload', 'pattern_webshell_name', 'webshell_active']), C('status', 'in', ['2xx'])]],
    ['POST pe .php', [C('method', 'in', ['POST']), C('ext', 'in', ['php'])]],
    ['PHP in uploads / cache', [C('path_only', 'regex', ['wp-content/(uploads|cache)/.*\\.ph(p\\d?|tml)$'])]],
    ['Brute force login (POST)', [C('method', 'in', ['POST']), C('path_only', 'suffix', ['wp-login.php', 'xmlrpc.php'])]],
    ['Brute force din afara RO', [C('method', 'in', ['POST']), C('path_only', 'suffix', ['wp-login.php', 'xmlrpc.php']), C('country', 'in', ['__NON_RO__'])]],
    ['wp-admin din afara RO', [C('wp', 'in', ['wp_admin']), C('country', 'in', ['__NON_RO__']), C('status', 'in', ['200'])]],
    ['Fisiere sensibile', [C('path_only', 'regex', ['(\\.env|\\.git/|wp-config|phpinfo|\\.sql|\\.bak|\\.old|\\.zip|\\.tar|\\.gz|/\\.aws|id_rsa)'])]],
    ['Enumerare filtre (Woo/Presta)', [C('path', 'regex', ['[?&](filter_[^=&]*|query_type_[^=&]*|add_to_wishlist|add-to-cart|q)='])]],
    ['Scanere (403 / 404 in rafala)', [C('status', 'in', ['403', '404']), C('ip_hits', 'range', [50, null]), C('crawler', 'in', ['verified'], true)]],
  ]],
  ['Erori si performanta', [
    ['Erori server 5xx', [C('status', 'in', ['5xx'])]],
    ['404 fara crawlere', [C('status', 'in', ['404']), C('crawler', 'in', ['none'])]],
    ['403 / 429 (blocate)', [C('status', 'in', ['403', '429'])]],
    ['Raspunsuri > 1 MB', [C('size', 'range', [1048576, null])]],
    ['Redirecturi 301/302', [C('status', 'in', ['301', '302'])]],
  ]],
  ['Comportament', [
    ['IP-uri agresive (300+ cereri)', [C('ip_hits', 'range', [300, null])]],
    ['IP-uri cu 100+ URL-uri unice', [C('ip_paths', 'range', [100, null])]],
    ['Trafic de noapte (00-06), uman', [C('hour', 'range', [0, 5]), C('ua_cat', 'in', ['Human/Browser'])]],
    ['Doar trafic non-RO', [C('country', 'in', ['__NON_RO__'])]],
    ['Doar assets (img/js/css/font)', [C('ext', 'in', ['img', 'js', 'css', 'font'])]],
    ['Fara assets statice', [C('ext', 'in', ['img', 'js', 'css', 'font', 'media'], true)]],
  ]],
];
const WK_SAVED = {
  list() { try { return JSON.parse(localStorage.getItem('logscan.wk.presets') || '[]'); } catch (e) { return []; } },
  save(v) { try { localStorage.setItem('logscan.wk.presets', JSON.stringify(v)); return true; } catch (e) { showError('Browserul nu permite salvarea locala: ' + e.message); return false; } },
};
function wkLabel(field, v) { const m = WK_VAL_LABEL[field]; if (m && m[v]) return m[v]; if (field === 'wp') return (typeof WP_CAT_LABEL !== 'undefined' && WP_CAT_LABEL[v]) || (v === 'wp_any' ? 'orice WordPress' : v); if (field === 'country' && v === '__NON_RO__') return 'non-RO'; return String(v); }
function wkFieldLabel(f) { return (WK.meta && WK.meta.fields[f] && WK.meta.fields[f].label) || f; }
function wkMkCond(c) { return { id: WK.nextId++, field: c.field, op: c.op, values: (c.values || []).slice(), not: !!c.not, off: false }; }

async function wkEnsureMeta() {
  if (!DATASET_ID) return false;
  if (WK.meta && WK.metaFor === DATASET_ID) return true;
  if (WK.metaFor !== DATASET_ID) { WK.res = null; WK.conds = []; WK.offset = 0; WK.open = {}; WK.period = 'global'; }
  try {
    const r = await fetch(`/api/dataset/${DATASET_ID}/workplace/meta`);
    const d = await r.json();
    if (!r.ok) { WK.err = d.error || 'eroare'; wkRender(); return false; }
    WK.meta = d; WK.metaFor = DATASET_ID; WK.err = '';
    try {
      const st = JSON.parse(sessionStorage.getItem('logscan.wk.state.' + DATASET_ID) || 'null');
      if (st) { WK.conds = (st.conds || []).map(wkMkCond); WK.period = st.period || 'global'; WK.from = st.from; WK.to = st.to; }
    } catch (e) {}
    return true;
  } catch (e) { WK.err = 'Eroare de retea: ' + e.message; wkRender(); return false; }
}
function wkPeriodTs() {
  if (WK.period === 'all') return [null, null];
  if (WK.period === 'custom') return [WK.from, WK.to];
  return gfTimeNarrowed() ? [TRIAGE.tsFrom, TRIAGE.tsTo] : [null, null];
}
function wkQuery() {
  const [a, b] = wkPeriodTs();
  return { ts_from: a, ts_to: b, conds: WK.conds.map(c => ({ field: c.field, op: c.op, values: c.values, not: c.not, off: c.off })) };
}
function wkPersist() {
  try { sessionStorage.setItem('logscan.wk.state.' + DATASET_ID, JSON.stringify({ conds: wkQuery().conds, period: WK.period, from: WK.from, to: WK.to })); } catch (e) {}
}
function wkSchedule(resetOffset) {
  if (resetOffset !== false) WK.offset = 0;
  clearTimeout(WK.timer);
  WK.timer = setTimeout(wkRun, 220);
}
async function wkRun() {
  if (!(await wkEnsureMeta())) return;
  wkPersist();
  const seq = ++WK.seq;
  WK.busy = true; wkRenderBusy();
  try {
    const r = await fetch(`/api/dataset/${DATASET_ID}/workplace`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: wkQuery(), limit: WK.limit, offset: WK.offset, sort: WK.sort }) });
    const d = await r.json();
    if (seq !== WK.seq) return;
    WK.busy = false;
    if (!r.ok) { WK.err = d.error || 'eroare'; } else { WK.err = ''; WK.res = d; }
  } catch (e) { if (seq !== WK.seq) return; WK.busy = false; WK.err = 'Eroare de retea: ' + e.message; }
  wkRender();
}

// ---------------------------------------------------------------- randare
function wkRender() {
  const root = $('#wkMod');
  if (!root) return;
  if (!DATASET_ID) { root.innerHTML = '<div class="wkEmpty">Incarca un log ca sa folosesti Workplace.</div>'; return; }
  if (!WK.meta) { root.innerHTML = `<div class="wkEmpty">${WK.err ? esc(WK.err) : '<span class="spinner"></span> Se pregateste Workplace...'}</div>`; return; }
  const focusSel = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.wkfocus;
  root.innerHTML = `
    <div class="wkTop">
      <section class="wkCard" id="wkBuilder">
        <div class="wkHeadRow">
          <div><h3>Conditii de filtrare</h3><div class="wkSub">Toate conditiile se aplica impreuna (SI). Mai multe valori in aceeasi conditie = SAU. <b>NU</b> = excludere. Fiecare rand arata cate cereri potriveste singur si cate raman dupa el.</div></div>
          <div class="spacer"></div>
          <div class="wkPeriod">Perioada
            <select id="wkPeriodSel">
              <option value="global"${WK.period === 'global' ? ' selected' : ''}>selectia globala${gfTimeNarrowed() ? '' : ' (tot logul)'}</option>
              <option value="all"${WK.period === 'all' ? ' selected' : ''}>tot logul</option>
              <option value="custom"${WK.period === 'custom' ? ' selected' : ''}>personalizata</option>
            </select>
            ${WK.period === 'custom' ? `<input type="datetime-local" step="1" id="wkFrom" value="${WK.from != null ? epochToDtLocal(WK.from, TRIAGE.tzOffset) : ''}"> - <input type="datetime-local" step="1" id="wkTo" value="${WK.to != null ? epochToDtLocal(WK.to, TRIAGE.tzOffset) : ''}">` : ''}
          </div>
        </div>
        <div class="wkConds" id="wkConds">${wkRenderConds()}</div>
        <div class="wkActions" style="border-top:0;padding-top:0">
          <button class="ghost" id="wkSavePreset" ${WK.conds.length ? '' : 'disabled'}>Salveaza ca preset</button>
          <button class="ghost" id="wkClear" ${WK.conds.length ? '' : 'disabled'}>Sterge toate conditiile</button>
          <button class="ghost" id="wkToGlobal" title="Aplica perioada din Workplace ca selectie globala in toata aplicatia" ${WK.period === 'custom' ? '' : 'disabled'}>Perioada &rarr; selectie globala</button>
          <div class="spacer"></div>
          <span class="wkBusy" id="wkBusy"></span>
        </div>
        <div class="wkAddTitle wkBigSub" style="margin-top:12px">Adauga o conditie</div><div class="wkAdd" style="margin-top:4px">${WK_GROUPS.map(([g, items]) => `<div class="wkAddGrp"><div class="wkAddLbl">${esc(g)}</div>${items.map(([f, o, l]) => `<button type="button" data-wkadd="${f}|${o}">+ ${esc(l)}</button>`).join('')}</div>`).join('')}</div>
        ${WK.err ? `<div class="wkErr">${esc(WK.err)}</div>` : ''}
      </section>
      <aside class="wkCard">
        <h3>Preseturi</h3>
        <div class="wkSub">Un click inlocuieste conditiile; Shift+click le adauga la cele existente. Orice preset se poate edita apoi in randurile din stanga.</div>
        <div class="wkUaBar">
          <input id="wkUaQuick" data-wkfocus="ua" placeholder="Scrie un User-Agent (sau o parte din el)...">
          <div class="wkUaBtns">
            <button class="ghost" data-wkua="contains">contine</button><button class="ghost" data-wkua="not">NU contine</button>
            <button class="ghost" data-wkua="exact">exact</button><button class="ghost" data-wkua="prefix">incepe cu</button><button class="ghost" data-wkua="regex">regex</button>
          </div>
        </div>
        ${wkRenderPresets()}
      </aside>
    </div>
    ${wkRenderGuide()}
    <div class="wkMain">
      <section class="wkCard" id="wkResults">${wkRenderResults()}</section>
      <aside class="wkFacets" id="wkFacets">${wkRenderFacets()}</aside>
    </div>`;
  if (focusSel) { const el = root.querySelector(`[data-wkfocus="${focusSel}"]`); if (el) el.focus(); }
  wkRenderBusy();
}
function wkRenderBusy() {
  const el = $('#wkBusy');
  if (!el) return;
  el.innerHTML = WK.busy ? '<span class="spinner" style="width:11px;height:11px"></span> se calculeaza...'
    : (WK.res ? `calculat in ${WK.res.elapsed_ms} ms` : '');
}
function wkOpsFor(f) { return (WK.meta.fields[f] && WK.meta.fields[f].ops) || ['in']; }
function wkRenderConds() {
  if (!WK.conds.length) return '<div class="wkEmpty">Nicio conditie: se afiseaza toate cererile din perioada. Adauga o conditie de mai jos, alege un preset sau apasa pe o valoare din fatetele din dreapta.</div>';
  const fun = {};
  ((WK.res && WK.res.funnel) || []).forEach(x => { fun[x.i] = x; });
  return WK.conds.map((c, i) => {
    const fe = Object.keys(WK.meta.fields).map(f => `<option value="${f}"${f === c.field ? ' selected' : ''}>${esc(wkFieldLabel(f))}</option>`).join('');
    const ops = wkOpsFor(c.field).map(o => `<option value="${o}"${o === c.op ? ' selected' : ''}>${esc(WK_OPS[o] || o)}</option>`).join('');
    const fx = fun[i];
    const cnt = c.off ? '<span class="wkCnt">dezactivata</span>'
      : fx ? `<span class="wkCnt"><b class="${fx.alone ? '' : 'zero'}">${fmtNum(fx.alone)}</b> singura<br><b class="${fx.after ? '' : 'zero'}">${fmtNum(fx.after)}</b> dupa ea</span>`
      : '<span class="wkCnt">fara valoare</span>';
    return (i ? '<div class="wkAnd">SI</div>' : '') + `<div class="wkCond${c.off ? ' off' : ''}${c.not ? ' neg' : ''}" data-cid="${c.id}">
      <span class="wkNum">${i + 1}</span>
      <select data-k="field">${fe}</select>
      <select data-k="op">${ops}</select>
      <button type="button" class="wkNot${c.not ? ' on' : ''}" data-k="not" title="Excludere: pastreaza cererile care NU se potrivesc">NU</button>
      <div class="wkVals">${wkRenderVals(c)}</div>
      ${cnt}
      <div class="wkCtl"><button type="button" data-k="off" title="${c.off ? 'Activeaza' : 'Dezactiveaza temporar'}">${c.off ? '&#9711;' : '&#9673;'}</button><button type="button" data-k="del" title="Sterge conditia">&times;</button></div>
    </div>`;
  }).join('');
}
function wkRenderVals(c) {
  if (c.op === 'empty') return '<span class="wkBigSub">fara valoare -- UA lipsa sau "-"</span>';
  if (c.op === 'range') {
    const ph = c.field === 'hour' ? ['0', '23'] : ['min', 'max'];
    return `<div class="wkRange"><input type="number" data-k="r0" data-wkfocus="r0_${c.id}" placeholder="${ph[0]}" value="${c.values[0] ?? ''}"> &ndash; <input type="number" data-k="r1" data-wkfocus="r1_${c.id}" placeholder="${ph[1]}" value="${c.values[1] ?? ''}">${c.field === 'hour' ? '<span>ora din fusul logului; 22-5 = peste noapte</span>' : ''}</div>`;
  }
  if (c.op === 'has') {
    const v = c.values[0] || 'da';
    return `<select data-k="has"><option value="da"${v === 'da' ? ' selected' : ''}>da, are query string</option><option value="nu"${v === 'nu' ? ' selected' : ''}>nu are query string</option></select>`;
  }
  const chips = c.values.map((v, j) => (j ? '<span class="wkOr">sau</span>' : '') + `<span class="wkChip" title="${esc(v)}"><span>${esc(wkLabel(c.field, v))}</span><button type="button" data-k="rm" data-j="${j}">&times;</button></span>`).join('');
  const known = WK.meta.values[c.field];
  if (c.op === 'in' && known && c.field !== 'country') {
    const opts = known.filter(v => !c.values.includes(String(v))).map(v => `<option value="${esc(v)}">${esc(wkLabel(c.field, v))}</option>`).join('');
    const extra = c.field === 'status' ? ['1xx', '2xx', '3xx', '4xx', '5xx'].filter(v => !c.values.includes(v)).map(v => `<option value="${v}">clasa ${v}</option>`).join('') : '';
    return chips + `<select data-k="pick" style="width:auto;max-width:220px"><option value="">+ adauga...</option>${extra}${opts}</select>`;
  }
  const dl = c.field === 'country' ? `<datalist id="wkDl${c.id}"><option value="__NON_RO__">non-RO</option>${(known || []).map(v => `<option value="${esc(v)}">`).join('')}</datalist>` : '';
  const ph = c.op === 'regex' ? 'expresie regulata (fara majuscule)' : c.op === 'cidr' ? '86.124.0.0/16' : (WK_PH[c.field] || 'valoare');
  return chips + `<input class="wkIn" data-k="txt" data-wkfocus="t_${c.id}" ${dl ? `list="wkDl${c.id}"` : ''} placeholder="${esc(ph)} + Enter">${dl}`;
}
function wkRenderPresets() {
  const saved = WK_SAVED.list();
  let h = WK_PRESETS.map(([g, list], gi) => `<div class="wkPresetGrp"><div class="wkAddLbl">${esc(g)}</div><div class="wkPresets">${list.map((p, pi) => `<button type="button" class="wkPreset" data-wkp="${gi}|${pi}">${esc(p[0])}</button>`).join('')}</div></div>`).join('');
  h += `<div class="wkPresetGrp"><div class="wkAddLbl">Salvate in acest browser</div><div class="wkPresets">${saved.length ? saved.map((p, i) => `<button type="button" class="wkPreset saved" data-wks="${i}" title="${esc(wkDescribe(p.conds))}">${esc(p.name)}<span class="x" data-wksx="${i}" title="Sterge">&times;</span></button>`).join('') : '<span class="wkBigSub">niciunul -- construieste conditiile si apasa "Salveaza ca preset"</span>'}</div></div>`;
  return h;
}
function wkDescribe(conds) {
  return (conds || []).map(c => `${c.not ? 'NU ' : ''}${wkFieldLabel(c.field)} ${WK_OPS[c.op] || c.op} ${c.op === 'range' ? (c.values[0] ?? '') + '-' + (c.values[1] ?? '') : (c.values || []).map(v => wkLabel(c.field, v)).join(' | ')}`).join('  SI  ');
}
function wkPct(a, b) { return b ? (100 * a / b).toFixed(a / b < 0.01 ? 2 : 1) + '%' : '0%'; }
function wkRenderResults() {
  const r = WK.res;
  if (!r) return '<div class="wkEmpty"><span class="spinner"></span> Se calculeaza...</div>';
  const pct = r.period_total ? (100 * r.total / r.period_total) : 0;
  const head = `<div class="wkStats">
      <div><div class="wkBig">${fmtNum(r.total)}</div><div class="wkBigSub">cereri potrivite din ${fmtNum(r.period_total)} in perioada (${wkPct(r.total, r.period_total)})</div></div>
      <div class="wkStat"><b>${fmtNum(r.unique_ips)}</b> IP-uri</div>
      <div class="wkStat"><b>${fmtNum(r.unique_paths)}</b> URL-uri</div>
      <div class="wkStat"><b>${fmtNum(r.unique_uas)}</b> User-Agent-uri</div>
      <div class="wkStat"><b>${fmtBytes(r.bytes)}</b> trafic</div>
      ${r.ts_min != null ? `<div class="wkStat">${esc(fmtRange(r.ts_min, r.ts_max))}</div>` : ''}
    </div>
    <div class="wkPctBar"><i style="width:${Math.max(pct, r.total ? 0.4 : 0).toFixed(2)}%"></i></div>
    ${WK.meta.fp_suppressed && WK.meta.fp_suppressed.events ? `<div class="wkFpNote">&#10003; ${fmtNum(WK.meta.fp_suppressed.events)} evenimente de la ${fmtNum(WK.meta.fp_suppressed.ips)} crawlere verificate DNS au fost retrogradate la INFO (fals pozitive).</div>` : ''}
    <div class="wkActions">
      <div class="wkSeg"><button type="button" data-wkview="table" class="${WK.view === 'table' ? 'on' : ''}">Tabel</button><button type="button" data-wkview="raw" class="${WK.view === 'raw' ? 'on' : ''}">Linii brute</button></div>
      <select id="wkSort"><option value="ts_desc"${WK.sort === 'ts_desc' ? ' selected' : ''}>cele mai noi</option><option value="ts_asc"${WK.sort === 'ts_asc' ? ' selected' : ''}>cele mai vechi</option><option value="size_desc"${WK.sort === 'size_desc' ? ' selected' : ''}>cele mai mari</option></select>
      <select id="wkLimit">${[50, 100, 250, 500, 1000].map(n => `<option value="${n}"${WK.limit === n ? ' selected' : ''}>${n} / pagina</option>`).join('')}</select>
      <div class="spacer"></div>
      <button class="ghost" id="wkCopyPage" ${r.rows.length ? '' : 'disabled'}>Copiaza pagina (${fmtNum(r.rows.length)})</button>
      <button class="ghost" id="wkCopyAll" ${r.total ? '' : 'disabled'} title="Copiaza in clipboard liniile brute ale TUTUROR cererilor potrivite (max 20.000)">Copiaza toate ${r.total > 20000 ? '(primele 20.000)' : '(' + fmtNum(r.total) + ')'}</button>
      <button class="ghost" id="wkDownload" ${r.total ? '' : 'disabled'}>Descarca .log (${fmtNum(r.total)})</button>
      <button class="ghost" id="wkCopyJson" title="Copiaza conditiile ca JSON (le poti lipi intr-un preset sau un ticket)">JSON</button>
      ${r.total ? ruleBtn(() => ({ q: wkQuery(), label: 'rezultatul din Workplace' }), 'Regulă de blocare', 'wkRuleBtn') : ''}
    </div>`;
  let body;
  if (!r.rows.length) body = '<div class="wkEmpty" style="margin-top:10px">Nicio cerere nu indeplineste toate conditiile. Uita-te la coloana "dupa ea" din stanga ca sa vezi care conditie elimina tot.</div>';
  else if (WK.view === 'raw') body = `<div class="wkScroll"><div class="wkRaw" id="wkRawBox">${r.rows.map((x, i) => `<div class="s${String(x.status)[0]}" data-wkraw="${i}" title="click = copiaza linia">${esc(x.raw)}</div>`).join('')}</div></div>`;
  else body = `<div class="wkScroll"><table class="wkTable"><colgroup><col style="width:128px"><col style="width:150px"><col style="width:52px"><col><col style="width:50px"><col style="width:70px"><col style="width:26%"><col style="width:74px"></colgroup>
    <thead><tr><th>Timp</th><th>IP / tara</th><th>Metoda</th><th>URL</th><th>Cod</th><th class="num">Marime</th><th>User-Agent</th><th>Sev.</th></tr></thead><tbody>
    ${r.rows.map((x, i) => `<tr data-wkrow="${i}">
      <td class="mono clk" data-wkcell="open" title="Detaliul cererii">${esc(epochToDtLocal(x.ts, TRIAGE.tzOffset).replace('T', ' '))}</td>
      <td class="mono clk" data-wkcell="ip" title="Filtreaza pe acest IP">${esc(x.ip)} <span class="wkPill">${esc(x.country)}</span></td>
      <td class="mono clk" data-wkcell="method">${esc(x.method)}</td>
      <td class="mono clk" data-wkcell="path" title="${esc(x.path)}">${esc(x.path)}</td>
      <td class="clk" data-wkcell="status"><span class="wkPill c${String(x.status)[0]}">${x.status}</span></td>
      <td class="num mono">${fmtBytes(x.size)}</td>
      <td class="mono clk" data-wkcell="ua" title="${esc(x.ua)}">${x.crawler !== 'none' ? `<span class="wkPill ${x.crawler}">${esc(wkLabel('crawler', x.crawler))}</span> ` : ''}${esc(x.ua || '-')}</td>
      <td class="clk" data-wkcell="severity"><span class="wkPill ${esc(x.severity)}">${esc(x.severity)}</span></td>
    </tr>${WK.open[i] ? `<tr class="wkRawRow"><td colspan="8">${esc(x.raw)}  <button class="ghost" data-wkcopy="${i}" style="font-size:11px;padding:1px 6px">copiaza</button></td></tr>` : ''}`).join('')}
    </tbody></table></div>`;
  const pages = Math.max(1, Math.ceil(r.total / WK.limit));
  const pg = Math.floor(WK.offset / WK.limit) + 1;
  const pager = r.total > WK.limit ? `<div class="wkPager"><button class="ghost" data-wkpg="-1" ${pg <= 1 ? 'disabled' : ''}>&lsaquo; inapoi</button>pagina ${fmtNum(pg)} din ${fmtNum(pages)}<button class="ghost" data-wkpg="1" ${pg >= pages ? 'disabled' : ''}>inainte &rsaquo;</button></div>` : '';
  return head + body + pager + (WK.view === 'table' && r.rows.length ? '<div class="wkBigSub" style="margin-top:6px">Click pe IP / URL / cod / UA / severitate = adauga conditia. Alt+click = exclude. Click pe ora = detaliul cererii; dublu-click pe rand = linia bruta.</div>' : '');
}
const WK_FACETS = [
  ['ua_cat', 'Categorie User-Agent'], ['crawler', 'Crawler (verificare DNS)'], ['status', 'Cod HTTP'], ['method', 'Metoda'],
  ['severity', 'Severitate'], ['country', 'Tara'], ['ext', 'Tip fisier'], ['query', 'Query string'], ['action', 'Actiune / regula'],
  ['ip', 'Top IP-uri', 1], ['path_only', 'Top URL-uri', 1], ['ua', 'Top User-Agent-uri', 1],
];
function wkRenderFacets() {
  const r = WK.res;
  if (!r || !r.total) return '<div class="wkFacet"><h4>Fatete</h4><div class="wkBigSub">Apar dupa ce selectia are cereri.</div></div>';
  const F = r.facets || {};
  let h = '';
  for (const [k, title, mono] of WK_FACETS) {
    const list = (F[k] || []).filter(x => x.n);
    if (!list.length) continue;
    const max = Math.max(...list.map(x => x.n));
    h += `<div class="wkFacet"><h4>${esc(title)} <em>${list.length}${list.length >= 12 ? '+' : ''} valori</em></h4>${list.map(x => `
      <div class="wkFi"><span class="bar" style="width:${(100 * x.n / max).toFixed(1)}%"></span>
        <span class="lab${mono ? ' mono' : ''}" data-wkf="${k}" data-v="${esc(x.value)}" title="${esc(x.value)} -- click = doar acestea">${k === 'country' ? flagHtml(x.value) : ''}${esc(wkLabel(k, x.value) || '(gol)')}</span>
        <span class="n">${fmtNum(x.n)} <span class="wkBigSub">${wkPct(x.n, r.total)}</span></span>
        <span class="bt"><button type="button" data-wkf="${k}" data-v="${esc(x.value)}" title="Include">+</button><button type="button" class="ex" data-wkf="${k}" data-v="${esc(x.value)}" data-ex="1" title="Exclude">&minus;</button></span>
      </div>`).join('')}</div>`;
  }
  const hrs = F.hour || [];
  if (hrs.length) {
    const max = Math.max(1, ...hrs.map(x => x.n));
    h += `<div class="wkFacet"><h4>Ore (fusul logului) <em>click = doar ora</em></h4><div class="wkHours">${hrs.map(x => `<div data-wkhour="${x.value}" style="height:${(100 * x.n / max).toFixed(1)}%" title="${x.value}:00 - ${fmtNum(x.n)} cereri"></div>`).join('')}</div><div class="wkHoursLbl">${hrs.map(x => `<span>${x.value % 3 ? '' : x.value}</span>`).join('')}</div></div>`;
  }
  const wd = (F.weekday || []).filter(x => x.n);
  if (wd.length) {
    const max = Math.max(...wd.map(x => x.n));
    h += `<div class="wkFacet"><h4>Zile</h4>${wd.map(x => `<div class="wkFi"><span class="bar" style="width:${(100 * x.n / max).toFixed(1)}%"></span><span class="lab" data-wkf="weekday" data-v="${x.value}">${x.value}</span><span class="n">${fmtNum(x.n)}</span><span class="bt"><button type="button" data-wkf="weekday" data-v="${x.value}">+</button><button type="button" class="ex" data-wkf="weekday" data-v="${x.value}" data-ex="1">&minus;</button></span></div>`).join('')}</div>`;
  }
  return h;
}

// ---------------------------------------------------------------- actiuni
function wkCond(id) { return WK.conds.find(c => c.id === +id); }
function wkAddValue(field, value, exclude) {
  const opMap = { ip: 'in', path_only: 'exact', ua: 'exact', query: 'has' };
  const op = opMap[field] || 'in';
  value = String(value);
  if (field === 'ua' && !value) { WK.conds.push(wkMkCond({ field: 'ua', op: 'empty', values: [], not: !!exclude })); wkRender(); wkSchedule(); return; }
  if (field === 'query') value = value === 'da' ? 'da' : 'nu';
  let c = WK.conds.find(x => x.field === field && x.op === op && x.not === !!exclude && !x.off);
  if (c && op !== 'has') { if (!c.values.includes(value)) c.values.push(value); }
  else WK.conds.push(wkMkCond({ field, op, values: [value], not: !!exclude }));
  wkRender(); wkSchedule();
}
// Ghid: ce face fiecare filtru, cu exemple concrete aplicabile dintr-un click.
const WK_GUIDE = [
  ['IP exact / Subnet / IP începe cu', 'Selectează cererile unuia sau mai multor IP-uri. Subnetul primește notație CIDR, IP-ul „începe cu” un prefix.',
    [['Un singur IP', [C('ip', 'in', ['185.191.171.1'])], 'IP exact = 185.191.171.1'],
     ['Un subnet /24', [C('ip', 'cidr', ['185.191.171.0/24'])], 'Subnet = 185.191.171.0/24'],
     ['Toate IP-urile 66.249.*', [C('ip', 'prefix', ['66.249.'])], 'IP începe cu = 66.249.']]],
  ['Furnizor (ASN)', 'Rețeaua căreia îi aparține IP-ul (operator de internet sau cloud), din baza GeoLite2 ASN. Grupează mii de IP-uri diferite care vin din aceeași rețea.',
    [['Tot traficul din Amazon', [C('asn', 'contains', ['amazon'])], 'Furnizor conține amazon'],
     ['Google, fără crawlerele verificate', [C('asn', 'contains', ['google']), C('crawler', 'in', ['verified'], true)], 'Furnizor conține google + NU Crawler = verificat']]],
  ['Țară', 'Țara IP-ului din GeoIP. „Non-RO” = orice țară determinată în afară de România; „??” = nedeterminată (IP privat sau absent din bază).',
    [['Doar din afara României', [C('country', 'in', ['__NON_RO__'])], 'Țară = non-RO'],
     ['Exclude România și SUA', [C('country', 'in', ['RO', 'US'], true)], 'NU Țară = RO, US']]],
  ['Metodă HTTP', 'GET, POST, HEAD... POST-urile sunt de obicei formulare, login-uri sau API-uri.',
    [['Doar POST', [C('method', 'in', ['POST'])], 'Metodă = POST'],
     ['POST pe wp-login.php', [C('method', 'in', ['POST']), C('path_only', 'suffix', ['wp-login.php'])], 'Metodă = POST + URL se termină cu wp-login.php']]],
  ['URL conține / regex / exact / începe cu / se termină cu', '„URL” include query string-ul (?a=1), „URL fără query” doar calea. Regex-ul nu ține cont de majuscule.',
    [['Tot ce atinge /wp-admin/', [C('path_only', 'prefix', ['/wp-admin/'])], 'URL fără query începe cu /wp-admin/'],
     ['Pagini de produs', [C('path_only', 'regex', ['^/produs/'])], 'URL fără query regex ^/produs/'],
     ['Fișiere .sql / .zip / .bak', [C('path_only', 'regex', ['\\.(sql|zip|bak|tar|gz)$'])], 'regex \\.(sql|zip|bak|tar|gz)$']]],
  ['Extensie fișier', 'Grupează cererile după tipul fișierului: php, js, css, img, font, html, arhivă, media, „fara” (pagini fără extensie).',
    [['Fără assets statice', [C('ext', 'in', ['img', 'js', 'css', 'font', 'media'], true)], 'NU Extensie = img, js, css, font, media'],
     ['Doar scripturi PHP', [C('ext', 'in', ['php'])], 'Extensie = php']]],
  ['Query string / Parametru în query', '„Are query string” = URL-uri cu „?”. „Parametru” caută un nume anume (ex. filter_culoare), oricare ar fi valoarea.',
    [['Doar URL-uri cu parametri', [C('query', 'has', ['da'])], 'Are query string = da'],
     ['Parametrul s (căutare WP)', [C('query', 'param', ['s'])], 'Parametru = s']]],
  ['Cod / clasă HTTP', 'Un cod exact (404) sau o clasă întreagă (4xx, 5xx).',
    [['Erori de server', [C('status', 'in', ['5xx'])], 'Cod = 5xx'],
     ['Blocate (403 / 429)', [C('status', 'in', ['403', '429'])], 'Cod = 403, 429']]],
  ['Mărime răspuns (B)', 'Interval în bytes: minim și/sau maxim. Util pentru descărcări mari sau răspunsuri goale.',
    [['Peste 1 MB', [C('size', 'range', [1048576, null])], 'Mărime ≥ 1048576'],
     ['Răspunsuri goale', [C('size', 'range', [0, 0])], 'Mărime între 0 și 0']]],
  ['User-Agent conține / exact / regex / gol', 'Textul User-Agent-ului trimis de client. Mai multe valori în aceeași condiție = SAU.',
    [['Facebook / Meta', [C('ua', 'contains', ['facebookexternalhit', 'meta-externalagent'])], 'UA conține facebookexternalhit SAU meta-externalagent'],
     ['Fără User-Agent', [C('ua', 'empty', [])], 'UA gol / „-”'],
     ['Exclude Googlebot', [C('ua', 'contains', ['googlebot'], true)], 'NU UA conține googlebot']]],
  ['Categorie UA', 'Clasificarea automată a User-Agent-ului: browser, motor de căutare, AI crawler, SEO, social, script/tool, automatizare suspectă.',
    [['AI crawlere (GPTBot, ClaudeBot...)', [C('ua_cat', 'in', ['AI crawler'])], 'Categorie = AI crawler'],
     ['Scripturi și unelte', [C('ua_cat', 'in', ['Script/tool'])], 'Categorie = Script / tool']]],
  ['Crawler verificat DNS', 'Pentru UA-urile care pretind că sunt Googlebot, Bingbot etc.: „verificat” = IP confirmat prin DNS, „fals” = IP-ul nu aparține motorului.',
    [['Googlebot fals', [C('ua', 'contains', ['googlebot']), C('crawler', 'in', ['fake'])], 'UA conține googlebot + Crawler = fals'],
     ['Exclude crawlerele legitime', [C('crawler', 'in', ['verified'], true)], 'NU Crawler = verificat']]],
  ['Severitate / Acțiune / Zonă WordPress', 'Rezultatul motorului de detecție pe fiecare cerere (tip atac, login, webshell) și zona WordPress atinsă.',
    [['Doar CRITICAL', [C('severity', 'in', ['CRITICAL'])], 'Severitate = CRITICAL'],
     ['SQLi / LFI / XSS', [C('action', 'in', WK_PATTERN_ACTIONS)], 'Acțiune = tipare de atac'],
     ['wp-admin din afara RO', [C('wp', 'in', ['wp_admin']), C('country', 'in', ['__NON_RO__'])], 'Zonă WP = wp-admin + Țară = non-RO']]],
  ['Interval orar / Zi din săptămână', 'Ora din fusul orar al logului. Un interval inversat (22-5) trece peste miezul nopții.',
    [['Noaptea (00-05)', [C('hour', 'range', [0, 5])], 'Ora între 0 și 5'],
     ['Weekend', [C('weekday', 'in', ['Sa', 'Du'])], 'Zi = Sa, Du']]],
  ['Cereri / URL-uri unice per IP', 'Calculate pe ce a rămas după condițiile de deasupra: câte cereri și câte URL-uri diferite are fiecare IP.',
    [['IP-uri cu 300+ cereri', [C('ip_hits', 'range', [300, null])], 'Cereri / IP ≥ 300'],
     ['Crawling: 150+ URL-uri unice', [C('ip_paths', 'range', [150, null])], 'URL-uri unice / IP ≥ 150']]],
  ['Vârf cereri / minut per IP', 'Cel mai mare număr de cereri făcute de IP într-un singur minut. Un om nu trece de 20-30 pe minut; peste 60 e aproape sigur automat.',
    [['Rafale de 60+ / minut', [C('ip_rpm', 'range', [60, null])], 'Vârf ≥ 60 / minut'],
     ['Rafale pe login', [C('path_only', 'suffix', ['wp-login.php']), C('ip_rpm', 'range', [10, null])], 'wp-login.php + vârf ≥ 10 / minut']]],
  ['% erori 4xx per IP', 'Procentul răspunsurilor 4xx (404, 403...) din cererile IP-ului. Scannerele care ghicesc fișiere au peste 50%.',
    [['Scannere de fișiere', [C('ip_err', 'range', [50, null]), C('ip_hits', 'range', [30, null])], '% erori ≥ 50 + cereri ≥ 30'],
     ['Doar 404 la 100%', [C('ip_err', 'range', [100, 100])], '% erori = 100']]],
  ['User-Agent-uri diferite per IP', 'Câte UA-uri distincte trimite același IP. Boții care se ascund rotesc UA-ul la fiecare cerere.',
    [['Rotație de UA (5+)', [C('ip_uas', 'range', [5, null])], 'UA-uri / IP ≥ 5']]],
  ['Cereri per subnet', 'Cererile însumate ale subnetului (/24 la IPv4, /64 la IPv6). Prinde atacurile împărțite pe multe IP-uri din aceeași rețea.',
    [['Subnet cu 500+ cereri, IP-uri mici', [C('subnet_hits', 'range', [500, null]), C('ip_hits', 'range', [null, 50])], 'Subnet ≥ 500 + cereri / IP ≤ 50']]],
];
function wkRenderGuide() {
  return `<details class="wkCard wkGuide" id="wkGuide"${WK.guideOpen ? ' open' : ''}>
    <summary><h3>Ghid: cum folosești fiecare filtru</h3><span class="wkSub">exemple concrete &middot; „Aplică” înlocuiește condițiile, Shift+click le adaugă</span></summary>
    <div class="wkGuideGrid">${WK_GUIDE.map(([t, d, exs], gi) => `<div class="wkGuideItem"><div class="wkGuideT">${esc(t)}</div><div class="wkGuideD">${esc(d)}</div>
      ${exs.map(([lbl, , how], ei) => `<div class="wkGuideEx"><button type="button" class="wkPreset" data-wkex="${gi}|${ei}">Aplică</button><span><b>${esc(lbl)}</b> <code>${esc(how)}</code></span></div>`).join('')}</div>`).join('')}</div>
  </details>`;
}
function wkApplyPreset(conds, append, focus) {
  const nc = conds.map(wkMkCond);
  WK.conds = append ? WK.conds.concat(nc) : nc;
  wkRender();
  if (focus) { const last = nc[nc.length - 1]; const el = document.querySelector(`[data-wkfocus="t_${last.id}"]`); if (el) el.focus(); }
  wkSchedule();
}
function wkFetchRaw(limit) {
  return fetch(`/api/dataset/${DATASET_ID}/workplace/raw`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ q: wkQuery(), limit: limit || null, filename: 'workplace' }) });
}
function wkInit() {
  const root = $('#wkMod');
  if (!root || root._wk) return;
  root._wk = true;
  root.addEventListener('change', (e) => {
    const t = e.target;
    if (t.id === 'wkPeriodSel') {
      WK.period = t.value;
      if (WK.period === 'custom' && WK.from == null) { WK.from = TRIAGE.tsFrom ?? TRIAGE.boundsFrom; WK.to = TRIAGE.tsTo ?? TRIAGE.boundsTo; }
      wkRender(); wkSchedule(); return;
    }
    if (t.id === 'wkFrom' || t.id === 'wkTo') { const v = dtLocalToEpoch(t.value, TRIAGE.tzOffset); if (t.id === 'wkFrom') WK.from = v; else WK.to = v; wkSchedule(); return; }
    if (t.id === 'wkSort') { WK.sort = t.value; wkSchedule(); return; }
    if (t.id === 'wkLimit') { WK.limit = +t.value; wkSchedule(); return; }
    const row = t.closest('[data-cid]');
    if (!row) return;
    const c = wkCond(row.dataset.cid);
    const k = t.dataset.k;
    if (k === 'field') { c.field = t.value; const ops = wkOpsFor(c.field); if (!ops.includes(c.op)) c.op = ops[0]; c.values = []; }
    else if (k === 'op') { const wasR = c.op === 'range'; c.op = t.value; if (wasR !== (c.op === 'range') || c.op === 'has' || c.op === 'empty') c.values = []; }
    else if (k === 'pick') { if (t.value && !c.values.includes(t.value)) c.values.push(t.value); }
    else if (k === 'has') c.values = [t.value];
    else if (k === 'r0' || k === 'r1') { const v = c.values.slice(0, 2); while (v.length < 2) v.push(null); v[k === 'r0' ? 0 : 1] = t.value === '' ? null : +t.value; c.values = v; wkSchedule(); return; }
    else if (k === 'txt') { wkCommitText(t, c); return; }
    wkRender(); wkSchedule();
  });
  root.addEventListener('keydown', (e) => {
    const t = e.target;
    if (t.id === 'wkUaQuick' && e.key === 'Enter') { e.preventDefault(); wkUaQuick('contains'); return; }
    if (t.dataset.k === 'txt' && (e.key === 'Enter' || (e.key === ',' && t.closest('[data-cid]') && wkCond(t.closest('[data-cid]').dataset.cid).op !== 'regex'))) {
      e.preventDefault(); wkCommitText(t, wkCond(t.closest('[data-cid]').dataset.cid));
    } else if (t.dataset.k === 'txt' && e.key === 'Backspace' && !t.value) {
      const c = wkCond(t.closest('[data-cid]').dataset.cid); if (c.values.length) { c.values.pop(); wkRender(); wkSchedule(); }
    }
  });
  root.addEventListener('toggle', (e) => {
    if (e.target.id !== 'wkGuide') return;
    WK.guideOpen = e.target.open;
    try { localStorage.setItem('logscan.wk.guide', WK.guideOpen ? '1' : '0'); } catch (err) {}
  }, true);
  root.addEventListener('click', async (e) => {
    const t = e.target.closest('button, [data-wkf], [data-wkcell], [data-wkraw], [data-wkhour], .wkPreset .x');
    if (!t) return;
    if (t.dataset.wksx != null) { e.stopPropagation(); const l = WK_SAVED.list(); const p = l.splice(+t.dataset.wksx, 1)[0]; WK_SAVED.save(l); toast('Preset sters: ' + (p && p.name)); wkRender(); return; }
    if (t.dataset.wkadd) { const [f, o] = t.dataset.wkadd.split('|'); const c = wkMkCond({ field: f, op: o, values: o === 'has' ? ['da'] : [] }); WK.conds.push(c); wkRender();
      const el = document.querySelector(`[data-wkfocus="t_${c.id}"], [data-wkfocus="r0_${c.id}"]`); if (el) el.focus(); else if (o === 'has' || o === 'empty') wkSchedule(); return; }
    if (t.dataset.wkex) { const [g, x] = t.dataset.wkex.split('|').map(Number); const ex = WK_GUIDE[g][2][x]; wkApplyPreset(ex[1], e.shiftKey); toast('Exemplu: ' + ex[0]); window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
    if (t.dataset.wkp) { const [g, p] = t.dataset.wkp.split('|').map(Number); const pr = WK_PRESETS[g][1][p]; wkApplyPreset(pr[1], e.shiftKey, pr[2] === 'focus'); toast('Preset: ' + pr[0]); return; }
    if (t.dataset.wks != null) { const p = WK_SAVED.list()[+t.dataset.wks]; if (p) { wkApplyPreset(p.conds, e.shiftKey); if (p.period) { WK.period = p.period; } toast('Preset: ' + p.name); } return; }
    if (t.dataset.wkua) { wkUaQuick(t.dataset.wkua); return; }
    if (t.dataset.wkview) { WK.view = t.dataset.wkview; $('#wkResults').innerHTML = wkRenderResults(); return; }
    if (t.dataset.wkpg) { WK.offset = Math.max(0, WK.offset + (+t.dataset.wkpg) * WK.limit); WK.open = {}; wkSchedule(false); return; }
    if (t.dataset.wkf) { if (e.target.closest('.lab') && !e.altKey) { WK.conds = WK.conds.filter(c => !(c.field === t.dataset.wkf && !c.not)); } wkAddValue(t.dataset.wkf, t.dataset.v, t.dataset.ex === '1' || e.altKey); return; }
    if (t.dataset.wkhour != null) { WK.conds = WK.conds.filter(c => c.field !== 'hour'); WK.conds.push(wkMkCond({ field: 'hour', op: 'range', values: [+t.dataset.wkhour, +t.dataset.wkhour] })); wkRender(); wkSchedule(); return; }
    if (t.dataset.wkraw != null) { copyText(WK.res.rows[+t.dataset.wkraw].raw); return; }
    if (t.dataset.wkcopy != null) { copyText(WK.res.rows[+t.dataset.wkcopy].raw); return; }
    if (t.dataset.wkcell) {
      const i = +t.closest('[data-wkrow]').dataset.wkrow, x = WK.res.rows[i];
      const cell = t.dataset.wkcell;
      if (cell === 'open') { const list = { rows: WK.res.rows, total: WK.res.rows.length, done: true, label: 'Workplace', more: null }; XP.openEvent(list, i); return; }
      const map = { ip: ['ip', x.ip], method: ['method', x.method], path: ['path_only', x.path.split('?')[0]], status: ['status', String(x.status)], ua: ['ua', x.ua], severity: ['severity', x.severity] };
      const [f, v] = map[cell]; wkAddValue(f, v, e.altKey); return;
    }
    const id = t.id;
    if (id === 'wkClear') { WK.conds = []; wkRender(); wkSchedule(); return; }
    if (id === 'wkSavePreset') {
      const name = prompt('Nume pentru preset (conditiile curente):', wkDescribe(WK.conds).slice(0, 60));
      if (!name) return;
      const l = WK_SAVED.list().filter(p => p.name !== name);
      l.push({ name, conds: wkQuery().conds.filter(c => !c.off) });
      if (WK_SAVED.save(l)) { toast('Preset salvat: ' + name); wkRender(); }
      return;
    }
    if (id === 'wkToGlobal') { if (WK.from != null && WK.to != null) { triageSetRange(WK.from, WK.to); WK.period = 'global'; wkRender(); wkSchedule(); toast('Perioada aplicata in toata aplicatia'); } return; }
    if (id === 'wkCopyJson') { copyText(JSON.stringify(wkQuery(), null, 1)); return; }
    if (id === 'wkCopyPage') { copyText(WK.res.rows.map(x => x.raw).join('\n')); return; }
    if (id === 'wkCopyAll') {
      t.disabled = true; const old = t.textContent; t.textContent = 'se copiaza...';
      try { const r = await wkFetchRaw(20000); if (!r.ok) throw new Error((await r.json()).error); const txt = await r.text(); copyText(txt.replace(/\n$/, '')); toast(`${fmtNum(+(r.headers.get('X-Lines') || 0))} linii brute copiate`); }
      catch (err) { showError('Copiere esuata: ' + err.message); } finally { t.disabled = false; t.textContent = old; }
      return;
    }
    if (id === 'wkDownload') {
      t.disabled = true;
      try { const r = await wkFetchRaw(null); if (!r.ok) throw new Error((await r.json()).error); const b = await r.blob(); const a = document.createElement('a');
        a.href = URL.createObjectURL(b); a.download = 'workplace_' + ((CURRENT_SUMMARY && CURRENT_SUMMARY.filename) || DATASET_ID).replace(/[^A-Za-z0-9._-]+/g, '_') + '.log'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); }
      catch (err) { showError('Descarcare esuata: ' + err.message); } finally { t.disabled = false; }
      return;
    }
    const row = t.closest('[data-cid]');
    if (row) {
      const c = wkCond(row.dataset.cid), k = t.dataset.k;
      if (k === 'not') c.not = !c.not;
      else if (k === 'off') c.off = !c.off;
      else if (k === 'del') WK.conds = WK.conds.filter(x => x !== c);
      else if (k === 'rm') c.values.splice(+t.dataset.j, 1);
      else return;
      wkRender(); wkSchedule();
    }
  });
  root.addEventListener('dblclick', (e) => {
    const tr = e.target.closest('[data-wkrow]');
    if (!tr) return;
    const i = +tr.dataset.wkrow; WK.open[i] = !WK.open[i]; $('#wkResults').innerHTML = wkRenderResults();
  });
  root.addEventListener('focusout', (e) => {
    const t = e.target;
    if (t.dataset && t.dataset.k === 'txt' && t.value.trim()) { const row = t.closest('[data-cid]'); if (row) wkCommitText(t, wkCond(row.dataset.cid)); }
  });
}
function wkCommitText(input, c) {
  const raw = input.value;
  if (!raw.trim()) return;
  const parts = c.op === 'regex' ? [raw.trim()] : raw.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  parts.forEach(p => { if (!c.values.includes(p)) c.values.push(p); });
  input.value = '';
  wkRender();
  const el = document.querySelector(`[data-wkfocus="t_${c.id}"]`); if (el) el.focus();
  wkSchedule();
}
function wkUaQuick(mode) {
  const v = ($('#wkUaQuick').value || '').trim();
  if (!v) { $('#wkUaQuick').focus(); toast('Scrie intai un User-Agent'); return; }
  const op = mode === 'not' ? 'contains' : mode;
  const not = mode === 'not';
  // conditie NOUA (SI cu celelalte); pentru SAU adaugi valori in acelasi rand
  WK.conds.push(wkMkCond({ field: 'ua', op, values: [v], not }));
  $('#wkUaQuick').value = '';
  wkRender(); wkSchedule();
}
// deschidere din alte module: Workplace cu o conditie gata pusa
function wkOpenWith(conds) {
  WK.conds = (conds || []).map(wkMkCond);
  showPage('workplace');
}
MOD_HOOKS.workplace = async () => { wkInit(); if (!(await wkEnsureMeta())) { wkRender(); return; } wkRender(); wkRun(); };
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'workplace' && WK.period === 'global') wkSchedule(); });

// ===================== v47.2: Incidente - traseu cronologic =====================
// Regrupeaza pe IP datele existente (compromise_trail + severitate/label din
// index). Respecta selectia globala; se reincarca prin GF_LISTENERS.
const INC = { key: null, data: null, sel: null, only: 'all', trail: null, seq: 0, dseq: 0, stale: true };
function incFmtDt(s) {
  if (s == null) return '';
  if (s < 60) return '+' + s + 's';
  if (s < 3600) return '+' + Math.floor(s / 60) + 'm' + String(s % 60).padStart(2, '0') + 's';
  if (s < 86400) return '+' + Math.floor(s / 3600) + 'h' + String(Math.floor(s % 3600 / 60)).padStart(2, '0') + 'm';
  return '+' + Math.floor(s / 86400) + 'z' + Math.floor(s % 86400 / 3600) + 'h';
}
function incCode(st) { return `<span class="codePill c${String(st)[0]}">${tEsc(st)}</span>`; }
function incCat(x) { return x.dominant_category ? `<span class="catTag ${tEsc(x.dominant_category)}">${tEsc(x.dominant_category_label || x.dominant_category)}</span>` : '<span class="secHint">-</span>'; }
async function incLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready) return;
  const key = DATASET_ID + '|' + gfJSON();
  if (!force && key === INC.key && INC.data) return;
  INC.key = key; INC.stale = false;
  const seq = ++INC.seq;
  $('#incMsg').className = 'incMsg'; $('#incMsg').textContent = 'Se incarca incidentele din selectie...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/incidents`)); d = await r.json(); }
  catch (e) { if (seq === INC.seq) { $('#incMsg').className = 'incMsg err'; $('#incMsg').textContent = 'Eroare de retea: ' + e.message; } return; }
  if (seq !== INC.seq) return;
  if (!r.ok) { INC.data = null; $('#incBody').innerHTML = ''; $('#incCount').textContent = ''; $('#incMsg').className = 'incMsg err'; $('#incMsg').textContent = d.error || ('HTTP ' + r.status); $('#incDetail').hidden = true; return; }
  INC.data = d.incidents || [];
  INC.adminOnly = d.admin_only_total || 0; INC.adminOnlyBy = d.admin_only || {};
  $('#incCount').textContent = `(${fmtN(d.total || 0)})`;
  incRenderTable();
  if (INC.sel && INC.data.some(x => x.ip === INC.sel)) incOpen(INC.sel, true);
  else { INC.sel = null; $('#incDetail').hidden = true; }
}
function incRenderTable() {
  const q = ($('#incSearch').value || '').trim();
  const cov = (typeof admCoveredIps === 'function') ? admCoveredIps() : new Set();
  // v49.1: in tabelul de incidente raman DOAR atacurile: IP-uri cu un eveniment
  // CRITICAL/HIGH care nu tine de autentificare, sau cu traseu de tip atac /
  // compromitere. Login-urile (reusite sau nu) si accesele admin sunt in
  // "Acces WP admin".
  // v49.1: separarea atac / doar-admin vine din backend (aceeasi clasificare ca "Acces WP admin").
  const rows = (INC.data || []).filter(x => !q || x.ip.includes(q));
  $('#incMsg').className = 'incMsg';
  $('#incMsg').textContent = !(INC.data || []).length
    ? 'Niciun atac (IP cu semnale CRITICAL/HIGH in afara autentificarii, sau din traseul de compromitere) in selectia curenta.'
    : (!rows.length ? `Niciun IP nu contine "${q}".` : '');
  if (INC.adminOnly) {
    const b = INC.adminOnlyBy, parts = [];
    if (b.login) parts.push(`${fmtN(b.login)} cu login confirmat`);
    if (b.sesiune) parts.push(`${fmtN(b.sesiune)} cu sesiune autentificata`);
    if (b.neconfirmat) parts.push(`${fmtN(b.neconfirmat)} cu acces neconfirmat`);
    if (b.incercari) parts.push(`${fmtN(b.incercari)} doar cu incercari de login`);
    $('#incMsg').textContent += ($('#incMsg').textContent ? ' ' : '') + `Alte ${fmtN(INC.adminOnly)} IP-uri au doar semnale de autentificare (${parts.join(', ')}) -- nu sunt numarate aici, sunt in rubrica "Acces WP admin".`;
  }
  $('#incBody').innerHTML = rows.map(x => {
    const f = x.first_significant;
    const first = f ? `<div class="incFirst"><span class="t">${tEsc(fmtEpoch(f.ts))}</span><span>${tEsc(f.label || f.action_type)}</span></div>` : '<span class="secHint">fara CRITICAL/HIGH in selectie</span>';
    const p = x.posts_after || {};
    const posts = f ? `<span class="incPosts"><span class="codePill c2">2xx <b>${fmtN(p['2xx'])}</b></span><span class="codePill c4">4xx <b>${fmtN(p['4xx'])}</b></span></span>` : '-';
    return `<tr data-ip="${tEscAttr(x.ip)}" class="${x.ip === INC.sel ? 'sel' : ''}">
      <td><span class="incIp">${tEsc(x.ip)}</span></td><td>${tEsc(x.country || '??')}</td><td>${incCat(x)}</td>
      <td>${first}</td><td class="num">${f ? fmtN(x.after) : '-'}</td><td>${posts}</td>
      <td><span class="tag ${tEsc(x.max_severity)}">${tEsc(x.max_severity)}</span></td></tr>`;
  }).join('');
}
async function incOpen(ip, keepScroll) {
  INC.sel = ip;
  document.querySelectorAll('#incBody tr').forEach(tr => tr.classList.toggle('sel', tr.dataset.ip === ip));
  const box = $('#incDetail'); box.hidden = false;
  if (!keepScroll) box.innerHTML = '<div class="incNote">Se incarca cronologia IP-ului...</div>';
  const seq = ++INC.dseq;
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/ip_trail?ip=${encodeURIComponent(ip)}&only=${INC.only}&limit=5000`)); d = await r.json(); }
  catch (e) { if (seq === INC.dseq) box.innerHTML = `<div class="incMsg err">Eroare de retea: ${tEsc(e.message)}</div>`; return; }
  if (seq !== INC.dseq) return;
  if (!r.ok) { box.innerHTML = `<div class="incMsg err">${tEsc(d.error || ('HTTP ' + r.status))}</div>`; return; }
  INC.trail = d;
  incRenderDetail(keepScroll);
}
function incRenderDetail(keepScroll) {
  const d = INC.trail, box = $('#incDetail');
  const scroll = keepScroll && box.querySelector('.incTl') ? box.querySelector('.incTl').scrollTop : 0;
  const summ = Array.isArray(d.trail_summary) ? d.trail_summary.join(' ') : (d.trail_summary || '');
  const uas = (d.user_agents || []).slice(0, 6);
  const sigIdx = d.events.findIndex(e => e.first_significant);
  let html = `<div class="incDTitle"><span class="incIp">${tEsc(d.ip)}</span>${incCat(d)}${d.risk_score != null ? `<span class="secHint">risk score ${tEsc(d.risk_score)}</span>` : ''}</div>
    <div class="incDHead">
      <div><div class="k">Tara</div><div class="v">${tEsc(d.country || '??')}</div></div>
      <div><div class="k">Interval</div><div class="v">${tEsc(fmtEpoch(d.first_ts))} &ndash; ${tEsc(fmtEpoch(d.last_ts))}</div></div>
      <div><div class="k">Cereri in selectie</div><div class="v">${fmtN(d.total)}</div></div>
      <div><div class="k">User-Agent-uri</div><div class="v">${fmtN((d.user_agents || []).length)}</div></div>
    </div>
    ${summ ? `<div class="incSummary">${tEsc(summ)}</div>` : ''}
    ${uas.length ? `<ul class="incUas">${uas.map(u => `<li>${tEsc(u.ua || '-')} <b>(${fmtN(u.n)})</b></li>`).join('')}</ul>` : ''}
    <div class="incTools">
      <span class="incSeg"><button type="button" data-inc-only="all" class="${INC.only === 'all' ? 'on' : ''}">Toate cererile</button><button type="button" data-inc-only="significant" class="${INC.only === 'significant' ? 'on' : ''}">Doar semnificative</button></span>
      <button type="button" class="ghost" data-inc-act="copyall">Copiaza toate liniile brute</button>
      <button type="button" class="ghost" data-inc-act="download">Descarca .log</button>
      <button type="button" class="ghost" data-inc-act="workplace">Deschide in Workplace</button>
    </div>`;
  if (d.truncated) html += `<div class="incNote">Afisate primele ${fmtN(d.shown)} cereri. "Copiaza" si "Descarca" includ toate liniile IP-ului.</div>`;
  if (d.first_significant_index == null) html += `<div class="incNote">Niciun eveniment CRITICAL/HIGH al acestui IP in selectie: toate cererile sunt in faza "inainte".</div>`;
  if (!d.events.length) html += `<div class="incNote">Nicio cerere a acestui IP in selectia curenta.</div>`;
  html += '<ol class="incTl" id="incTl">';
  let phaseShown = false;
  d.events.forEach((e, i) => {
    if (i === 0 && e.phase === 'inainte') { html += '<li class="incPhase">Inainte</li>'; phaseShown = true; }
    if (e.first_significant) html += '<li class="incSep">Primul eveniment semnificativ &mdash; de aici incepe faza "dupa"</li>';
    else if (i === 0 && e.phase === 'dupa' && sigIdx < 0) html += '<li class="incPhase">Dupa</li>';
    html += `<li class="incEv ${tEsc(e.phase)} sev-${tEsc(e.severity)}" data-i="${i}">
      <div class="incRow"><span class="tm">${tEsc(fmtEpoch(e.ts))}</span><span class="dt">${i ? incFmtDt(e.dt) : ''}</span>
        <span class="me">${tEsc(e.method)}</span><span class="url" title="${tEscAttr(e.url)}">${tEsc(e.url)}</span>
        <span class="rt">${incCode(e.status)}<span class="tag ${tEsc(e.severity)}">${tEsc(e.severity)}</span>${e.ua_changed ? '<span class="incUaNew" title="User-Agent diferit fata de cererea anterioara">UA nou</span>' : ''}</span></div>
      ${e.label ? `<div class="incLbl">${tEsc(e.label)}</div>` : ''}
      <div class="incRaw"><pre>${tEsc(e.raw)}</pre><button type="button" class="ghost" data-inc-copy="${i}">Copiaza linia</button></div>
    </li>`;
  });
  html += '</ol>';
  box.innerHTML = html;
  if (scroll) $('#incTl').scrollTop = scroll;
}
function incRawQuery(ip) {
  return { ts_from: gfTimeNarrowed() ? TRIAGE.tsFrom : null, ts_to: gfTimeNarrowed() ? TRIAGE.tsTo : null,
           conds: [{ field: 'ip', op: 'in', values: [ip] }] };
}
async function incFetchRaw(ip) {
  const r = await fetch(`/api/dataset/${DATASET_ID}/workplace/raw`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ q: incRawQuery(ip), filename: 'ip_' + ip }) });
  if (!r.ok) { let m = 'HTTP ' + r.status; try { m = (await r.json()).error || m; } catch (e) {} throw new Error(m); }
  return r.text();
}
document.addEventListener('click', async (ev) => {
  const t = ev.target;
  if (!t.closest || !t.closest('#incCard')) return;
  const tr = t.closest('#incBody tr');
  if (tr) { incOpen(tr.dataset.ip); return; }
  const only = t.closest('[data-inc-only]');
  if (only) { INC.only = only.dataset.incOnly; if (INC.sel) incOpen(INC.sel); return; }
  const cp = t.closest('[data-inc-copy]');
  if (cp) { const e = INC.trail.events[+cp.dataset.incCopy]; copyText(e.raw); return; }
  const act = t.closest('[data-inc-act]');
  if (act && INC.sel) {
    const ip = INC.sel, a = act.dataset.incAct;
    if (a === 'workplace') {
      if (await wkEnsureMeta()) { WK.conds = [wkMkCond({ field: 'ip', op: 'in', values: [ip] })]; WK.sort = 'ts_asc'; WK.period = 'global'; WK.offset = 0; }
      showPage('workplace');
      return;
    }
    try {
      act.disabled = true;
      const txt = await incFetchRaw(ip);
      if (a === 'copyall') copyText(txt);
      else {
        const url = URL.createObjectURL(new Blob([txt], { type: 'text/plain;charset=utf-8' }));
        const lnk = document.createElement('a'); lnk.href = url; lnk.download = 'ip_' + ip.replace(/[^0-9A-Za-z.:_-]/g, '_') + '.log';
        document.body.appendChild(lnk); lnk.click(); lnk.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
      }
    } catch (e) { toast('Eroare: ' + e.message); }
    finally { act.disabled = false; }
    return;
  }
  const evRow = t.closest('.incEv');
  if (evRow && !t.closest('.incRaw')) evRow.classList.toggle('open');
});
document.addEventListener('input', (ev) => { if (ev.target && ev.target.id === 'incSearch') incRenderTable(); });
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') incLoad(); else INC.stale = true; });

// ===================== v47.3: Acces WP admin =====================
const ADM = { key: null, data: null, tab: 'ok', open: {}, seq: 0 };
const ADM_ONLY_ACTIONS = new Set(['admin_login_success', 'admin_get', 'admin_login_post']);
function admResTxt(r) { return { executat: 'raspuns 200', redirect: 'raspuns 302', blocat: 'BLOCAT', eroare: 'eroare 5xx', inexistent: '404' }[r] || r; }
async function admLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready) return;
  const key = DATASET_ID + '|' + gfJSON();
  if (!force && key === ADM.key && ADM.data) return;
  ADM.key = key;
  const seq = ++ADM.seq;
  $('#admMsg').className = 'incMsg'; $('#admMsg').textContent = 'Se incarca accesele in WP admin...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/admin_access`)); d = await r.json(); }
  catch (e) { if (seq === ADM.seq) { $('#admMsg').className = 'incMsg err'; $('#admMsg').textContent = 'Eroare de retea: ' + e.message; } return; }
  if (seq !== ADM.seq) return;
  if (!r.ok) { ADM.data = null; $('#admBody').innerHTML = ''; $('#admMsg').className = 'incMsg err'; $('#admMsg').textContent = d.error || ('HTTP ' + r.status); return; }
  ADM.data = d;
  $('#admNOk').textContent = `(${(d.successes || []).length})`;
  $('#admNTry').textContent = `(${(d.attempts || []).length})`;
  if ((d.unconfirmed || []).length === 0 && ADM.tab === 'unc') ADM.tab = 'ok';
  $('#admNUnc').textContent = `(${(d.unconfirmed || []).length})`;
  admRender();
  if (INC.data) incRenderTable();   // tabelul de incidente exclude IP-urile mutate aici
}
function admRender() {
  const d = ADM.data; if (!d) return;
  document.querySelectorAll('[data-adm-tab]').forEach(b => b.classList.toggle('on', b.dataset.admTab === ADM.tab));
  $('#admMsg').className = 'incMsg'; $('#admMsg').textContent = '';
  if (ADM.tab === 'try') { admRenderTry(d.attempts || []); return; }
  if (ADM.tab === 'unc') {
    const u = d.unconfirmed || [];
    $('#admBody').innerHTML = `<div class="admNote">IP-uri cu 1-2 pagini /wp-admin/ cu 200, fara login in log, fara un endpoint care raspunde doar utilizatorilor autentificati si fara operatii confirmate. Dovada insuficienta (cache, raspuns generic) -- NU sunt considerate acces reusit si nu apar in Alerte critice.</div>` + (u.length ? u.map(admIpHtml).join('') : '<div class="incNote">Niciun IP in aceasta categorie.</div>');
    return;
  }
  const list = d.successes || [];
  if (!list.length) { $('#admBody').innerHTML = `<div class="incNote">Niciun acces reusit in WP admin in selectia curenta (niciun login confirmat si niciun /wp-admin/ cu 200).${admFakeNote(d)}</div>`; return; }
  $('#admBody').innerHTML = `<div class="admNote">${tEsc(d.note)}${admFakeNote(d)}</div>` + list.map(admIpHtml).join('');
}
function admFakeNote(d) {
  const f = d.wp_fake_prefixes || [];
  return f.length ? ` ${fmtN(d.wp_probe_events)} cereri pe cai unde nu exista WordPress (${f.slice(0, 5).map(p => (p || '/') + '/wp-admin').join(', ')}${f.length > 5 ? ', ...' : ''}) au primit raspunsul generic al site-ului si sunt tratate ca sondari, nu ca acces in admin.` : '';
}
function admIpHtml(x) {
  const ro = !x.is_non_ro;
  const badge = x.session_mode === 'login'
    ? `<span class="admBadge ok ${ro ? 'ro' : ''}">LOGIN REUSIT</span>`
    : (x.confirmed === false ? `<span class="admBadge unc">NECONFIRMAT (${fmtN(x.distinct_admin_pages)} pag. admin)</span>`
       : `<span class="admBadge sess">SESIUNE AUTENTIFICATA (fara login in log)</span>`);
  const chips = x.groups.filter(g => g.key !== 'login_post' && g.key !== 'login_page').map(g => {
    const allBlocked = g.critical && Object.keys(g.results).every(k => k === 'blocat');
    let res = Object.entries(g.results).map(([k, n]) => `${n} ${admResTxt(k)}`).join(', ');
    if (g.critical && g.confirmed_units) res += ` · CONFIRMAT: ${g.confirmed_units}`;
    else if (g.critical && !allBlocked) res += ' · neconfirmat';
    const tg = (g.targets || []).filter(t => t !== 'bulk');
    const tip = res + (tg.length ? ' -- ' + tg.join(', ') : '');
    const cls = g.critical ? (allBlocked ? 'blk' : (g.confirmed_units ? 'crit conf' : 'crit')) : (g.sensitive ? 'sens' : '');
    return `<span class="admChip ${cls}" title="${tEscAttr(tip)}">${tEsc(g.label)} <b>x${fmtN(g.n)}</b><span class="r">${tEsc(res)}</span>${tg.length ? `<span class="r">${tEsc(tg.slice(0, 4).join(', '))}${tg.length > 4 ? '…' : ''}</span>` : ''}</span>`;
  }).join('');
  const open = !!ADM.open[x.ip];
  return `<div class="admIp ${x.confirmed === false ? 'unc' : (ro ? 'ro' : 'nonro')}" data-adm-ip="${tEscAttr(x.ip)}">
    <div class="admTop"><span class="incIp">${tEsc(x.ip)}</span><span class="admMeta">${tEsc(x.country || '??')}</span>${badge}
      <span class="admMeta">${x.login_ts.length ? 'login la ' + tEsc(fmtEpoch(x.login_ts[0])) : 'prima cerere ' + tEsc(fmtEpoch(x.first_ts))}
      &middot; ${fmtN(x.admin_requests)} cereri admin${(() => { const n = x.groups.filter(g => g.key === 'login_post' || g.key === 'login_page').reduce((t, g) => t + g.n, 0); return n ? ` + ${fmtN(n)} pe pagina de login` : ''; })()} &middot; <b>${fmtN(x.critical_actions)}</b> actiuni care modifica site-ul (${fmtN(x.critical_confirmed)} confirmate, ${fmtN(x.critical_blocked)} blocate)</span></div>
    <div class="admNarr">${tEsc(x.narrative)}</div>
    ${(x.evidence || []).length ? `<div class="admEvid"><b>Dovada din log:</b> ${x.evidence.map(tEsc).join(' &middot; ')}</div>` : ''}
    ${(x.hints || []).length ? `<div class="admEvid"><b>Indicii (nu sunt dovada):</b> ${x.hints.map(tEsc).join(' &middot; ')}</div>` : ''}
    <div class="admChips">${chips}</div>
    <div class="admTools">
      <button type="button" class="ghost" data-adm-act="toggle">${open ? 'Ascunde' : 'Arata'} activitatea in admin (${fmtN(x.timeline.length)})</button>
      <button type="button" class="ghost" data-adm-act="trail">Traseu complet al IP-ului</button>
      <button type="button" class="ghost" data-adm-act="workplace">Deschide in Workplace</button>
    </div>
    ${open ? admTimelineHtml(x) : ''}
  </div>`;
}
function admTimelineHtml(x) {
  let seen = false;
  let h = '<ol class="admTl">';
  x.timeline.forEach(e => {
    if (e.login_ok && !seen) { seen = true; h += `<li class="admSep ${x.is_non_ro ? '' : 'ro'}">Login confirmat la ${tEsc(fmtEpoch(e.ts))} &mdash; de aici activitatea in admin cu sesiunea obtinuta</li>`; }
    h += `<li class="admEv ${e.critical ? 'crit' : ''} res-${tEsc(e.result)}">
      <span class="tm">${tEsc(fmtEpoch(e.ts))}</span><span class="me">${tEsc(e.method)}</span>
      <span class="ur"><span class="lb">${tEsc(e.label)}</span><span class="u" title="${tEscAttr(e.url)}">${tEsc(e.url)}</span></span>
      <span class="rt">${incCode(e.status)}<span class="admRes ${tEsc(e.result)}">${tEsc(admResTxt(e.result))}</span>${e.confirm ? `<span class="admRes conf">${tEsc(e.confirm)}</span>` : ''}</span></li>`;
  });
  h += '</ol>';
  if (x.timeline_truncated) h += '<div class="incNote">Lista e trunchiata; traseul complet are toate cererile.</div>';
  return h;
}
function admRenderTry(list) {
  if (!list.length) { $('#admBody').innerHTML = '<div class="incNote">Nicio incercare de autentificare fara reusita in selectia curenta.</div>'; return; }
  $('#admBody').innerHTML = `<div class="admNote">IP-uri care au trimis POST la wp-login.php / xmlrpc.php fara niciun acces reusit in admin in selectie. Click pe un rand pentru traseul complet.</div>
    <div class="incTableWrap"><table class="incTable"><thead><tr><th>IP</th><th>Tara</th><th class="num">Incercari</th><th>wp-login / xmlrpc</th><th>Coduri</th><th>Interval</th><th class="num">302 fara acces</th><th class="num">Ritm/min</th><th class="num">UA-uri</th></tr></thead><tbody>` +
    list.map(x => `<tr data-adm-try="${tEscAttr(x.ip)}"><td><span class="incIp">${tEsc(x.ip)}</span></td><td>${tEsc(x.country || '??')}</td>
      <td class="num">${fmtN(x.attempts)}</td><td>${fmtN(x.via['wp-login'])} / ${fmtN(x.via.xmlrpc)}</td>
      <td>${Object.entries(x.statuses).sort((a, b) => b[1] - a[1]).map(([s, n]) => `<span class="codePill c${s[0]}">${tEsc(s)} <b>${fmtN(n)}</b></span>`).join('')}</td>
      <td><span class="t mono">${tEsc(fmtEpoch(x.first_ts))} &ndash; ${tEsc(fmtEpoch(x.last_ts))}</span></td>
      <td class="num" title="302 dupa POST, dar fara acces confirmat in /wp-admin/">${x.n_302 ? '<b>' + fmtN(x.n_302) + '</b>' : '0'}</td>
      <td class="num">${tEsc(x.per_min)}</td><td class="num">${fmtN(x.user_agents)}</td></tr>`).join('') + '</tbody></table></div>';
}
async function admOpenWorkplace(ip) {
  if (await wkEnsureMeta()) { WK.conds = [wkMkCond({ field: 'ip', op: 'in', values: [ip] })]; WK.sort = 'ts_asc'; WK.period = 'global'; WK.offset = 0; }
  showPage('workplace');
}
function admTrail(ip) { incOpen(ip); setTimeout(() => $('#incDetail').scrollIntoView({ behavior: 'smooth', block: 'start' }), 150); }
document.addEventListener('click', (ev) => {
  const t = ev.target;
  if (!t.closest || !t.closest('#admCard')) return;
  const tab = t.closest('[data-adm-tab]');
  if (tab) { ADM.tab = tab.dataset.admTab; admRender(); return; }
  const tr = t.closest('[data-adm-try]');
  if (tr) { admTrail(tr.dataset.admTry); return; }
  const btn = t.closest('[data-adm-act]');
  if (btn) {
    const ip = btn.closest('[data-adm-ip]').dataset.admIp, a = btn.dataset.admAct;
    if (a === 'toggle') { ADM.open[ip] = !ADM.open[ip]; admRender(); }
    else if (a === 'trail') admTrail(ip);
    else if (a === 'workplace') admOpenWorkplace(ip);
  }
});
// IP-urile ale caror evenimente CRITICAL/HIGH sunt DOAR de autentificare/acces admin
// apar in "Acces WP admin", nu si in tabelul de incidente.
function admCoveredIps() {
  const s = new Set();
  if (!ADM.data) return s;
  (ADM.data.successes || []).forEach(x => s.add(x.ip));
  (ADM.data.attempts || []).forEach(x => s.add(x.ip));
  (ADM.data.unconfirmed || []).forEach(x => s.add(x.ip));
  return s;
}
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') admLoad(); });

// ===================== v48: SIGNAL FIRST =====================
// Ecranul de securitate arata implicit: rezumatul executiv, incidentele
// prioritare, evenimentele importante (max 5) si pasii urmatori. Restul
// (alerte brute, findings, anomalii, path-uri, coada completa, cronologie)
// e in sectiuni restranse implicit, cu numarul real de elemente si un buton
// care face exact ce scrie. Nimic nu e sters: datele sunt aceleasi, doar
// prezentarea e prioritizata.
const SF = { key: null, seq: 0, data: null, s: null, evAll: false, inited: false, open: {}, incAll: false };
const SF_ST_CLASS = { 'Confirmat din loguri': 'st-conf', 'Suspect': 'st-susp', 'Blocat conform raspunsului HTTP': 'st-block',
  'Neconfirmat': 'st-unc', 'Necesita verificare suplimentara': 'st-verify' };
function sfStatusTag(st) { return `<span class="sfSt ${SF_ST_CLASS[st] || ''}">${tEsc(st)}</span>`; }
function sfLs(k, v) { try { if (v === undefined) return localStorage.getItem('sf:' + k); localStorage.setItem('sf:' + k, v); } catch (e) { return null; } }

// ---- sectiuni restranse ----
const SF_SECTIONS = [];
function sfMakeCollapsible(el, key, title, btnOpen, note) {
  if (!el || el.classList.contains('sfCollapsible')) return;
  const bar = document.createElement('div');
  bar.className = 'sfBar';
  bar.innerHTML = `<span class="sfBarTitle">${tEsc(title)}</span><span class="sfBarCount" data-sf-count></span>` +
    `<span class="sfBarNote" data-sf-note>${note ? tEsc(note) : ''}</span>` +
    `<button type="button" class="ghost sfSmallBtn" data-sf-toggle aria-expanded="false"></button>`;
  el.prepend(bar);
  el.classList.add('sfCollapsible');
  const sec = { el, key, btnOpen, bar };
  SF_SECTIONS.push(sec);
  const saved = sfLs('open:' + key);
  sfSetOpen(sec, saved === '1', true);
  bar.querySelector('[data-sf-toggle]').addEventListener('click', () => sfSetOpen(sec, el.classList.contains('sfCollapsed')));
}
function sfSetOpen(sec, open, silent) {
  sec.el.classList.toggle('sfCollapsed', !open);
  const b = sec.bar.querySelector('[data-sf-toggle]');
  b.textContent = open ? 'Restrange sectiunea' : sec.btnOpen;
  b.setAttribute('aria-expanded', open ? 'true' : 'false');
  if (!silent) sfLs('open:' + sec.key, open ? '1' : '0');
  if (open && sec.onOpen) sec.onOpen();
}
function sfSection(key) { return SF_SECTIONS.find(x => x.key === key); }
function sfOpen(key) { const s = sfSection(key); if (s) sfSetOpen(s, true); return s; }
function sfCount(key, txt, note) {
  const s = sfSection(key); if (!s) return;
  s.bar.querySelector('[data-sf-count]').textContent = txt;
  if (note !== undefined) s.bar.querySelector('[data-sf-note]').textContent = note;
}
function sfInitSections() {
  if (SF.inited) return; SF.inited = true;
  assignDashTabs();
  sfMakeCollapsible($('#admCard'), 'adm', 'Acces WP admin: detalii complete', 'Vezi dovezile');
  sfMakeCollapsible($('#incCard'), 'inc', 'Atacuri: traseu cronologic pe IP', 'Vezi atacurile');
  sfMakeCollapsible($('#alertsWrap'), 'alerts', 'Detecții pe IP (CRITICAL / HIGH)', 'Vezi detecțiile', 'Fiecare IP la care motorul a găsit cel puțin o cerere gravă (SQLi, webshell, LFI...). Sunt detecțiile individuale, înainte de gruparea lor în incidentele de mai sus.');
  const q = (id) => { const e = $('#' + id); return e ? (e.classList.contains('card') || e.classList.contains('invQueueCard') ? e : e.closest('.card')) : null; };
  sfMakeCollapsible(q('investigationQueueCard'), 'queue', 'Toate semnalele de investigare', 'Deschide coada completa');
  sfMakeCollapsible(q('findingsCard'), 'findings', 'Findings tehnice', 'Vezi toate findings');
  sfMakeCollapsible(q('compromiseTrailCard'), 'trail', 'Traseu de compromitere per IP', 'Vezi traseele');
  sfMakeCollapsible(q('tblPathsRisk'), 'paths', 'Path-uri scanate si endpointuri sensibile', 'Afiseaza path-urile scanate');
  sfMakeCollapsible(q('tblScan'), 'scan', 'Scanare CMS / fisiere sensibile', 'Afiseaza scanarile');
  sfMakeCollapsible(q('anomaliesCard'), 'anom', 'Anomalii si trafic neobisnuit', 'Vezi toate anomaliile');
  sfMakeCollapsible(q('wordfenceCard'), 'wf', 'Plugin-uri / teme cu vulnerabilitati cunoscute (Wordfence)', 'Vezi verificarea');
  // cronologia (analiza temporala) e un <details>: o tinem inchisa si o
  // calculam abia la deschidere (nu la fiecare schimbare de filtru).
  const sc = $('#secCard');
  if (sc) {
    const sm = sc.querySelector('summary b'); if (sm) sm.textContent = 'Analiza temporala -- cronologie de securitate';
    sc.addEventListener('toggle', () => { sfLs('open:sec', sc.open ? '1' : '0'); if (sc.open && SEC.stale) { SEC.stale = false; _sfOrigSecRefresh(); } });
    if (sfLs('open:sec') === '1') sc.open = true;
  }
  sfUpdateDashCounts();
  sfUpdateTriageCounts();
}
const _sfOrigSecRefresh = secCardRefresh;
secCardRefresh = function () {
  const sc = $('#secCard');
  if (sc && !sc.open) { SEC.stale = true; return; }
  _sfOrigSecRefresh();
};

function sfUpdateDashCounts() {
  const s = SF.s; if (!s || !SF.inited) return;
  const n = (v) => fmtN(v || 0);
  const iq = s.investigation_queue || {};
  sfCount('queue', `(${n(iq.total)} semnale)`, 'Prioritizare, nu dovada de atac.');
  const fs = s.findings || [];
  sfCount('findings', `(${n(s.findings_count != null ? s.findings_count : fs.length)}${s.findings_signals && s.findings_signals !== fs.length ? ` grupuri, ${n(s.findings_signals)} semnale` : ''})`,
    'Cererile din aceeasi secventa sunt grupate; fiecare cerere originala e in "evidence".');
  sfCount('trail', `(${n((s.compromise_trail || []).length)} IP-uri)`);
  sfCount('paths', `(${n((s.top_paths_risk || []).length)} path-uri)`, 'Un request catre un endpoint sensibil nu e o compromitere.');
  const sh = s.scan_hits; sfCount('scan', `(${n(Array.isArray(sh) ? sh.length : (sh ? Object.keys(sh).length : 0))} semnaturi)`);
  sfCount('anom', `(${n(s.anomalies_count != null ? s.anomalies_count : (s.anomalies || []).length)})`, 'Statistic, fara impact demonstrat; cele legate de un incident apar in incident.');
  const wf = s.wordfence_status || {};
  sfCount('wf', `(${n((s.wordfence_matches || []).length)})`, wf.available === false ? 'Verificare INDISPONIBILA (feed-ul Wordfence nu e incarcat) -- nu inseamna ca site-ul nu are vulnerabilitati.' : '');
}
function sfUpdateTriageCounts() {
  if (!SF.inited) return;
  const d = ADM.data;
  if (d) sfCount('adm', `(${fmtN((d.successes || []).length)} acces reusit · ${fmtN((d.unconfirmed || []).length)} neconfirmat · ${fmtN((d.attempts || []).length)} IP-uri cu incercari)`);
  if (INC.data) sfCount('inc', `(${fmtN(INC.data.length)})`, INC.adminOnly ? `alte ${fmtN(INC.adminOnly)} IP-uri doar cu autentificari sunt in "Acces WP admin"` : '');
  const ac = $('#triageAlertsCount'); if (ac) sfCount('alerts', ac.textContent || '(0)', 'Detecțiile individuale ale motorului, pe IP; aceleași IP-uri apar mai sus grupate ca incidente.');
}

// ---- datele ----
async function sfLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready) return;
  sfInitSections();
  const key = DATASET_ID + '|' + gfJSON();
  if (!force && key === SF.key && SF.data) return;
  SF.key = key;
  const seq = ++SF.seq;
  $('#sfMsg').className = 'incMsg'; $('#sfMsg').textContent = 'Se incarca incidentele prioritare...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/brief`)); d = await r.json(); }
  catch (e) { if (seq === SF.seq) { $('#sfMsg').className = 'incMsg err'; $('#sfMsg').textContent = 'Eroare de retea: ' + e.message; } return; }
  if (seq !== SF.seq) return;
  if (!r.ok) { SF.data = null; $('#sfIncs').innerHTML = ''; $('#sfMsg').className = 'incMsg err'; $('#sfMsg').textContent = d.error || ('HTTP ' + r.status); return; }
  SF.data = d;
  $('#sfMsg').textContent = '';
  sfRender();
}
function sfRender() {
  const d = SF.data; if (!d) return;
  const e = d.exec, n = fmtN;
  const sev = e.incidents_by_severity || {};
  const sevTxt = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].filter(k => sev[k]).map(k => `${n(sev[k])} ${k}`).join(', ');
  const st = (lbl, val, attn, title) => `<span class="sfStat${attn ? ' attn' : ''}"${title ? ` title="${tEscAttr(title)}"` : ''}>${lbl} <b>${val}</b></span>`;
  const parts = [
    st('Interval', e.ts_min ? `${tEsc(fmtEpoch(e.ts_min))} – ${tEsc(fmtEpoch(e.ts_max))}` : '-'),
    st('Cereri', n(e.requests)), st('IP-uri unice', n(e.unique_ips)),
    '<span class="sfSep"></span>',
    st('Incidente de investigat', n(e.incidents) + (sevTxt ? ` <span class="sfMuted">(${tEsc(sevTxt)})</span>` : ''), e.incidents > 0),
    st('Sesiuni admin confirmate', n(e.admin_sessions_confirmed)),
    st('Operatii admin confirmate', n(e.admin_ops_confirmed), false, 'Confirmate de pagina de succes a WordPress (ex. ?update=del, ?settings-updated=true).'),
  ];
  if (e.admin_unconfirmed) parts.push(st('Acces admin neconfirmat', n(e.admin_unconfirmed)));
  if (e.blocked_admin_actions) parts.push(st('Actiuni admin blocate (401/403)', n(e.blocked_admin_actions)));
  if (e.blocked_login_requests) parts.push(st('Cereri de login blocate (401/403)', n(e.blocked_login_requests), false, `${n(e.login_attempt_ips)} IP-uri cu incercari de autentificare`));
  parts.push(st('Necesita verificare', n(e.needs_verification), e.needs_verification > 0));
  if (e.filtered) parts.push('<span class="sfStat">· doar in selectia curenta</span>');
  $('#sfExec').innerHTML = parts.join('');
  $('#sfIncN').textContent = `(${n(d.incidents.length)})`;
  const SF_FIRST = 10;
  const incs = SF.incAll ? d.incidents : d.incidents.slice(0, SF_FIRST);
  $('#sfIncs').innerHTML = d.incidents.length ? incs.map(sfIncHtml).join('') + (d.incidents.length > SF_FIRST
      ? `<button type="button" class="ghost sfSmallBtn sfIncMore" id="sfIncMore">${SF.incAll ? 'Arată doar primele ' + SF_FIRST : 'Arată toate cele ' + n(d.incidents.length) + ' incidente'}</button>` : '')
    : '<div class="incNote">Niciun incident de investigat în selecția curentă. Detecțiile individuale (dacă există) sunt în secțiunile de mai jos.</div>';
  sfRenderEvents();
  // pasii identici (aceeasi fraza, alt IP) se grupeaza: o fraza + lista IP-urilor
  const groups = [];
  const byTpl = new Map();
  d.steps.forEach(x => {
    const tpl = x.ip ? x.text.split(x.ip).join('{IP}') : x.text;
    let g = byTpl.get(tpl);
    if (!g) { g = { tpl, ips: [] }; byTpl.set(tpl, g); groups.push(g); }
    if (x.ip && !g.ips.includes(x.ip)) g.ips.push(x.ip);
  });
  $('#sfSteps').innerHTML = groups.length ? groups.slice(0, 8).map(g => {
    const many = g.ips.length > 1;
    const txt = many ? g.tpl.split('{IP}').join(`aceste ${n(g.ips.length)} IP-uri`).replace(/ e deja blocat\b/, ' sunt deja blocate').replace(/blocheaza-l sau limiteaza/, 'blocheaza-le sau limiteaza') : g.tpl.split('{IP}').join(g.ips[0] || '');
    const ips = many ? `<div class="sfStepIps">${g.ips.slice(0, 12).map(ip => `<span class="ip">${tEsc(ip)}</span>`).join(' ')}${g.ips.length > 12 ? ` <span class="sfMuted">+${n(g.ips.length - 12)}</span>` : ''}</div>` : '';
    return `<li>${tEsc(txt)}${ips}</li>`;
  }).join('') + (groups.length > 8 ? `<li class="sfMuted">+${n(groups.length - 8)} alte acțiuni în incidentele de mai sus</li>` : '')
    : '<li class="sfMuted">Nimic de făcut pe baza dovezilor din selecție.</li>';
  $('#sfDefs').innerHTML = Object.entries(d.definitions || {}).map(([k, v]) => `<dt>${sfStatusTag(k)}</dt><dd>${tEsc(v)}</dd>`).join('');
}
function sfRenderEvents() {
  const ev = SF.data.events || [];
  const list = SF.evAll ? ev : ev.slice(0, 5);
  $('#sfEvents').innerHTML = list.length ? list.map(x =>
    `<li><span class="t">${tEsc(x.when)}</span><span class="ip">${tEsc(x.ip)}</span>${tEsc(x.text)} ${sfStatusTag(x.status)}</li>`).join('')
    : '<li class="sfMuted">Niciun eveniment important in selectie.</li>';
  const b = $('#sfEvAll');
  b.hidden = ev.length <= 5;
  b.textContent = SF.evAll ? 'Arata doar ultimele 5' : `Vezi toate evenimentele (${fmtN(ev.length)})`;
}
function sfRelated(x) {
  const s = SF.s; const out = [];
  if (x.signals && x.signals.alert) out.push(`alerta ${x.signals.alert}`);
  if (s) {
    const f = (s.findings || []).filter(z => z.ip === x.ip);
    if (f.length) out.push(`${fmtN(f.length)} finding(s): ${[...new Set(f.map(z => z.rule))].slice(0, 3).join('; ')}`);
    const t = (s.compromise_trail || []).find(z => z.ip === x.ip);
    if (t) out.push(`traseu: ${t.dominant_category_label || t.dominant_category} (${fmtN(t.total_events)} evenimente)`);
    const pfx = x.ip.split('.').slice(0, 3).join('.') + '.';
    const an = (s.anomalies || []).filter(z => z.ip === x.ip || (z.subnet && z.subnet.startsWith(pfx)));
    if (an.length) out.push(`${fmtN(an.length)} anomalie(i) asociate: ${an.slice(0, 2).map(z => z.rule + (z.subnet ? ' ' + z.subnet : '')).join('; ')}`);
  }
  return out;
}
function sfIncHtml(x) {
  const li = (a) => a.length ? `<ul>${a.map(v => `<li>${tEsc(v)}</li>`).join('')}</ul>` : '<span class="sfMuted">-</span>';
  const rel = sfRelated(x);
  const open = !!SF.open[x.id];
  return `<article class="sfInc sev-${tEscAttr(x.severity)}${open ? ' open' : ''}" data-sf-inc="${tEscAttr(x.id)}">
    <div class="sfIncTop" data-sf-inctoggle role="button" tabindex="0" aria-expanded="${open}"><span class="sfCaret">${open ? '&#9662;' : '&#9656;'}</span><span class="tag ${tEscAttr(x.severity)}">${tEsc(x.severity)}</span>
      <span class="incIp">${tEsc(x.ip)}</span>${flagHtml(x.country)}<span class="sfMuted">${tEsc(x.country)}</span>
      <span class="sfIncTitle">${tEsc(x.title)}</span>${x.status.map(sfStatusTag).join(' ')}
      <span class="sfIncN">${(x.observed || []).length} semnale</span>
      <span class="sfWhen">${tEsc(fmtEpoch(x.first_ts))} – ${tEsc(fmtEpoch(x.last_ts))}</span></div>
    <div class="sfIncBody"${open ? '' : ' hidden'}>
    <dl class="sfGrid">
      <dt>Observat</dt><dd>${li(x.observed)}</dd>
      ${x.affected && x.affected.length ? `<dt>Resurse afectate</dt><dd>${tEsc(x.affected.join(', '))}</dd>` : ''}
      <dt>Interpretare</dt><dd>${tEsc(x.interpretation)}</dd>
      <dt>Certitudine</dt><dd>${tEsc(x.certainty)}${x.hints && x.hints.length ? `<div class="sfRel">Indicii (nu sunt dovada): ${tEsc(x.hints.join(' · '))}</div>` : ''}</dd>
      <dt>De ce conteaza</dt><dd>${tEsc((x.why || []).join('; ') || '-')}</dd>
      <dt>Actiune recomandata</dt><dd>${li(x.actions)}</dd>
      ${rel.length ? `<dt>Semnale asociate</dt><dd class="sfRel">${tEsc(rel.join(' · '))}</dd>` : ''}
    </dl>
    <div class="sfIncTools">
      <button type="button" class="ghost sfSmallBtn" data-sf-act="evidence">Vezi dovezile</button>
      <button type="button" class="ghost sfSmallBtn" data-sf-act="trail">Traseu complet al IP-ului</button>
      <button type="button" class="ghost sfSmallBtn" data-sf-act="raw">Consulta logurile brute</button>
      ${/^[0-9a-f:.]+$/i.test(x.ip || '') ? ruleBtn({ ip: x.ip, label: x.ip }) : ''}
    </div><!--/tools--></div></article>`;
}
function sfScrollTo(el) { if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120); }
document.addEventListener('click', (ev) => {
  const t = ev.target;
  if (!t.closest) return;
  if (t.id === 'sfEvAll') { SF.evAll = !SF.evAll; sfRenderEvents(); return; }
  if (t.id === 'sfIncMore') { SF.incAll = !SF.incAll; sfRender(); return; }
  const tg = t.closest('[data-sf-inctoggle]');
  if (tg && !t.closest('button, a, [data-sf-act]')) {
    const art = tg.closest('[data-sf-inc]'); const id = art.dataset.sfInc;
    SF.open[id] = !SF.open[id];
    art.classList.toggle('open', SF.open[id]); art.querySelector('.sfIncBody').hidden = !SF.open[id];
    tg.setAttribute('aria-expanded', String(SF.open[id])); tg.querySelector('.sfCaret').innerHTML = SF.open[id] ? '&#9662;' : '&#9656;';
    return;
  }
  if (t.id === 'sfExpandAll' || t.id === 'sfCollapseAll') {
    const open = t.id === 'sfExpandAll';
    SF_SECTIONS.forEach(s => sfSetOpen(s, open));
    const sc = $('#secCard'); if (sc) sc.open = open;
    return;
  }
  if (t.id === 'sfRawBtn') { showPage('raw'); return; }
  const btn = t.closest('[data-sf-act]');
  if (!btn) return;
  const id = btn.closest('[data-sf-inc]').dataset.sfInc;
  const x = (SF.data.incidents || []).find(z => z.id === id); if (!x) return;
  const a = btn.dataset.sfAct;
  if (a === 'raw') { admOpenWorkplace(x.ip); return; }
  if (a === 'trail') { sfOpen('inc'); incOpen(x.ip); sfScrollTo($('#incDetail')); return; }
  if (x.kind === 'admin') {
    sfOpen('adm');
    ADM.tab = x.status[0] === 'Neconfirmat' ? 'unc' : 'ok';
    ADM.open[x.ip] = true;
    admRender();
    sfScrollTo(document.querySelector(`#admBody [data-adm-ip="${CSS.escape(x.ip)}"]`));
  } else {
    sfOpen('inc'); incOpen(x.ip); sfScrollTo($('#incDetail'));
  }
});

// ---- legaturi cu restul aplicatiei ----
const _sfOrigRenderSummary = renderSummary;
renderSummary = function (s) {
  const r = _sfOrigRenderSummary.apply(this, arguments);
  SF.s = s;
  try { sfUpdateDashCounts(); if (SF.data) sfRender(); } catch (e) { console.warn('sf summary', e); }
  return r;
};
const _sfOrigAdmLoad = admLoad;
admLoad = async function () { const r = await _sfOrigAdmLoad.apply(this, arguments); sfUpdateTriageCounts(); return r; };
const _sfOrigIncLoad = incLoad;
incLoad = async function () { const r = await _sfOrigIncLoad.apply(this, arguments); sfUpdateTriageCounts(); return r; };
const _sfOrigAlerts = triageLoadAlerts;
triageLoadAlerts = async function () { const r = await _sfOrigAlerts.apply(this, arguments); sfUpdateTriageCounts(); return r; };
const _sfOrigShowPage2 = showPage;
showPage = function (page) {
  _sfOrigShowPage2.apply(this, arguments);
  if (CURRENT_PAGE === 'security') { sfInitSections(); sfLoad(); }
};
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') sfLoad(); else SF.key = null; });

// ===================== v49: TIMPUL -- o singura definitie =====================
// Ora afisata si selectata = ora din log (offsetul fiecarei linii). Daca logul
// are mai multe offseturi (trecerea la ora de iarna), fiecare moment foloseste
// segmentul lui. Intervalele sunt [de la, pana la] cu ambele capete incluse.
const TIME = { info: null, seg: null };
function tzOffsetAt(epoch) {
  const seg = TIME.seg;
  if (!seg || !seg.length) return TRIAGE.tzOffset || 0;
  let off = seg[0].offset_sec;
  for (const s of seg) if (epoch >= s.ts_min) off = s.offset_sec;
  return off;
}
function tzLabel(off) {
  const a = Math.abs(off), sg = off >= 0 ? '+' : '-';
  return `UTC${sg}${String(Math.floor(a / 3600)).padStart(2, '0')}:${String(Math.floor(a % 3600 / 60)).padStart(2, '0')}`;
}
// conversiile existente devin constiente de segmente (acelasi API pentru tot codul)
const _ppOrigE2D = epochToDtLocal;
epochToDtLocal = function (epoch, tzOff) { return _ppOrigE2D(epoch, TIME.seg ? tzOffsetAt(epoch) : tzOff); };
const _ppOrigD2E = dtLocalToEpoch;
dtLocalToEpoch = function (value, tzOff) {
  if (!TIME.seg || TIME.seg.length < 2) return _ppOrigD2E(value, tzOff);
  for (const s of TIME.seg) { const e = _ppOrigD2E(value, s.offset_sec); if (e != null && e >= s.ts_min - 3600 && e <= s.ts_max + 3600) return e; }
  return _ppOrigD2E(value, tzOff);
};
const _ppOrigE2S = epochToDtLocalStr;
epochToDtLocalStr = function (epoch) {
  if (!TIME.seg) return _ppOrigE2S(epoch);
  const keep = TRIAGE.tzOffset; TRIAGE.tzOffset = tzOffsetAt(epoch);
  try { return _ppOrigE2S(epoch); } finally { TRIAGE.tzOffset = keep; }
};

const PP = { last: null, busy: false };
const PP_SHOW = {
  all: [], day: ['day'], hour: ['day', 'h'], min30: ['day', 'h', 'm'], min10: ['day', 'h', 'm'], minute: ['day', 'h', 'm'],
  moment: ['day', 'h', 'm', 's', 'win'], custom: ['day', 'h', 'm', 's', 'end'],
};
function ppOpts(n, sel) { let h = ''; for (let i = 0; i < n; i++) { const v = String(i).padStart(2, '0'); h += `<option value="${i}"${i === sel ? ' selected' : ''}>${v}</option>`; } return h; }
function ppWall(epoch) {
  // {day:'30/Sep/2026', h, m, s} in ora logului
  const s = epochToDtLocalStr(epoch);
  const m = /^(\d{2}\/\w{3}\/\d{4}):(\d{2}):(\d{2}):(\d{2})/.exec(s);
  return m ? { day: m[1], h: +m[2], m: +m[3], s: +m[4] } : null;
}
function ppSetFields(sfx, w) {
  if (!w) return;
  const d = $('#ppDay' + sfx);
  if (d && ![...d.options].some(o => o.value === w.day)) d.insertAdjacentHTML('beforeend', `<option value="${tEscAttr(w.day)}">${tEsc(w.day)}</option>`);
  if (d) d.value = w.day;
  $('#ppH' + sfx).value = String(w.h); $('#ppM' + sfx).value = String(w.m); $('#ppS' + sfx).value = String(w.s);
}
function ppRenderMode() {
  const mode = $('#ppMode').value, show = new Set(PP_SHOW[mode] || []);
  $('#ppStart').hidden = !show.has('day');
  $('#ppH').hidden = !show.has('h'); $('#ppM').hidden = !show.has('m'); $('#ppS').hidden = !show.has('s');
  $('#ppStart').querySelectorAll('.ppColon').forEach((c, i) => { c.hidden = !(i === 0 ? show.has('m') : show.has('s')); });
  $('#ppWin').hidden = !show.has('win');
  $('#ppEnd').hidden = !show.has('end');
  $('#ppStartLbl').textContent = mode === 'custom' ? 'de la' : (mode === 'moment' ? 'momentul' : '');
  $('#ppFirst').hidden = mode === 'all'; $('#ppLast').hidden = mode !== 'custom';
}
async function ppInit() {
  if (!DATASET_ID || !TRIAGE.ready) return;
  let r, d;
  try { r = await fetch(`/api/dataset/${DATASET_ID}/time_info`); d = await r.json(); } catch (e) { return; }
  if (!r.ok) { if (r.status === 202) setTimeout(ppInit, 1500); return; }
  TIME.info = d; TIME.seg = d.segments;
  const days = d.days.map(x => `<option value="${tEscAttr(x)}">${tEsc(x)}</option>`).join('');
  $('#ppDay').innerHTML = days; $('#ppDay2').innerHTML = days;
  ['', '2'].forEach(sfx => { $('#ppH' + sfx).innerHTML = ppOpts(24, 0); $('#ppM' + sfx).innerHTML = ppOpts(60, 0); $('#ppS' + sfx).innerHTML = ppOpts(60, 0); });
  if (d.first) ppSetFields('', d.first);
  if (d.last) ppSetFields('2', d.last);
  ppRenderMode();
  ppSyncFromRange();
}
function ppTzText() {
  const seg = TIME.seg || [];
  if (seg.length > 1) return 'ora logului: ' + seg.map(s => tzLabel(s.offset_sec)).join(' / ') + ' (logul isi schimba offsetul; fiecare moment foloseste offsetul lui)';
  return 'ora logului: ' + tzLabel(seg.length ? seg[0].offset_sec : (TRIAGE.tzOffset || 0));
}
function ppSyncFromRange() {
  if (!TIME.info || TRIAGE.tsFrom == null) return;
  const narrowed = gfTimeNarrowed();
  if (!narrowed) {
    if (!PP.last || PP.last.mode !== 'all') { $('#ppMode').value = 'all'; ppRenderMode(); }
  } else if (!PP.last || PP.last.ts_from !== Math.floor(TRIAGE.tsFrom) || PP.last.ts_to !== Math.floor(TRIAGE.tsTo)) {
    // intervalul a venit din alta parte (histograma, Workplace, drilldown) -> il aratam exact, ca interval
    $('#ppMode').value = 'custom';
    ppSetFields('', ppWall(TRIAGE.tsFrom)); ppSetFields('2', ppWall(TRIAGE.tsTo));
    ppRenderMode();
    PP.last = { mode: 'custom', ts_from: Math.floor(TRIAGE.tsFrom), ts_to: Math.floor(TRIAGE.tsTo), label: null };
  }
  const a = ppWall(TRIAGE.tsFrom), b = ppWall(TRIAGE.tsTo);
  const txt = a && b ? `${a.day} ${String(a.h).padStart(2, '0')}:${String(a.m).padStart(2, '0')}:${String(a.s).padStart(2, '0')} – ${b.day} ${String(b.h).padStart(2, '0')}:${String(b.m).padStart(2, '0')}:${String(b.s).padStart(2, '0')}` : '';
  $('#ppInfo').innerHTML = `Aplicat: <b>${tEsc(narrowed ? (PP.last && PP.last.label) || txt : 'tot logul')}</b> <span class="ppDim">[${tEsc(txt)}, ambele capete incluse] · ${tEsc(ppTzText())}</span>`;
}
function ppGfWithoutTime() {
  const o = gfObject(); delete o.ts_from; delete o.ts_to; delete o.ts_str_day;
  return Object.keys(o).length ? JSON.stringify(o) : '';
}
async function ppApply(override) {
  if (!TIME.info || PP.busy) return;
  const mode = override ? override.mode : $('#ppMode').value;
  if (mode === 'all') { PP.last = { mode: 'all' }; triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo); return; }
  const q = new URLSearchParams(override ? Object.assign({ h: 0, m: 0, s: 0 }, override) : {
    mode, day: $('#ppDay').value, h: $('#ppH').value, m: $('#ppM').value, s: $('#ppS').value,
    day2: $('#ppDay2').value, h2: $('#ppH2').value, m2: $('#ppM2').value, s2: $('#ppS2').value, win: $('#ppWinSel').value,
  });
  const g = ppGfWithoutTime(); if (g) q.set('gf', g);
  PP.busy = true; $('#ppApply').disabled = true;
  try {
    const r = await fetch(`/api/dataset/${DATASET_ID}/period?${q}`); const d = await r.json();
    if (!r.ok) { $('#ppInfo').innerHTML = `<span class="ppErr">${tEsc(d.error || 'HTTP ' + r.status)}</span>`; return; }
    PP.last = { mode, ts_from: d.ts_from, ts_to: d.ts_to, label: d.label };
    if (override && override.mode === 'day') { $('#ppMode').value = 'day'; $('#ppDay').value = override.day; ppRenderMode(); }
    // limitele exacte ale intervalului (nu taiate la prima/ultima cerere -- altfel "o ora" n-ar mai fi o ora)
    TRIAGE.tsFrom = d.ts_from; TRIAGE.tsTo = d.ts_to;
    if (TRIAGE.tsFrom <= TRIAGE.boundsFrom && TRIAGE.tsTo >= TRIAGE.boundsTo) { TRIAGE.tsFrom = TRIAGE.boundsFrom; TRIAGE.tsTo = TRIAGE.boundsTo; }
    $('#triageFrom').value = epochToDtLocal(TRIAGE.tsFrom, TRIAGE.tzOffset); $('#triageTo').value = epochToDtLocal(TRIAGE.tsTo, TRIAGE.tzOffset);
    triageRenderActiveChips(); triageReloadAll();
    if (d.requests === 0) gfSetStatus('Nicio cerere in intervalul ales (cu celelalte filtre active). Alege alt interval sau apasa "Reseteaza doar perioada".', 'warn');
  } catch (e) { $('#ppInfo').innerHTML = `<span class="ppErr">Eroare de retea: ${tEsc(e.message)}</span>`; }
  finally { PP.busy = false; $('#ppApply').disabled = false; }
}
$('#ppMode').addEventListener('change', ppRenderMode);
$('#ppApply').addEventListener('click', () => ppApply());
$('#ppFirst').addEventListener('click', () => { if (TIME.info && TIME.info.first) ppSetFields('', TIME.info.first); });
$('#ppLast').addEventListener('click', () => { if (TIME.info && TIME.info.last) ppSetFields('2', TIME.info.last); });
$('#ppReset').addEventListener('click', () => { PP.last = { mode: 'all' }; $('#ppMode').value = 'all'; ppRenderMode(); triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo); });
GF_LISTENERS.push(() => ppSyncFromRange());
const _ppOrigBounds = triageFetchTimeBounds;
triageFetchTimeBounds = async function () { const r = await _ppOrigBounds.apply(this, arguments); await ppInit(); return r; };
// interval scos din chip-ul "Interval" sau din "Reseteaza" -> selectorul revine la "tot logul"
const _ppOrigSetRange = triageSetRange;
triageSetRange = function (a, b, silent) {
  _ppOrigSetRange(a, b, silent);
  if (!gfTimeNarrowed()) PP.last = { mode: 'all' };
  ppSyncFromRange();
};

// ---- selectorul de zi din bara de sus = ACELASI mecanism (ziua -> interval 00:00:00 - 23:59:59) ----
(function () {
  const sel = $('#daySelect');
  if (!sel) return;
  const prev = sel.onchange;
  const install = () => {
    sel.onchange = async () => {
      if (!TRIAGE.ready || !TIME.info) { if (prev) return prev(); return; }
      TRIAGE.filters.day = '';
      if (sel.value === 'ALL') { PP.last = { mode: 'all' }; $('#ppMode').value = 'all'; ppRenderMode(); triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo); return; }
      await ppApply({ mode: 'day', day: sel.value });
    };
  };
  const _origPop = populateDaySelect;
  populateDaySelect = function () { const r = _origPop.apply(this, arguments); install(); return r; };
  install();
})();

// ---- filtru Metoda (dropdown din valorile reale ale selectiei) + sugestii IP / path ----
(function () {
  const bar = document.querySelector('.gfFilters');
  if (!bar || $('#triageMethodFilter')) return;
  $('#triageIpFilter').insertAdjacentHTML('beforebegin', `<select id="triageMethodFilter" title="Metoda HTTP"><option value="">Metoda: oricare</option></select>`);
  $('#triageIpFilter').setAttribute('list', 'ppIpList');
  $('#triagePathFilter').setAttribute('list', 'ppPathList');
  bar.insertAdjacentHTML('beforeend', '<datalist id="ppIpList"></datalist><datalist id="ppPathList"></datalist>');
  $('#triageMethodFilter').addEventListener('change', () => { TRIAGE.filters.method = $('#triageMethodFilter').value; triageRenderActiveChips(); triageReloadAll(); });
})();
function ppFillSuggestions(s) {
  if (!s) return;
  const m = s.methods || {};
  const cur = TRIAGE.filters.method || '';
  const keys = Object.keys(m).sort((a, b) => (m[b] || 0) - (m[a] || 0));
  if (cur && !keys.includes(cur)) keys.unshift(cur);
  $('#triageMethodFilter').innerHTML = '<option value="">Metoda: oricare</option>' + keys.map(k => `<option value="${tEscAttr(k)}"${k === cur ? ' selected' : ''}>${tEsc(k)}${m[k] != null ? ' (' + fmtNum(m[k]) + ')' : ''}</option>`).join('');
  const ips = (s.top_ips || []).slice(0, 300).map(x => x.ip || x[0]).filter(Boolean);
  $('#ppIpList').innerHTML = ips.map(v => `<option value="${tEscAttr(v)}">`).join('');
  const paths = (s.top_paths || []).slice(0, 300).map(x => x.path || x[0]).filter(Boolean);
  $('#ppPathList').innerHTML = paths.map(v => `<option value="${tEscAttr(v)}">`).join('');
}
const _ppOrigRS = renderSummary;
renderSummary = function (s) { const r = _ppOrigRS.apply(this, arguments); try { ppFillSuggestions(s); } catch (e) { } return r; };
const _ppOrigReset = $('#triageResetBtn');
_ppOrigReset.addEventListener('click', () => { if ($('#triageMethodFilter')) $('#triageMethodFilter').value = ''; PP.last = { mode: 'all' }; $('#ppMode').value = 'all'; ppRenderMode(); ppSyncFromRange(); });

// ---- copy tabel = TOATE randurile (dupa cautarea din tabel), nu doar cele afisate ----
const _ppOrigCopyTable = copyTable;
copyTable = function (sel) {
  const st = (typeof TBL_STATE !== 'undefined') ? TBL_STATE[sel] : null;
  const table = document.querySelector(sel);
  if (!st || !table || !st.rows || !st.rowFn) return _ppOrigCopyTable(sel);
  const head = [...table.querySelectorAll('thead tr')].map(r => [...r.children].map(c => c.innerText.trim()).join('\t'));
  const body = st.rows.map(r => st.rowFn(r).map(c => cellText(c).replace(/\s+/g, ' ').trim()).join('\t'));
  copyText(head.concat(body).join('\n'));
  toast(`${fmtNum(body.length)} randuri copiate (toate randurile tabelului din selectia curenta, nu doar cele afisate)`);
};

// ---- v49: selectoarele de timp DUPLICATE sunt redirectionate spre selectorul global ----
// (1) IP Explorer avea zi + ora de la/pana la proprii, care oricum setau perioada
//     globala -> le ascundem; presetarile "rapide" devin butoane globale, calculate
//     in epoch (inainte se taiau la miezul noptii: "ultima ora" la 00:20 dadea 00:00-00:20).
// (2) Raw Logs > "Vezi cererile dintr-un moment exact" era al treilea selector de
//     zi/ora/minut/fereastra -> acum e chiar selectorul global (moduri identice).
(function () {
  const row = document.querySelector('#ipOverviewCard .ipovCtlRow');
  if (row) {
    row.hidden = true;
    row.insertAdjacentHTML('afterend', '<div class="note ppPointer">Perioada si filtrele se aleg din selectorul global de sus (aceeasi selectie pentru toata aplicatia). <button type="button" class="ghost ppSmall" data-pp-focus>Mergi la selectorul de perioada</button></div>');
  }
  const mc = $('#momentCard');
  if (mc) {
    [...mc.children].forEach(ch => { if (ch.tagName !== 'H2') ch.hidden = true; });
    const h2 = mc.querySelector('h2'); if (h2) h2.innerHTML = '&#128337; Cererile dintr-un moment exact';
    mc.insertAdjacentHTML('beforeend', '<div class="note ppPointer">Alege in selectorul global de sus <b>Moment exact ± fereastra</b> (sau o ora / 30 / 10 minute / un minut) si apasa <b>Aplica perioada</b>: lista de cereri, statisticile si exporturile din toata aplicatia folosesc acel interval. <button type="button" class="ghost ppSmall" data-pp-focus="moment">Alege momentul</button> <button type="button" class="ghost ppSmall" data-pp-wk>Vezi cererile brute ale selectiei (Workplace)</button></div>');
  }
  const r2 = document.querySelector('.ppRow2');
  if (r2) r2.insertAdjacentHTML('beforeend', '<span class="ppDim">Rapid:</span><button type="button" class="ghost ppSmall" data-pp-quick="600">ultimele 10 min</button><button type="button" class="ghost ppSmall" data-pp-quick="3600">ultima ora</button><button type="button" class="ghost ppSmall" data-pp-quick="86400">ultimele 24 h</button>');
})();
document.addEventListener('click', (e) => {
  const q = e.target.closest('[data-pp-quick]');
  if (q && TRIAGE.boundsTo != null) {
    // relativ la ultima cerere din log; intervalul poate traversa miezul noptii
    const span = parseInt(q.dataset.ppQuick, 10), end = TRIAGE.boundsTo;
    PP.last = { mode: 'custom', ts_from: end - span + 1, ts_to: end, label: q.textContent + ' ale logului' };
    TRIAGE.tsFrom = Math.max(TRIAGE.boundsFrom, end - span + 1); TRIAGE.tsTo = end;
    PP.last.ts_from = TRIAGE.tsFrom;
    triageRenderActiveChips(); triageReloadAll();
    return;
  }
  const f = e.target.closest('[data-pp-focus]');
  if (f) {
    if (f.dataset.ppFocus) { $('#ppMode').value = f.dataset.ppFocus; ppRenderMode(); }
    $('#ppWrap').scrollIntoView({ behavior: 'smooth', block: 'center' }); setTimeout(() => $('#ppMode').focus(), 300);
    return;
  }
  if (e.target.closest('[data-pp-wk]')) { showPage('workplace'); }
});

// ===================== v49.1: ATACURI PE FILTRE =====================
const FA = { key: null, seq: 0, lseq: 0, data: null, items: [], offset: 0, total: 0 };
async function faLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready) return;
  const key = DATASET_ID + '|' + gfJSON();
  if (!force && key === FA.key && FA.data) return;
  FA.key = key;
  const seq = ++FA.seq;
  $('#faMsg').className = 'incMsg'; $('#faMsg').textContent = 'Se analizeaza cererile cu parametri de filtrare...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/filter_attacks?top=300`)); d = await r.json(); }
  catch (e) { if (seq === FA.seq) { $('#faMsg').className = 'incMsg err'; $('#faMsg').textContent = 'Eroare de retea: ' + e.message; } return; }
  if (seq !== FA.seq) return;
  if (!r.ok) { FA.data = null; $('#faMsg').className = 'incMsg err'; $('#faMsg').textContent = d.error || ('HTTP ' + r.status); return; }
  FA.data = d; $('#faMsg').textContent = '';
  faRender();
}
function faRender() {
  const d = FA.data, n = fmtN;
  const on = !!d.detected;
  $('#faVerdictTag').innerHTML = on ? `<span class="tag ${tEscAttr(d.severity)}">${tEsc(d.severity)}</span>` : (d.filter_requests ? '<span class="sfSt">sub praguri</span>' : '<span class="sfSt">nimic</span>');
  $('#faVerdict').className = 'faVerdict ' + (on ? 'on' : 'off');
  $('#faVerdict').textContent = d.verdict;
  $('#faCard').classList.toggle('faOn', on);
  if (!d.filter_requests) { $('#faStats').innerHTML = ''; $('#faBody').hidden = true; return; }
  const st = (l, v, attn, t) => `<span class="sfStat${attn ? ' attn' : ''}"${t ? ` title="${tEscAttr(t)}"` : ''}>${l} <b>${v}</b></span>`;
  const s = d.status || {};
  $('#faStats').innerHTML = [
    st('Cereri de filtrare (IP totale)', n(d.filter_requests), on, 'Toate aparitiile: o cerere = un rand; acelasi IP poate aparea de mai multe ori'),
    st('IP-uri unice', n(d.unique_ips), on),
    st('IP-uri cu o singura cerere', n(d.ips_with_1_request), false, 'Tipic pentru rotatie de proxy-uri'),
    st('Din selectie', (100 * d.share).toFixed(1) + '%'),
    st('5xx', n(s['5xx']), s['5xx'] > 0), st('4xx', n(s['4xx'])), st('2xx', n(s['2xx'])),
    st('Varf', `${n(d.peak_minute.requests)}/min la ${tEsc(fmtEpoch(d.peak_minute.ts))}`),
    st('Interval', `${tEsc(fmtEpoch(d.first_ts))} – ${tEsc(fmtEpoch(d.last_ts))}`),
  ].join('');
  $('#faBody').hidden = false;
  const distSet = new Set(d.distributed_targets || []);
  $('#faTargets').innerHTML = d.targets.map(t => `<tr data-fa-target="${tEscAttr(t.target)}" class="${$('#faTarget').value === t.target ? 'sel' : ''}">
    <td><span class="faUrl">${tEsc(t.target)}</span>${distSet.has(t.target) ? ' <span class="tag HIGH">distribuit</span>' : ''}</td>
    <td class="num">${n(t.requests)}</td><td class="num">${n(t.unique_ips)}</td><td class="num">${t.ratio}</td><td class="num">${n(t.distinct_urls)}</td>
    <td class="faUrl">${tEsc(t.params.join(', '))}</td>
    <td><span class="codePill c2">2xx <b>${n(t.status['2xx'])}</b></span>${t.status['4xx'] ? `<span class="codePill c4">4xx <b>${n(t.status['4xx'])}</b></span>` : ''}${t.status['5xx'] ? `<span class="codePill c5">5xx <b>${n(t.status['5xx'])}</b></span>` : ''}</td>
    <td>${n(t.countries)} <span class="sfMuted">${tEsc(t.top_countries.slice(0, 3).map(c => c.cc).join(' '))}</span></td>
    <td class="sfMuted">${tEsc(fmtEpoch(t.first_ts))} – ${tEsc(fmtEpoch(t.last_ts))}</td></tr>`).join('') +
    (d.targets_total > d.targets.length ? `<tr><td colspan="9" class="sfMuted">+${n(d.targets_total - d.targets.length)} tinte mai mici</td></tr>` : '');
  const curT = $('#faTarget').value, curP = $('#faParam').value;
  $('#faTarget').innerHTML = '<option value="">toate</option>' + d.targets.map(t => `<option value="${tEscAttr(t.target)}">${tEsc(t.target)} (${n(t.requests)})</option>`).join('');
  $('#faTarget').value = d.targets.some(t => t.target === curT) ? curT : '';
  const params = [...new Set(d.targets.flatMap(t => t.params))];
  $('#faParam').innerHTML = '<option value="">oricare</option>' + params.map(p => `<option value="${tEscAttr(p)}">${tEsc(p)}</option>`).join('');
  $('#faParam').value = params.includes(curP) ? curP : '';
  $('#faIpList').innerHTML = (d.ips || []).map(x => `<option value="${tEscAttr(x.ip)}">`).join('');
  $('#faRules').innerHTML = Object.entries(d.rules || {}).map(([k, v]) => `<dt>${tEsc(k)}</dt><dd>${tEsc(v)}</dd>`).join('');
  faLoadList(true);
}
async function faLoadList(reset) {
  if (!FA.data || !FA.data.filter_requests) return;
  if (reset) { FA.items = []; FA.offset = 0; }
  const mode = $('#faMode').value;
  $('#faMinWrap').hidden = mode !== 'unique';
  const q = new URLSearchParams({ mode, target: $('#faTarget').value, param: $('#faParam').value, status_class: $('#faStatus').value,
    min_requests: $('#faMin').value, ip: ($('#faIp').value || '').trim(), sort: $('#faSort').value, limit: 200, offset: FA.offset });
  const seq = ++FA.lseq;
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/filter_attacks/requests?${q}`)); d = await r.json(); } catch (e) { return; }
  if (seq !== FA.lseq || !r.ok) return;
  FA.items = FA.items.concat(d.items); FA.offset += d.items.length; FA.total = d.total;
  const n = fmtN;
  if (mode === 'unique') {
    $('#faListCount').textContent = `(${n(d.unique_ips)} IP-uri unice · ${n(d.total_requests)} cereri)`;
    $('#faListHead').innerHTML = '<tr><th>IP</th><th>Tara</th><th class="num">Cereri</th><th class="num">URL-uri distincte</th><th class="num">4xx</th><th class="num">5xx</th><th>Prima</th><th>Ultima</th></tr>';
    $('#faList').innerHTML = FA.items.map(x => `<tr data-fa-ip="${tEscAttr(x.ip)}"><td><span class="incIp">${tEsc(x.ip)}</span></td><td>${tEsc(x.country || '??')}</td>
      <td class="num">${n(x.requests)}</td><td class="num">${n(x.distinct_urls)}</td><td class="num">${n(x['4xx'])}</td><td class="num">${n(x['5xx'])}</td>
      <td class="sfMuted">${tEsc(fmtEpoch(x.first_ts))}</td><td class="sfMuted">${tEsc(fmtEpoch(x.last_ts))}</td></tr>`).join('');
  } else {
    $('#faListCount').textContent = `(${n(d.total)} cereri -- toate aparitiile · ${n(d.unique_ips)} IP-uri unice)`;
    $('#faListHead').innerHTML = '<tr><th>Ora</th><th>IP</th><th>Tara</th><th>Metoda</th><th>URL</th><th class="num">Cod</th></tr>';
    $('#faList').innerHTML = FA.items.map(x => `<tr data-fa-ip="${tEscAttr(x.ip)}"><td class="sfMuted">${tEsc(fmtEpoch(x.ts))}</td><td><span class="incIp">${tEsc(x.ip)}</span></td>
      <td>${tEsc(x.country || '??')}</td><td>${tEsc(x.method)}</td><td class="faUrl">${tEsc(x.url)}</td><td class="num">${incCode(x.status)}</td></tr>`).join('');
  }
  if (!FA.items.length) $('#faList').innerHTML = '<tr><td colspan="8" class="sfMuted">Nicio cerere pentru filtrele alese. Scoate un filtru din lista de mai sus.</td></tr>';
  $('#faMore').hidden = FA.offset >= d.total;
  $('#faMore').textContent = `Incarca mai multe (${n(FA.offset)} din ${n(d.total)})`;
}
['faMode', 'faTarget', 'faParam', 'faStatus', 'faMin', 'faSort'].forEach(id => $('#' + id).addEventListener('change', () => faLoadList(true)));
$('#faIp').addEventListener('input', debounce(() => faLoadList(true), 350));
$('#faMore').addEventListener('click', () => faLoadList(false));
document.addEventListener('click', (e) => {
  const tr = e.target.closest('[data-fa-target]');
  if (tr) { $('#faTarget').value = $('#faTarget').value === tr.dataset.faTarget ? '' : tr.dataset.faTarget; document.querySelectorAll('[data-fa-target]').forEach(x => x.classList.toggle('sel', x.dataset.faTarget === $('#faTarget').value)); faLoadList(true); return; }
  const ipr = e.target.closest('[data-fa-ip]');
  if (ipr && e.target.closest('.incIp')) { XP.open('ip', ipr.dataset.faIp); }
});
function faPathToken() {
  // cel mai specific token prezent in toate cererile listei: parametrul ales sau cel dominant
  return $('#faParam').value && !$('#faParam').value.startsWith('(') ? $('#faParam').value : ((FA.data && FA.data.top_param) || 'filter_');
}
$('#faApply').addEventListener('click', () => {
  const t = $('#faTarget').value;
  TRIAGE.filters.pathContains = faPathToken().replace(/^\(.*\)$/, '');
  $('#triagePathFilter').value = TRIAGE.filters.pathContains;
  if (t && !t.endsWith('*fatete*')) TRIAGE.filters.pathExact = t;
  triageRenderActiveChips(); triageReloadAll();
  toast('Aplicatia e filtrata pe cererile care contin "' + TRIAGE.filters.pathContains + '"' + (t ? ' catre ' + t : ''));
});
$('#faExport').addEventListener('click', () => {
  const o = gfObject(); o.path_contains = faPathToken().replace(/^\(.*\)$/, '');
  const t = $('#faTarget').value; if (t && !t.endsWith('*fatete*')) o.path_exact = t;
  window.open(redactUrl(`/api/dataset/${DATASET_ID}/export_events?kind=sel&value=&format=log&gf=${encodeURIComponent(JSON.stringify(o))}`), '_blank');
});
const _faShow = showPage;
showPage = function (page) { _faShow.apply(this, arguments); if (CURRENT_PAGE === 'security') faLoad(); };
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') faLoad(); else FA.key = null; });
// ---------- v50: Retele -- IP-uri unice grupate (IP Explorer) ----------
const NET = { key: null, seq: 0, data: null, shown: 50 };
async function netLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready || !$('#netCard')) return;
  const group = $('#netGroup').value, max = $('#netMax').value;
  const key = [DATASET_ID, gfJSON(), group, max].join('|');
  if (!force && key === NET.key && NET.data) return;
  NET.key = key; NET.shown = 50;
  const seq = ++NET.seq;
  $('#netBusy').innerHTML = '<span class="spinner" style="width:11px;height:11px"></span> se calculează' + (group === 'asn' || group === 'block' ? ' (prima dată se încarcă baza de furnizori, ~1 s)' : '') + '...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/networks?group=${group}&max_hits=${max}&top=500`)); d = await r.json(); }
  catch (e) { if (seq === NET.seq) { $('#netBusy').textContent = 'Eroare de rețea: ' + e.message; } return; }
  if (seq !== NET.seq) return;
  if (!r.ok) { NET.data = null; $('#netBusy').textContent = d.error || ('HTTP ' + r.status); return; }
  NET.data = d; $('#netBusy').textContent = `calculat în ${fmtN(d.elapsed_ms)} ms`;
  netRender();
}
function netRender() {
  const d = NET.data; if (!d) return;
  const n = fmtN;
  $('#netVerdict').textContent = d.verdict || '';
  $('#netVerdict').style.display = d.verdict ? '' : 'none';
  const st = (l, v, attn) => `<span class="sfStat${attn ? ' attn' : ''}">${l} <b>${v}</b></span>`;
  const maxTxt = { 0: 'oricâte cereri', 1: 'o singură cerere', 3: '≤ 3 cereri', 10: '≤ 10 cereri' }[d.max_hits] || ('≤ ' + d.max_hits);
  $('#netStats').innerHTML = [
    st('IP-uri în selecție', n(d.selection_ips)),
    st('cu o singură cerere', `${n(d.single_hit_ips)} <span class="sfMuted">(${pct(d.single_hit_ips, d.selection_ips)})</span>`, d.selection_ips && d.single_hit_ips / d.selection_ips >= 0.5),
    d.max_hits === 1 ? '' : st(`IP-uri cu ${maxTxt}`, n(d.matched_ips)), st('cererile lor', n(d.matched_requests)),
    st('grupuri', n(d.n_groups || 0)), st('primele 10 acoperă', (d.top10_ips_pct != null ? String(d.top10_ips_pct).replace('.', ',') : '-') + ' %'),
    d.cloud_ips != null ? st('cloud / găzduire', `${n(d.cloud_ips)} <span class="sfMuted">(${pct(d.cloud_ips, d.matched_ips)})</span>`) : '',
    d.cloud_ips != null ? st('internet casnic / mobil', `${n(d.isp_ips)} <span class="sfMuted">(${pct(d.isp_ips, d.matched_ips)})</span>`) : '',
  ].join('');
  const gs = d.groups || [];
  if (!gs.length) { $('#netBody').innerHTML = '<div class="incNote">Niciun IP care să corespundă în selecția curentă.</div>'; return; }
  const asn = d.group === 'asn';
  const head = { asn: 'Furnizor (ASN)', block: 'Bloc de rețea', s24: 'Subnet', s16: 'Rețea' }[d.group];
  const maxIps = Math.max(1, ...gs.map(g => g.ips));
  const list = gs.slice(0, NET.shown);
  $('#netBody').innerHTML = `<div class="netTblWrap"><table class="autoTbl netTbl"><thead><tr><th>${head}</th>${asn ? '<th>Tip</th>' : ''}<th class="num">IP-uri</th><th></th><th class="num">Cereri</th><th>Țări</th><th>URL dominant</th><th class="num">5xx</th><th>Interval</th><th></th></tr></thead><tbody>` +
    list.map((g, i) => `<tr>
      <td><div class="netKey${asn ? '' : ' mono'}" title="${tEscAttr(g.key)}">${tEsc(g.key)}</div>${asn && g.cidrs.length ? `<div class="autoD mono">${tEsc(g.cidrs.slice(0, 2).join(', '))}${g.cidrs.length > 2 ? ` +${n(g.cidrs.length - 2)}` : ''}</div>` : ''}</td>
      ${asn ? `<td>${g.kind === 'cloud' ? '<span class="netKind cloud">cloud</span>' : g.kind === 'isp' ? '<span class="netKind isp">rezidențial</span>' : ''}</td>` : ''}
      <td class="num">${n(g.ips)}</td><td class="barCol"><span class="hbar" style="width:${Math.max(1, Math.round(100 * g.ips / maxIps))}%"></span></td>
      <td class="num">${n(g.requests)}</td>
      <td>${g.countries.map(c => `<span class="netCc" title="${tEscAttr(ccLabel(c.cc))}: ${n(c.ips)} IP">${flagHtml(c.cc)}${tEsc(c.cc)}</span>`).join('')}${g.n_countries > 4 ? `<span class="sfMuted">+${g.n_countries - 4}</span>` : ''}</td>
      <td class="mono netPath" title="${tEscAttr(g.top_path)}: ${n(g.top_path_requests)} cereri">${tEsc(g.top_path)}</td>
      <td class="num">${g.e5 ? `<span class="netE5">${n(g.e5)}</span>` : '0'}</td>
      <td class="autoD">${tEsc(fmtEpoch(g.ts_min))}<br>${tEsc(fmtEpoch(g.ts_max))}</td>
      <td class="netAct"><button type="button" class="ghost sfSmallBtn" data-net-wk="${i}" title="Deschide in Workplace: aceste blocuri de retea${d.max_hits ? ', doar IP-urile cu ' + maxTxt : ''}">Workplace</button><button type="button" class="ghost sfSmallBtn" data-net-copy="${i}" title="Copiaza blocurile CIDR (pentru reguli de blocare)">CIDR</button>${ruleBtn(netRuleSpec(d, g), 'Regulă')}</td></tr>`).join('') +
    '</tbody></table></div>' +
    (gs.length > NET.shown ? `<button type="button" class="ghost sfSmallBtn" id="netMore">Arată mai multe (${n(NET.shown)} din ${n(gs.length)}${d.n_groups > gs.length ? ' afișabile, ' + n(d.n_groups) + ' în total' : ''})</button>` : '');
}
$('#netGroup').addEventListener('change', () => netLoad());
$('#netMax').addEventListener('change', () => netLoad());
document.addEventListener('click', async (e) => {
  if (e.target.id === 'netMore') { NET.shown += 100; netRender(); return; }
  const cp = e.target.closest('[data-net-copy]');
  if (cp && NET.data) { const g = NET.data.groups[+cp.dataset.netCopy]; await copyToClipboard(g.cidrs.join('\n') + '\n'); toast(`Copiate ${g.cidrs.length} blocuri CIDR (${g.key})`); return; }
  const wk = e.target.closest('[data-net-wk]');
  if (!wk || !NET.data) return;
  const g = NET.data.groups[+wk.dataset.netWk];
  if (NET.data.group !== 'asn' && !g.cidrs.length) { toast('Grupul nu are blocuri de rețea cunoscute.'); return; }
  const conds = NET.data.group === 'asn'
    ? [{ field: 'asn', op: 'in', values: [g.key === '(furnizor necunoscut)' ? '__NONE__' : g.key] }]
    : [{ field: 'ip', op: 'cidr', values: g.cidrs }];
  if (NET.data.max_hits) conds.push({ field: 'ip_hits', op: 'range', values: [null, NET.data.max_hits] });
  if (await wkEnsureMeta()) { WK.conds = conds.map(wkMkCond); WK.period = 'global'; WK.offset = 0; }
  showPage('workplace'); wkSchedule();
});
GF_LISTENERS.push(() => { if (CURRENT_PAGE !== 'ip') NET.key = null; });
function netRuleSpec(d, g) {
  const conds = d.group === 'asn' ? [{ field: 'asn', op: 'in', values: [g.key === '(furnizor necunoscut)' ? '__NONE__' : g.key] }]
    : [{ field: 'ip', op: 'cidr', values: g.cidrs }];
  if (d.max_hits) conds.push({ field: 'ip_hits', op: 'range', values: [null, d.max_hits] });
  return { conds, label: g.key };
}

// ---------- v50: Activitate automata (boti, scanari, scraping) ----------
const AUTO = { key: null, seq: 0, data: null };
async function autoLoad(force) {
  if (!DATASET_ID || !TRIAGE.ready) return;
  const key = DATASET_ID + '|' + gfJSON();
  if (!force && key === AUTO.key && AUTO.data) return;
  AUTO.key = key;
  const seq = ++AUTO.seq;
  $('#autoMsg').className = 'incMsg'; $('#autoMsg').textContent = 'Se calculeaza activitatea automata...';
  let r, d;
  try { r = await fetch(gfUrl(`/api/dataset/${DATASET_ID}/automation`)); d = await r.json(); }
  catch (e) { if (seq === AUTO.seq) { $('#autoMsg').className = 'incMsg err'; $('#autoMsg').textContent = 'Eroare de retea: ' + e.message; } return; }
  if (seq !== AUTO.seq) return;
  if (!r.ok) { AUTO.data = null; $('#autoMsg').className = 'incMsg err'; $('#autoMsg').textContent = d.error || ('HTTP ' + r.status); return; }
  AUTO.data = d; $('#autoMsg').textContent = '';
  autoRender();
}
function autoRender() {
  const d = AUTO.data; if (!d) return;
  const cats = d.categories || [];
  const hit = cats.filter(c => c.requests > 0), none = cats.filter(c => !c.requests);
  const tot = Math.max(1, (GF.overview && GF.overview.requests) || 0);
  $('#autoBody').innerHTML = (hit.length ? `<table class="autoTbl"><thead><tr><th>Categorie</th><th class="num">Cereri</th><th class="num">IP-uri</th><th>IP-uri principale</th><th></th></tr></thead><tbody>` +
    hit.map(c => `<tr><td><div class="autoT">${tEsc(c.title)}</div><div class="autoD">${tEsc(c.desc)}</div></td>
      <td class="num">${fmtN(c.requests)}<div class="autoD">${GF.overview ? pct(c.requests, tot) : ''}</div></td><td class="num">${fmtN(c.ips)}</td>
      <td>${c.top.map(t => `<span class="autoIp" data-auto-ip="${tEscAttr(t.ip)}" title="Deschide IP-ul in panoul de explorare">${flagHtml(t.country)}${tEsc(t.ip)} <em>${fmtN(t.n)}</em></span>`).join('')}</td>
      <td><button type="button" class="ghost sfSmallBtn" data-auto-wk="${tEscAttr(c.key)}" title="Deschide in Workplace cu aceleasi conditii">Workplace</button>${ruleBtn({ conds: c.conds, label: c.title }, 'Regulă')}</td></tr>`).join('') + '</tbody></table>'
    : '<div class="incNote">Nicio activitate automata detectata in perioada selectata.</div>') +
    (none.length ? `<div class="autoNone">Fără activitate: ${tEsc(none.map(c => c.title).join(' · '))}.</div>` : '');
}
document.addEventListener('click', async (e) => {
  const ipEl = e.target.closest('[data-auto-ip]');
  if (ipEl) { XP.open('ip', ipEl.dataset.autoIp); return; }
  const wk = e.target.closest('[data-auto-wk]');
  if (!wk || !AUTO.data) return;
  const c = AUTO.data.categories.find(x => x.key === wk.dataset.autoWk); if (!c) return;
  if (await wkEnsureMeta()) { WK.conds = c.conds.map(wkMkCond); WK.period = 'global'; WK.offset = 0; }
  showPage('workplace'); wkSchedule();
});
const _autoShow = showPage;
showPage = function (page) { _autoShow.apply(this, arguments); if (CURRENT_PAGE === 'security') autoLoad(); };
GF_LISTENERS.push(() => { if (CURRENT_PAGE === 'security') autoLoad(); else AUTO.key = null; });
// in rezumatul executiv si in incidentul din Signal First
const _faSfIncHtml = sfIncHtml;
sfIncHtml = function (x) {
  if (x.kind !== 'filter_attack') return _faSfIncHtml(x);
  const h = _faSfIncHtml(Object.assign({}, x, { signals: {} }));
  return h.replace(/<div class="sfIncTools">[\s\S]*?<!--\/tools-->/, `<div class="sfIncTools"><button type="button" class="ghost sfSmallBtn" data-fa-goto>Vezi atacul pe filtre (IP-uri, cereri, tinte)</button>${ruleBtn({ kind: 'filter_attack', label: 'atac pe filtre' })}</div><!--/tools-->`);
};
const _faRelated = sfRelated;
sfRelated = function (x) { return x.kind === 'filter_attack' ? [] : _faRelated(x); };
document.addEventListener('click', (e) => { if (e.target.closest('[data-fa-goto]')) $('#faCard').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
const _faSfRender = sfRender;
sfRender = function () {
  _faSfRender();
  const e = SF.data && SF.data.exec; if (!e) return;
  $('#sfExec').insertAdjacentHTML('beforeend', `<span class="sfStat${e.filter_attack ? ' attn' : ''}">Atac pe filtre <b>${e.filter_attack ? 'DA' : 'nu'}</b>${e.filter_requests ? ` <span class="sfMuted">(${fmtN(e.filter_requests)} cereri / ${fmtN(e.filter_unique_ips)} IP-uri unice)</span>` : ''}</span>`);
};

// ======================================================================
// v51 -- REGULI DE BLOCARE gata de copiat, din orice loc: incident, categorie
// automata, Workplace, retea, IP. Serverul (/block_rules) alege strategia
// (IP / subnet / tipar / limitare de rata) din forma traficului.
// ruleBtn(spec) -> butonul; spec: { label, kind?, q?, conds?, ip?, pattern?, gf? }
// ======================================================================
const RULES = { specs: [], seq: 0 };
function ruleBtn(spec, text, cls) {
  const id = RULES.specs.push(spec) - 1;
  if (RULES.specs.length > 4000) RULES.specs.splice(0, 2000, ...new Array(2000).fill(null));
  return `<button type="button" class="ghost ruleBtn ${cls || 'sfSmallBtn'}" data-rule="${id}" title="Generează regula de blocare (Cloudflare / CSF / .htaccess) pentru exact acest trafic"><svg class="rbIco" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>${tEsc(text || 'Regulă de blocare')}</button>`;
}
function rulesClose() { $('#ruleOverlay').classList.remove('open'); RULES.seq++; }
async function rulesOpen(spec) {
  if (!DATASET_ID) return;
  const seq = ++RULES.seq;
  $('#rlTitle').textContent = 'Regulă de blocare -- ' + (spec.label || 'selecție');
  $('#rlSub').textContent = spec.q ? 'pentru rezultatul din Workplace' : 'în selecția: ' + gfDescribe();
  $('#rlBody').innerHTML = xpBusy('Se analizează traficul și se alege regula potrivită...');
  $('#ruleOverlay').classList.add('open');
  const body = Object.assign({ gf: spec.q ? '' : gfJSON() }, spec);
  let d;
  try {
    const r = await fetch(`/api/dataset/${DATASET_ID}/block_rules`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    d = await r.json();
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  } catch (e) { if (seq === RULES.seq) $('#rlBody').innerHTML = xpErr('Nu am putut genera regula: ' + e.message); return; }
  if (seq !== RULES.seq) return;
  RULES.cur = d;
  const opt = (o, i) => `<div class="rlOpt${o.recommended ? ' rec' : ''}">
      <div class="rlOptHead"><span class="rlTgt">${tEsc(o.target)}</span><strong>${tEsc(o.title)}</strong>${o.recommended ? '<span class="rlRec">Recomandat</span>' : ''}
        <button type="button" class="ghost sfSmallBtn" data-rl-copy="${i}">Copiază</button></div>
      <div class="rlMeta">Unde: <b>${tEsc(o.where)}</b> &middot; Acțiune: <b>${tEsc(o.action)}</b></div>
      <pre class="rlCode">${tEsc(o.text)}</pre>
      <div class="rlNote">${tEsc(o.note)}</div></div>`;
  const opts = d.options || [];
  const rec = opts.map((o, i) => [o, i]).filter(([o]) => o.recommended);
  const rest = opts.map((o, i) => [o, i]).filter(([o]) => !o.recommended);
  const pctSingle = d.ips ? Math.round(100 * d.single_hit_ips / d.ips) : 0;
  $('#rlBody').innerHTML = `<div class="rlWhy">${tEsc(d.why)}</div>
    <div class="rlStats"><span><b>${fmtN(d.requests)}</b> cereri</span><span><b>${fmtN(d.ips)}</b> IP-uri</span>
      <span><b>${pctSingle}%</b> cu o singură cerere</span>${d.ips ? `<span><b>${fmtN(d.cloud_ips)}</b> din cloud / hosting</span>` : ''}</div>` +
    ((d.unmapped || []).length ? `<div class="rlWarn">Nu se pot exprima într-o regulă de firewall: ${tEsc(d.unmapped.join(', '))}. Regula de pe tipar e deci mai largă decât selecția -- de aceea e propusă și lista de IP-uri / subrețele a selecției.</div>` : '') +
    (opts.length ? rec.map(([o, i]) => opt(o, i)).join('') +
      (rest.length ? `<details class="rlMore"${rec.length ? '' : ' open'}><summary>Alte variante (${rest.length})</summary>${rest.map(([o, i]) => opt(o, i)).join('')}</details>` : '')
      : '<div class="incNote">Nimic de blocat în această selecție.</div>') +
    ((d.top_ips || []).length ? `<div class="rlIps">IP-uri principale: ${d.top_ips.map(x => `<code>${tEsc(x.ip)}</code> ${fmtN(x.n)}`).join(' &middot; ')}</div>` : '');
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-rule]');
  if (b) { e.preventDefault(); e.stopPropagation(); const sp = RULES.specs[+b.dataset.rule]; if (sp) rulesOpen(typeof sp === 'function' ? sp() : sp); return; }
  const c = e.target.closest('[data-rl-copy]');
  if (c && RULES.cur) { copyText(RULES.cur.options[+c.dataset.rlCopy].text); return; }
  if (e.target.id === 'ruleOverlay' || e.target.closest('#rlClose') || (e.target.closest('#ruleOverlay [data-xopen]'))) rulesClose();
}, true);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#ruleOverlay').classList.contains('open')) { e.stopPropagation(); rulesClose(); } }, true);

// ======================================================================
// v51 -- "CE S-A INTAMPLAT": 3-5 concluzii in limbaj simplu, imediat dupa
// upload, fiecare cu actiunile ei (dovezile + regula de blocare). Surse:
// incidentele (/brief), activitatea automata, retelele IP-urilor unice si
// sinteza selectiei (5xx, IP dominant). Recalculat la fiecare selectie.
// ======================================================================
function gotoCard(page, sel) {
  showPage(page);
  let n = 0;
  const t = setInterval(() => {
    const el = document.querySelector(sel);
    if ((el && el.offsetParent && el.offsetHeight > 40) || ++n > 40) {
      clearInterval(t);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, 150);
}
async function wkOpenConds(conds) {
  if (await wkEnsureMeta()) { WK.conds = conds.map(wkMkCond); WK.period = 'global'; WK.offset = 0; }
  showPage('workplace'); wkSchedule();
}
const FIND = { seq: 0, acts: [] };
function findAct(text, fn, primary) {
  const id = FIND.acts.push(fn) - 1;
  return `<button type="button" class="${primary ? 'primary' : 'ghost'} sfSmallBtn" data-find="${id}">${tEsc(text)}</button>`;
}
document.addEventListener('click', (e) => { const b = e.target.closest('[data-find]'); if (b && FIND.acts[+b.dataset.find]) FIND.acts[+b.dataset.find](); });
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 1, OK: 0 };
async function ovFindings(d) {
  const box = $('#ovFind'); if (!box) return;
  const seq = ++FIND.seq;
  box.innerHTML = `<div class="cardHead"><h2>Ce s-a întâmplat</h2><span class="cardHint">concluziile pentru selecția curentă</span></div>` + xpBusy('Se analizează selecția...');
  let br, au, nw;
  try {
    [br, au, nw] = await Promise.all([
      xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/brief`)),
      xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/automation`)).catch(() => null),
      xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/networks?group=asn&max_hits=1&top=3`)).catch(() => null),
    ]);
  } catch (e) { if (seq === FIND.seq) box.innerHTML = `<div class="cardHead"><h2>Ce s-a întâmplat</h2></div>` + xpErr('Nu am putut calcula concluziile: ' + e.message); return; }
  if (seq !== FIND.seq) return;
  FIND.acts = [];
  const tot = Math.max(1, d.requests || 0);
  const P = n => pct(n, tot);
  const F = [];
  const incs = (br.incidents || []).slice().sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
  const fa = incs.find(x => x.kind === 'filter_attack');
  if (fa) {
    const t = (fa.affected || [])[0] || '';
    const e5 = br.exec ? null : null;
    F.push({ sev: fa.severity, title: 'Atac distribuit pe filtrele magazinului' + (t ? ` (${t})` : ''),
      text: `${fmtN(br.exec.filter_requests)} cereri cu parametri de filtrare (${P(br.exec.filter_requests)} din trafic), de la ${fmtN(br.exec.filter_unique_ips)} IP-uri diferite. ` +
        `Fiecare combinație de filtre e o pagină generată de PHP + MySQL, necache-uită -- ` + ((fa.why || [])[0] ? tEsc(fa.why[0]) + '.' : 'încarcă serverul.'),
      acts: findAct('Vezi atacul', () => gotoCard('security', '#faCard'), true) + findAct('IP-urile pe rețele', () => gotoCard('ip', '#netCard')) +
        ruleBtn({ kind: 'filter_attack', label: 'atac pe filtre' + (t ? ' ' + t : '') }) });
  }
  incs.filter(x => x.kind !== 'filter_attack').slice(0, 3).forEach(x => {
    F.push({ sev: x.severity, title: x.title.replace(/^[A-Z ĂÂÎȘȚ]+ -- /, m => m.charAt(0) + m.slice(1).toLowerCase()),
      text: tEsc((x.observed || [])[0] || x.interpretation || ''),
      acts: findAct('Profil IP', () => XP.open('ip', x.ip), true) + findAct('Detalii în Securitate', () => gotoCard('security', '#sfIncs')) + ruleBtn({ ip: x.ip, label: x.ip }) });
  });
  if (nw && nw.single_hit_ips >= 500 && nw.single_hit_ips >= 0.5 * nw.selection_ips) {
    const isp = nw.isp_ips != null ? Math.round(100 * nw.isp_ips / Math.max(1, nw.matched_ips)) : null;
    F.push({ sev: isp != null && isp >= 70 ? 'HIGH' : 'MEDIUM', title: 'Mii de IP-uri cu o singură cerere -- rotație de proxy-uri',
      text: `${fmtN(nw.single_hit_ips)} din ${fmtN(nw.selection_ips)} IP-uri au făcut o singură cerere` + (isp != null ? `, ${isp}% de la operatori de internet (rezidențial / mobil)` : '') +
        `, împrăștiate pe ${fmtN(nw.n_groups)} rețele. Blocarea pe IP nu ajută: fiecare adresă vine o singură dată.`,
      acts: findAct('Vezi rețelele', () => gotoCard('ip', '#netCard'), true) + findAct('Deschide în Workplace', () => wkOpenConds([{ field: 'ip_hits', op: 'range', values: [null, 1] }])) +
        ruleBtn({ conds: [{ field: 'ip_hits', op: 'range', values: [null, 1] }], label: 'IP-uri cu o singură cerere' }) });
  }
  const e5 = d.err_5xx || 0;
  if (e5 / tot >= 0.03 && e5 >= 50) {
    F.push({ sev: e5 / tot >= 0.08 ? 'HIGH' : 'MEDIUM', title: 'Serverul a cedat la o parte din cereri (erori 5xx)',
      text: `${fmtN(e5)} răspunsuri 5xx (${P(e5)} din cereri)` + (fa && fa.signals ? '; o parte coincid cu atacul pe filtre de mai sus' : '') +
        '. Vizitatorii reali primesc pagini de eroare în aceste momente.',
      acts: findAct('Vezi erorile', () => { triageSetSingleFilter('sclass', '5xx'); showPage('errors'); }, true) });
  }
  const cats = ((au && au.categories) || []).filter(c => c.requests >= Math.max(20, 0.01 * tot)).sort((a, b) => b.requests - a.requests);
  cats.slice(0, 2).forEach(c => {
    F.push({ sev: ['vuln_scan', 'scan_tools', 'brute_login', 'fake_bots'].includes(c.key) ? 'HIGH' : 'MEDIUM', title: c.title,
      text: `${fmtN(c.ips)} IP-uri, ${fmtN(c.requests)} cereri (${P(c.requests)}). ${tEsc(c.desc)}` +
        (c.top.length ? ` Principalul: <a href="#" data-ek="ip" data-ev="${tEscAttr(c.top[0].ip)}" data-xopen="1">${flagHtml(c.top[0].country)}${tEsc(c.top[0].ip)}</a> (${fmtN(c.top[0].n)}).` : ''),
      acts: findAct('Deschide în Workplace', () => wkOpenConds(c.conds), true) + ruleBtn({ conds: c.conds, label: c.title }) });
  });
  const top = (d.top_ips || [])[0];
  if (top && top.n / tot >= 0.08 && !F.some(f => f.text.includes(top.ip))) {
    F.push({ sev: top.n / tot >= 0.2 ? 'HIGH' : 'MEDIUM', title: `Un singur IP face ${P(top.n)} din trafic`,
      text: `<a href="#" data-ek="ip" data-ev="${tEscAttr(top.ip)}" data-xopen="1">${flagHtml(top.country)}${tEsc(top.ip)}</a> -- ${fmtN(top.n)} cereri. Verifică dacă e un crawler legitim, un monitor sau un script.`,
      acts: findAct('Profil IP', () => XP.open('ip', top.ip), true) + ruleBtn({ ip: top.ip, label: top.ip }) });
  }
  F.sort((a, b) => (SEV_RANK[b.sev] || 0) - (SEV_RANK[a.sev] || 0));
  const shown = F.slice(0, 5);
  const sevLbl = { CRITICAL: 'CRITIC', HIGH: 'RIDICAT', MEDIUM: 'MEDIU', LOW: 'INFO', INFO: 'INFO' };
  box.innerHTML = `<div class="cardHead"><h2>Ce s-a întâmplat</h2><span class="cardHint">${shown.length ? `${shown.length} ${shown.length === 1 ? 'concluzie' : 'concluzii'} pentru selecția curentă` : 'selecția curentă'}</span></div>` +
    (shown.length ? '<div class="ovFList">' + shown.map(f => `<div class="ovF sev-${tEscAttr(f.sev)}">
        <div class="ovFSev"><span class="ovFTag">${sevLbl[f.sev] || f.sev}</span></div>
        <div class="ovFMain"><div class="ovFT">${tEsc(f.title)}</div><div class="ovFX">${f.text}</div><div class="ovFA">${f.acts}</div></div></div>`).join('') + '</div>'
      : `<div class="ovF sev-OK"><div class="ovFSev"><span class="ovFTag">OK</span></div><div class="ovFMain"><div class="ovFT">Nimic neobișnuit în selecție</div>
          <div class="ovFX">Niciun atac, nicio activitate automată semnificativă, erorile de server sub 3%. Detaliile complete sunt mai jos.</div></div></div>`) +
    (F.length > shown.length ? `<div class="incNote">Încă ${F.length - shown.length} în <a href="#" data-goto="security">Security &amp; Triaj</a>.</div>` : '');
  // fraza de securitate din rezumat tine cont si de incidente (atacul pe filtre nu e un "eveniment" pe linie)
  if (incs.length) {
    const p = [...$('#ovLeadText').querySelectorAll('p')].find(x => x.textContent.startsWith('Securitate:'));
    const hi = incs.filter(x => x.severity === 'HIGH' || x.severity === 'CRITICAL').length;
    if (p && hi) p.innerHTML = `Securitate: <b class="tHigh">${fmtN(hi)} ${hi === 1 ? 'incident' : 'incidente'} ${incs[0].severity}</b> -- vezi „Ce s-a întâmplat” de mai sus.`;
  }
}
const _v51RenderOverview = renderOverview;
renderOverview = async function () {
  const r = await _v51RenderOverview.apply(this, arguments);
  if (CURRENT_PAGE === 'overview' && TRIAGE.ready) {
    try { const d = await selData(); if (CURRENT_PAGE === 'overview' && d.requests) ovFindings(d); else if (!d.requests) $('#ovFind').innerHTML = ''; } catch (e) {}
  }
  return r;
};
MOD_HOOKS.overview = renderOverview;

// ======================================================================
// v51 -- PROFIL IP complet in panoul lateral: furnizor, bloc, tip (cloud /
// rezidential), crawler verificat, vecinii din aceeasi retea si de la acelasi
// furnizor, un verdict in limbaj simplu si regula de blocare. Plus butonul
// "Regula" pentru orice entitate deschisa (IP, URL, tara, User-Agent).
// ======================================================================
function xpRuleSpec(kind, value) {
  const c = { ip: { field: 'ip', op: 'in', values: [value] }, path: { field: 'path_only', op: 'exact', values: [value] },
              prefix: { field: 'path', op: 'contains', values: [value] }, country: { field: 'country', op: 'in', values: [value] },
              ua: value ? { field: 'ua', op: 'exact', values: [value] } : { field: 'ua', op: 'empty', values: [] },
              method: { field: 'method', op: 'in', values: [value] } }[kind];
  if (kind === 'sel') return { label: 'selecția curentă' };
  return c ? { conds: [c], label: entLabel(kind, value) } : null;
}
function xpVerdict(d, id) {
  const rpm = +d.req_per_min || 0, err = d.requests ? (d.err_4xx + d.err_5xx) / d.requests : 0;
  if (id.crawler === 'verified') return ['ok', 'Crawler legitim, verificat prin DNS -- nu-l bloca (ar afecta indexarea în motoarele de căutare).'];
  if (id.crawler === 'fake') return ['bad', 'Se prezintă drept crawler (Googlebot / Bingbot...), dar IP-ul nu aparține motorului: boț fals.'];
  const why = [];
  if (id.kind === 'cloud') why.push(`vine din cloud / hosting (${id.asn}), nu de la un operator de internet`);
  if (rpm >= 30) why.push(`ritm de ${String(rpm).replace('.', ',')} cereri / minut`);
  if (d.unique_paths >= 150) why.push(`${fmtN(d.unique_paths)} URL-uri diferite`);
  if (d.requests >= 20 && err >= 0.5) why.push(`${Math.round(100 * err)}% din cereri primesc erori (caută căi care nu există)`);
  if (d.unique_uas >= 5) why.push(`${fmtN(d.unique_uas)} User-Agent-uri diferite`);
  const bot = ((d.user_agents || [])[0] || {}).ua || '';
  const bm = bot.match(/([A-Za-z][\w-]*(?:bot|crawler|spider))\b/i);
  if (bm) why.unshift(`se declară „${bm[1]}”`);
  if (why.length >= 2 || (why.length && d.requests >= 500)) return ['bad', 'Trafic automat: ' + why.join('; ') + '.'];
  if (why.length) return ['warn', 'De urmărit: ' + why.join('; ') + '.'];
  return ['ok', 'Comportament compatibil cu un vizitator obișnuit' + (id.kind === 'isp' ? ' (conexiune de internet rezidențială / mobilă).' : '.')];
}
async function xpIdentFill(v, d) {
  const box = $('#xpIdent'); if (!box) return;
  let id;
  try { id = await xpFetchJSON(gfUrl(`/api/dataset/${DATASET_ID}/ip_identity?ip=${encodeURIComponent(v.value)}`)); }
  catch (e) { box.innerHTML = `<div class="spMsg">Identitate indisponibilă: ${tEsc(e.message)}</div>`; return; }
  if (!document.body.contains(box)) return;
  const [lv, txt] = xpVerdict(d, id);
  const kind = id.kind === 'cloud' ? '<span class="xpIdK cloud">cloud / hosting</span>' : id.kind === 'isp' ? '<span class="xpIdK isp">rezidențial / mobil</span>' : '';
  const cr = id.crawler === 'verified' ? '<span class="xpIdK ok">crawler verificat DNS</span>' : id.crawler === 'fake' ? '<span class="xpIdK bad">crawler FALS</span>' : '';
  const ua = (d.user_agents || [])[0];
  const net = id.subnet || '';
  box.innerHTML = `<div class="xpVerd ${lv}">${tEsc(txt)}</div>
    <div class="xpIdGrid">
      <div class="k">Furnizor</div><div class="v">${tEsc(id.asn || 'necunoscut')} ${kind} ${cr}</div>
      ${id.cidr ? `<div class="k">Bloc de rețea</div><div class="v"><code>${tEsc(id.cidr)}</code></div>` : ''}
      ${net ? `<div class="k">Aceeași rețea</div><div class="v"><code>${tEsc(net)}</code>: <b>${fmtN(id.subnet_ips || 0)}</b> IP-uri, ${fmtN(id.subnet_requests || 0)} cereri în selecție
        ${(id.subnet_ips || 0) > 1 ? `<a href="#" class="xpIdLnk" data-xid-wk="cidr">vezi în Workplace</a>` : ''}</div>` : ''}
      ${id.asn ? `<div class="k">Același furnizor</div><div class="v"><b>${fmtN(id.asn_ips || 0)}</b> IP-uri, ${fmtN(id.asn_requests || 0)} cereri <a href="#" class="xpIdLnk" data-xid-wk="asn">vezi în Workplace</a></div>` : ''}
      ${ua ? `<div class="k">User-Agent</div><div class="v xpIdUa">${tEsc(ua.ua || '(gol)')}${(d.user_agents || []).length > 1 ? ` <span class="xpHint">+ încă ${(d.user_agents.length - 1)}</span>` : ''}</div>` : ''}
    </div>
    <div class="xpIdAct">${ruleBtn({ ip: v.value, label: v.value }, 'Regulă de blocare pentru IP')}${net && (id.subnet_ips || 0) > 1 ? ruleBtn({ conds: [{ field: 'ip', op: 'cidr', values: [net] }], label: 'rețeaua ' + net }, 'Regulă pentru rețeaua ' + net) : ''}</div>`;
  if (lv !== 'ok') {
    // pragurile vechi ("Niciun prag depasit") ar contrazice verdictul de mai sus
    const secs = [...$('#xpBody').querySelectorAll('.ipProfSec')].filter(x => x.textContent === 'Comportament');
    secs.forEach(x => { const n = x.nextElementSibling; if (n && n.textContent.startsWith('Niciun prag')) { n.remove(); x.remove(); } });
  }
  box.querySelectorAll('[data-xid-wk]').forEach(a => a.onclick = (e) => {
    e.preventDefault();
    wkOpenConds([a.dataset.xidWk === 'asn' ? { field: 'asn', op: 'in', values: [id.asn] } : { field: 'ip', op: 'cidr', values: [net] }]);
  });
}
const _v51Sum = xpSumHtml;
xpSumHtml = function (v, d) {
  const h = _v51Sum(v, d);
  if (v.kind !== 'ip') return h;
  setTimeout(() => xpIdentFill(v, d), 0);
  return `<div class="xpIdent" id="xpIdent">${xpBusy('Se identifică furnizorul și rețeaua...')}</div>` + h;
};
const _v51RenderEntity = xpRenderEntity;
xpRenderEntity = function (v, seq) {
  const r = _v51RenderEntity(v, seq);
  const sp = xpRuleSpec(v.kind, v.value);
  if (sp) $('#xpActions').insertAdjacentHTML('afterbegin', ruleBtn(sp, 'Regulă', 'xpRuleBtn'));
  return r;
};

// ======================================================================
// v51 -- BARA COMPACTA (fixa sus, apare cand panglica perioadei iese din
// ecran): mini-grafic pe tot logul cu selectie prin tragere, filtrele active
// (cu x), Reseteaza tot, Copiaza link, Compara perioade.
// ======================================================================
const CBAR = { buckets: [], bsec: 0, key: null, drag: null, visible: false };
function ctxContentGf() { const o = gfObject(); delete o.ts_from; delete o.ts_to; return Object.keys(o).length ? JSON.stringify(o) : ''; }
async function ctxLoadHist() {
  if (!TRIAGE.ready || TRIAGE.boundsFrom == null) return;
  const gf = ctxContentGf(), key = DATASET_ID + '|' + gf;
  if (key === CBAR.key) { ctxDraw(); return; }
  CBAR.key = key;
  const a = Math.floor(TRIAGE.boundsFrom), b = Math.floor(TRIAGE.boundsTo);
  const bucket = pickBucketSeconds(Math.max(1, b - a));
  const p = new URLSearchParams({ bucket_seconds: bucket, ts_from: a, ts_to: b });
  if (gf) p.set('gf', gf);
  try {
    const d = await xpFetchJSON(`/api/dataset/${DATASET_ID}/histogram?${p}`);
    if (CBAR.key !== key) return;
    CBAR.buckets = d.buckets || []; CBAR.bsec = d.bucket_seconds || bucket;
  } catch (e) { CBAR.buckets = []; }
  ctxDraw();
}
function ctxGeom() {
  const cv = $('#ctxHist'), r = cv.getBoundingClientRect();
  return { cv, w: r.width, h: r.height, a: TRIAGE.boundsFrom, b: TRIAGE.boundsTo + 1 };
}
function ctxX2T(x) { const g = ctxGeom(); return g.a + Math.max(0, Math.min(1, x / g.w)) * (g.b - g.a); }
function ctxDraw() {
  const cv = $('#ctxHist'); if (!cv || !CBAR.visible) return;
  const g = ctxGeom(), dpr = window.devicePixelRatio || 1;
  cv.width = Math.round(g.w * dpr); cv.height = Math.round(g.h * dpr);
  const c = cv.getContext('2d'); c.scale(dpr, dpr); c.clearRect(0, 0, g.w, g.h);
  const max = Math.max(1, ...CBAR.buckets.map(x => x.total));
  const span = g.b - g.a;
  const sa = gfTimeNarrowed() ? TRIAGE.tsFrom : null, sb = gfTimeNarrowed() ? TRIAGE.tsTo + 1 : null;
  CBAR.buckets.forEach(x => {
    const x0 = (x.bucket - g.a) / span * g.w, bw = Math.max(1, CBAR.bsec / span * g.w - 0.5);
    const hh = Math.max(1, (x.total / max) * (g.h - 3));
    const inSel = sa == null || (x.bucket + CBAR.bsec > sa && x.bucket < sb);
    c.fillStyle = inSel ? (x.critical ? '#D2384C' : x.high ? '#E08A1E' : 'rgba(11,110,115,.7)') : 'rgba(120,130,140,.28)';
    c.fillRect(x0, g.h - hh, bw, hh);
  });
  const sel = CBAR.drag ? [Math.min(CBAR.drag.t0, CBAR.drag.t1), Math.max(CBAR.drag.t0, CBAR.drag.t1)] : (sa != null ? [sa, sb] : null);
  if (sel) {
    const x0 = (sel[0] - g.a) / span * g.w, x1 = (sel[1] - g.a) / span * g.w;
    c.fillStyle = 'rgba(11,110,115,.10)'; c.fillRect(x0, 0, Math.max(2, x1 - x0), g.h);
    c.strokeStyle = 'rgba(11,110,115,.9)'; c.lineWidth = 1.5; c.strokeRect(x0 + .75, .75, Math.max(2, x1 - x0) - 1.5, g.h - 1.5);
  }
}
function ctxRender() {
  const bar = $('#ctxBar'); if (!bar) return;
  const show = !!DATASET_ID && TRIAGE.ready && !CBAR.ribbonVisible && $('#globalFilterBar').style.display !== 'none';
  if (show !== CBAR.visible) { CBAR.visible = show; bar.hidden = !show; }
  if (!show) return;
  const src = $('#triageActiveFilters');
  const n = src ? src.children.length : 0;
  $('#ctxChips').innerHTML = n ? [...src.children].map((el, i) => `<span class="filterChip${el.classList.contains('neg') ? ' neg' : ''}" data-ctxi="${i}">${tEsc(el.firstChild ? el.textContent.replace(/×$/, '') : '')}<span class="x" role="button" aria-label="Elimină filtrul">&times;</span></span>`).join('')
    : '<span class="ctxNone">fără filtre &middot; tot logul</span>';
  $('#ctxReset').disabled = !n;
  ctxLoadHist();
}
document.addEventListener('click', (e) => {
  const x = e.target.closest('#ctxChips .x');
  if (x) { const i = +x.parentElement.dataset.ctxi; const o = $('#triageActiveFilters').children[i]; if (o) o.querySelector('.x').click(); return; }
  if (e.target.closest('#ctxReset')) { $('#triageResetBtn').click(); return; }
  if (e.target.closest('#ctxLink')) { linkCopy(); return; }
  if (e.target.closest('#ctxCmp')) { cmpOpen(); return; }
});
(function ctxWire() {
  const cv = $('#ctxHist');
  const tip = (e) => {
    const r = cv.getBoundingClientRect(), t = ctxX2T(e.clientX - r.left);
    const bk = CBAR.buckets.find(x => t >= x.bucket && t < x.bucket + CBAR.bsec);
    cv.title = `${fmtShortTs(Math.floor(t))}${bk ? ' · ' + fmtN(bk.total) + ' cereri' : ''} -- trage ca să alegi perioada, dublu-click: tot logul`;
  };
  cv.addEventListener('mousedown', (e) => { const r = cv.getBoundingClientRect(); const t = ctxX2T(e.clientX - r.left); CBAR.drag = { t0: t, t1: t, x0: e.clientX }; e.preventDefault(); });
  window.addEventListener('mousemove', (e) => {
    if (!CBAR.drag) { if (e.target === cv) tip(e); return; }
    const r = cv.getBoundingClientRect(); CBAR.drag.t1 = ctxX2T(e.clientX - r.left); ctxDraw();
  });
  window.addEventListener('mouseup', (e) => {
    const d = CBAR.drag; if (!d) return; CBAR.drag = null;
    let a, b;
    if (Math.abs(e.clientX - d.x0) < 4) {     // click: intervalul barei
      const bk = CBAR.buckets.find(x => d.t0 >= x.bucket && d.t0 < x.bucket + CBAR.bsec);
      if (!bk) { ctxDraw(); return; }
      a = bk.bucket; b = bk.bucket + CBAR.bsec - 1;
    } else { a = Math.floor(Math.min(d.t0, d.t1)); b = Math.ceil(Math.max(d.t0, d.t1)); }
    triageSetRange(a, b);
  });
  cv.addEventListener('dblclick', () => { if (TRIAGE.boundsFrom != null) triageSetRange(TRIAGE.boundsFrom, TRIAGE.boundsTo); });
  const io = new IntersectionObserver((ents) => { ents.forEach(en => { CBAR.ribbonVisible = en.isIntersecting; }); ctxRender(); }, { rootMargin: '-90px 0px 0px 0px' });
  io.observe($('.gfRibbon'));
  window.addEventListener('resize', debounce(ctxDraw, 150));
})();
const _v51Chips = triageRenderActiveChips;
// la schimbari rapide (tragere pe grafic, click-uri succesive) bara si adresa se actualizeaza o data, la final
const ctxLater = debounce(() => { ctxRender(); linkSync(); }, 200);
triageRenderActiveChips = function () { const r = _v51Chips.apply(this, arguments); ctxLater(); return r; };
GF_LISTENERS.push(ctxLater);
const _v51Show = showPage;
showPage = function () { const r = _v51Show.apply(this, arguments); ctxLater(); return r; };

// ======================================================================
// v52 -- LINK care reproduce ecranul, integral in fragment:
// #<pagina>?d=<analiza>&v=<filtre + perioada + Workplace>. Fragmentul nu e
// trimis serverului (filtrele/ID-ul nu ajung in loguri de acces); analiza e
// cea din memoria aplicatiei, iar dupa restart linkul cere reincarcarea.
// ======================================================================
const LINK = { pending: null };
function b64e(s) { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64d(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return decodeURIComponent(escape(atob(s))); }
function linkState() {
  const st = { f: TRIAGE.filters };
  if (gfTimeNarrowed()) { st.a = Math.floor(TRIAGE.tsFrom); st.b = Math.floor(TRIAGE.tsTo); }
  if (CURRENT_PAGE === 'workplace' && typeof WK !== 'undefined' && WK.conds.length)
    st.wk = { conds: WK.conds.map(c => ({ field: c.field, op: c.op, values: c.values, not: c.not, off: c.off })), period: WK.period, from: WK.from, to: WK.to };
  return st;
}
function linkUrl() {
  const p = new URLSearchParams({ d: DATASET_ID });
  const st = linkState();
  if (JSON.stringify(st) !== JSON.stringify({ f: emptyTriageFilters() })) p.set('v', b64e(JSON.stringify(st)));
  return location.origin + location.pathname + '#' + CURRENT_PAGE + '?' + p;
}
function linkSync() {
  if (!DATASET_ID || !TRIAGE.ready || LINK.applying) return;
  try { history.replaceState(history.state, '', linkUrl()); } catch (e) {}
}
function linkCopy() { linkSync(); copyText(linkUrl()); toast('Link copiat -- deschide exact acest ecran cât timp aplicația rulează.'); }
async function linkApply(st) {
  if (!st) return;
  LINK.applying = true;
  try {
    TRIAGE.filters = Object.assign(emptyTriageFilters(), st.f || {});
    TRIAGE.filters.x = Object.assign(emptyTriageFilters().x, (st.f || {}).x || {});
    $('#triageIpFilter').value = TRIAGE.filters.ip || ''; $('#triagePathFilter').value = TRIAGE.filters.pathContains || '';
    if (st.a != null && st.b != null) triageSetRange(st.a, st.b, true);
    triageRenderMultiSelects();
    _v51Chips();
    triageReloadAll();
    if (st.wk && await wkEnsureMeta()) {
      WK.conds = st.wk.conds.map(c => Object.assign(wkMkCond(c), { off: !!c.off }));
      WK.period = st.wk.period || 'global'; WK.from = st.wk.from; WK.to = st.wk.to; WK.offset = 0;
      if (CURRENT_PAGE === 'workplace') { showPage('workplace', true); wkSchedule(); }
    }
  } finally { LINK.applying = false; linkSync(); }
}
const _v51AfterReady = gfAfterIndexReady;
gfAfterIndexReady = function () {
  const r = _v51AfterReady.apply(this, arguments);
  if (LINK.pending) { const st = LINK.pending; LINK.pending = null; setTimeout(() => linkApply(st), 0); }
  ctxRender();
  return r;
};
(async function linkBoot() {
  const rawHash = (location.hash || '').replace(/^#/, '');
  const hashQuery = rawHash.includes('?') ? rawHash.slice(rawHash.indexOf('?') + 1) : '';
  const q = new URLSearchParams(hashQuery || location.search);
  const id = q.get('d'); if (!id || !/^[0-9a-f]{32}$/.test(id)) return;
  try { LINK.pending = q.get('v') ? JSON.parse(b64d(q.get('v'))) : null; } catch (e) { LINK.pending = null; }
  try {
    const r = await fetch(`/api/dataset/${id}/reopen`);
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || r.status);
    dropzone.style.display = 'none';
    _onUploadSuccess(d);
  } catch (e) {
    try { history.replaceState(null, '', location.pathname + '#overview'); } catch (e2) {}
    const dz = document.querySelector('#dropzone .dzSub');
    if (dz) dz.insertAdjacentHTML('afterend', `<p class="dzLink">Linkul deschis se referă la o analiză care nu mai e în memorie (aplicația a fost repornită). Încarcă din nou fișierul${LINK.pending ? ' -- filtrele și perioada din link se aplică automat' : ''}.</p>`);
  }
})();

// ======================================================================
// v51 -- COMPARA PERIOADE: A (referinta) fata de B, pe aceleasi filtre.
// Ce e nou in B, ce a crescut (rata pe ora), ce a disparut.
// ======================================================================
const CMP = { seq: 0 };
function cmpDefaults() {
  const lo = Math.floor(TRIAGE.boundsFrom), hi = Math.floor(TRIAGE.boundsTo);
  let b0, b1;
  if (gfTimeNarrowed()) { b0 = Math.floor(TRIAGE.tsFrom); b1 = Math.floor(TRIAGE.tsTo); }
  else { const mid = Math.floor((lo + hi) / 2); return [lo, mid, mid + 1, hi]; }
  const len = b1 - b0 + 1;
  let a1 = b0 - 1, a0 = a1 - len + 1;
  if (a0 < lo) { a0 = lo; a1 = Math.max(lo, b0 - 1); }
  if (a1 <= a0) { a0 = b1 + 1; a1 = Math.min(hi, b1 + len); }   // nimic inainte: compara cu ce urmeaza
  return [a0, a1, b0, b1];
}
function cmpPresets() {
  const lo = Math.floor(TRIAGE.boundsFrom), hi = Math.floor(TRIAGE.boundsTo), mid = Math.floor((lo + hi) / 2);
  const P = [['Prima jumătate vs. a doua', [lo, mid, mid + 1, hi]]];
  if (gfTimeNarrowed()) P.unshift(['Selecția vs. aceeași durată dinainte', cmpDefaults()]);
  if (hi - lo > 2 * 86400) P.push(['Ultimele 24 h vs. cele 24 h dinainte', [hi - 2 * 86400 + 1, hi - 86400, hi - 86400 + 1, hi]]);
  if (hi - lo > 2 * 3600) P.push(['Ultima oră vs. ora dinainte', [hi - 7199, hi - 3600, hi - 3599, hi]]);
  return P;
}
function cmpOpen() {
  if (!TRIAGE.ready) return;
  const [a0, a1, b0, b1] = cmpDefaults();
  const dt = e => epochToDtLocal(e, TRIAGE.tzOffset);
  $('#rlTitle').textContent = 'Compară perioade';
  $('#rlSub').textContent = 'aceleași filtre: ' + gfDescribe({ contentOnly: true });
  $('#rlBody').innerHTML = `<div class="cmpForm">
      <div class="cmpSide"><div class="cmpLbl"><span class="cmpTag a">A</span> perioada de referință</div>
        <input type="datetime-local" step="1" id="cmpA0" value="${dt(a0)}"><span>până la</span><input type="datetime-local" step="1" id="cmpA1" value="${dt(a1)}"></div>
      <div class="cmpSide"><div class="cmpLbl"><span class="cmpTag b">B</span> perioada analizată</div>
        <input type="datetime-local" step="1" id="cmpB0" value="${dt(b0)}"><span>până la</span><input type="datetime-local" step="1" id="cmpB1" value="${dt(b1)}"></div>
      <div class="cmpPresets">${cmpPresets().map((p, i) => `<button type="button" class="ghost sfSmallBtn" data-cmpp="${i}">${tEsc(p[0])}</button>`).join('')}
        <button type="button" class="primary sfSmallBtn" id="cmpRun">Compară</button></div></div><div id="cmpOut"></div>`;
  $('#ruleOverlay').classList.add('open');
  RULES.cur = null;
  const P = cmpPresets();
  $('#rlBody').querySelectorAll('[data-cmpp]').forEach(b => b.onclick = () => {
    const v = P[+b.dataset.cmpp][1];
    ['#cmpA0', '#cmpA1', '#cmpB0', '#cmpB1'].forEach((s, i) => { $(s).value = dt(v[i]); });
    cmpRun();
  });
  $('#cmpRun').onclick = cmpRun;
  cmpRun();
}
async function cmpRun() {
  const v = ['#cmpA0', '#cmpA1', '#cmpB0', '#cmpB1'].map(s => dtLocalToEpoch($(s).value, TRIAGE.tzOffset));
  if (v.some(x => x == null) || v[1] < v[0] || v[3] < v[2]) { $('#cmpOut').innerHTML = xpErr('Alege începutul și sfârșitul ambelor perioade (sfârșitul după început).'); return; }
  const seq = ++CMP.seq;
  $('#cmpOut').innerHTML = xpBusy('Se compară...');
  const p = new URLSearchParams({ a_from: v[0], a_to: v[1], b_from: v[2], b_to: v[3], top: 10 });
  const gf = ctxContentGf(); if (gf) p.set('gf', gf);
  let d;
  try { d = await xpFetchJSON(`/api/dataset/${DATASET_ID}/diff?${p}`); } catch (e) { if (seq === CMP.seq) $('#cmpOut').innerHTML = xpErr('Eroare: ' + e.message); return; }
  if (seq !== CMP.seq) return;
  CMP.range = v;
  const A = d.a, B = d.b;
  const ch = (x, y, worseUp) => {
    if (!x && !y) return '<td class="num">-</td>';
    if (!x) return '<td class="num up">nou</td>';
    const pc = Math.round(100 * (y - x) / x);
    return `<td class="num ${pc === 0 ? '' : ((pc > 0) === worseUp ? 'up' : 'down')}">${pc > 0 ? '+' : ''}${pc}%</td>`;
  };
  const num = x => String(x).replace('.', ',');
  const lead = [];
  if (B.requests && A.requests) {
    const r = B.per_min / Math.max(0.01, A.per_min);
    if (r >= 1.5) lead.push(`Traficul e de <b>${num(r.toFixed(1))}×</b> mai mare în B (${num(B.per_min)} față de ${num(A.per_min)} cereri / minut).`);
    else if (r <= 0.67) lead.push(`Traficul e de <b>${num((1 / r).toFixed(1))}×</b> mai mic în B.`);
    else lead.push('Volumul de trafic e similar în cele două perioade.');
  }
  if (B.new_ip_requests) lead.push(`<b>${pct(B.new_ip_requests, B.requests)}</b> din cererile din B vin de la IP-uri care nu apăruseră deloc în A (${fmtN(B.new_ips)} IP-uri noi).`);
  if (B.pct_5xx - A.pct_5xx >= 2) lead.push(`Erorile de server au crescut de la ${num(A.pct_5xx)}% la <b>${num(B.pct_5xx)}%</b>.`);
  const dimHtml = (k) => {
    const x = d.dims[k]; if (!x) return '';
    const lab = r => k === 'country' ? `${flagHtml(r.key === '??' ? '' : r.key)}${tEsc(r.key === '??' ? 'nedeterminată' : ccLabel(r.key))}`
      : k === 'ip' ? `<a href="#" data-ek="ip" data-ev="${tEscAttr(r.key)}" data-xopen="1">${tEsc(r.key)}</a>` : `<span class="${k === 'path' ? 'cmpMono' : ''}">${tEsc(r.key)}</span>`;
    const list = (rows, mode) => rows.length ? '<table class="cmpDiff">' + rows.map(r => `<tr><td>${lab(r)}</td><td class="num">${mode === 'new' ? fmtN(r.b) : mode === 'gone' ? fmtN(r.a) : `${fmtN(Math.round(r.a_scaled))} &rarr; <b>${fmtN(r.b)}</b>`}</td></tr>`).join('') + '</table>' : '<div class="cmpNone">nimic</div>';
    return `<div class="cmpDim"><h4>${tEsc(x.label)}</h4>
      <div class="cmpCols"><div><div class="cmpH new">Noi în B <span>${fmtN(x.n_new)}${x.new_requests ? ' · ' + fmtN(x.new_requests) + ' cereri' : ''}</span></div>${list(x.new, 'new')}</div>
        <div><div class="cmpH up">Au crescut <span>${fmtN(x.n_grew)} · A ajustat la durata lui B &rarr; B</span></div>${list(x.grew, 'grew')}</div>
        <div><div class="cmpH gone">Au dispărut <span>${fmtN(x.n_gone)}</span></div>${list(x.gone, 'gone')}</div></div></div>`;
  };
  $('#cmpOut').innerHTML = `${lead.length ? `<div class="rlWhy">${lead.join(' ')}</div>` : ''}
    <table class="cmpTbl cmpTot"><thead><tr><th></th><th><span class="cmpTag a">A</span> ${tEsc(fmtShortTs(v[0]))} – ${tEsc(fmtShortTs(v[1]))}</th><th><span class="cmpTag b">B</span> ${tEsc(fmtShortTs(v[2]))} – ${tEsc(fmtShortTs(v[3]))}</th><th>B față de A</th></tr></thead><tbody>
      <tr><td>Cereri</td><td class="num">${fmtN(A.requests)}</td><td class="num">${fmtN(B.requests)}</td><td></td></tr>
      <tr><td>Cereri / minut</td><td class="num">${num(A.per_min)}</td><td class="num">${num(B.per_min)}</td>${ch(A.per_min, B.per_min, true)}</tr>
      <tr><td>IP-uri unice</td><td class="num">${fmtN(A.unique_ips)}</td><td class="num">${fmtN(B.unique_ips)}</td>${ch(A.unique_ips, B.unique_ips, true)}</tr>
      <tr><td>Erori 4xx</td><td class="num">${num(A.pct_4xx)}%</td><td class="num">${num(B.pct_4xx)}%</td>${ch(A.pct_4xx, B.pct_4xx, true)}</tr>
      <tr><td>Erori 5xx</td><td class="num">${num(A.pct_5xx)}%</td><td class="num">${num(B.pct_5xx)}%</td>${ch(A.pct_5xx, B.pct_5xx, true)}</tr></tbody></table>
    ${['asn', 'ip', 'country', 'path'].map(dimHtml).join('')}
    <div class="cmpFoot"><button type="button" class="ghost sfSmallBtn" id="cmpUseB">Aplică perioada B în toată aplicația</button>
      <span class="note">Liniile cu mai puțin de 3 cereri sunt ignorate, ca listele să arate schimbările reale, nu zgomotul.</span></div>`;
  $('#cmpUseB').onclick = () => { rulesClose(); triageSetRange(v[2], v[3]); };
}

// ======================================================================
// v51 -- TABELE UNIFORME: pe orice tabel din pagini (cu antet, >= 6 randuri)
// apare aceeasi bara: cautare rapida, copiere coloana (ex. toate IP-urile,
// pentru o lista de blocare), export CSV; sortare pe orice coloana (unde
// tabelul nu are deja sortarea lui pe date) si antet fix la derulare.
// ======================================================================
const TBLX_SKIP = '#xpDrawer, #ruleOverlay, #modalOverlay, #auditDrawer, .heatmap-table, .cmpDiff, .spList';
function tblxText(td) { return (td ? td.innerText || td.textContent || '' : '').replace(/\s+/g, ' ').trim(); }
function tblxNum(s) {
  const t = String(s).trim().split(' ')[0].replace(/%$/, '');
  if (!/^[-+]?\d[\d.]*(,\d+)?$/.test(t)) return null;
  return parseFloat(t.replace(/\./g, '').replace(',', '.'));
}
function tblxHeads(t) { return [...t.querySelectorAll('thead tr:last-child th')]; }
function tblxRows(t) { return [...(t.tBodies[0] ? t.tBodies[0].rows : [])]; }
function tblxApply(t) {
  const bar = t._tblx; if (!bar) return;
  const q = bar.querySelector('input').value.trim().toLowerCase();
  const rows = tblxRows(t);
  let shown = 0;
  rows.forEach(r => { const ok = !q || r.textContent.toLowerCase().includes(q); r.style.display = ok ? '' : 'none'; if (ok) shown++; });
  bar.querySelector('.tblxN').textContent = q ? `${fmtN(shown)} din ${fmtN(rows.length)} rânduri` : `${fmtN(rows.length)} rânduri`;
}
function tblxVisible(t) { return tblxRows(t).filter(r => r.style.display !== 'none'); }
function tblxCsv(t) {
  const q = v => /[",;\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  const head = tblxHeads(t).map(th => q(tblxText(th).replace(/[▲▼]$/, '').trim()));
  const lines = [head.join(',')].concat(tblxVisible(t).map(r => [...r.cells].map(c => q(tblxText(c))).join(',')));
  const name = (t.id || (t.closest('section,.card') || {}).id || 'tabel') + '.csv';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob(['﻿' + lines.join('\n')], { type: 'text/csv;charset=utf-8' }));
  a.download = name; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
function tblxSort(t, i, th) {
  const dir = th.dataset.tblxDir === 'desc' ? 'asc' : 'desc';
  tblxHeads(t).forEach(h => { delete h.dataset.tblxDir; const ar = h.querySelector('.tblxAr'); if (ar) ar.textContent = ''; });
  th.dataset.tblxDir = dir; th.querySelector('.tblxAr').textContent = dir === 'desc' ? '▼' : '▲';
  const rows = tblxRows(t);
  const vals = rows.map(r => tblxText(r.cells[i]));
  const nums = vals.map(tblxNum);
  const numeric = nums.filter(x => x != null).length >= 0.7 * vals.filter(Boolean).length;
  const idx = rows.map((_, k) => k).sort((a, b) => {
    let c = numeric ? (nums[a] ?? -Infinity) - (nums[b] ?? -Infinity) : vals[a].localeCompare(vals[b], 'ro', { numeric: true });
    return (dir === 'desc' ? -c : c) || a - b;
  });
  const tb = t.tBodies[0]; t._tblxSorting = true;
  idx.forEach(k => tb.appendChild(rows[k]));
  t._tblxSorting = false;
}
function tblxEnhance(t) {
  if (t._tblx || t.closest(TBLX_SKIP) || !t.tBodies[0]) return;
  const heads = tblxHeads(t);
  if (heads.length < 2 || tblxRows(t).length < 6) return;
  if (tblxRows(t).some(r => r.cells.length !== heads.length || r.querySelector('[colspan]'))) return;
  const bar = document.createElement('div');
  bar.className = 'tblx';
  bar.innerHTML = `<input type="search" placeholder="Caută în tabel…" aria-label="Caută în tabel"><span class="tblxN"></span>
    <select aria-label="Copiază o coloană"><option value="">Copiază coloana…</option>${heads.map((h, i) => tblxText(h) && !h.classList.contains('selCol') ? `<option value="${i}">${tEsc(tblxText(h))}</option>` : '').join('')}</select>
    <button type="button" class="ghost" title="Descarcă rândurile afișate ca CSV">CSV</button>`;
  const host = (t.parentElement && t.parentElement.children.length === 1 && getComputedStyle(t.parentElement).overflowX !== 'visible') ? t.parentElement : t;
  host.parentElement.insertBefore(bar, host);
  t._tblx = bar;
  // antet fix: fata de fereastra, sau fata de cutia cu derulare proprie in care sta tabelul
  let el = t.parentElement, inner = false;
  while (el && el !== document.body) {
    const cs = getComputedStyle(el);
    if (cs.overflowY === 'auto' || cs.overflowY === 'scroll') { inner = true; break; }
    // overflow:hidden face din card un container de derulare (antetul s-ar fixa fata de card); clip taie la fel, fara asta
    if (cs.overflowY === 'hidden' && cs.overflowX === 'hidden') el.style.overflow = 'clip';
    el = el.parentElement;
  }
  t.classList.add('tblxT'); if (inner) t.classList.add('tblxIn');
  // cardul are deja o cautare proprie (pe date, nu doar pe randurile afisate) -> o pastram pe aceea
  const card = t.closest('.card, section');
  if (card && [...card.querySelectorAll('input')].some(i => !i.closest('.tblx') && /^(cauta|caută|filtreaz|search)/i.test(i.placeholder || ''))) bar.classList.add('noSearch');
  bar.querySelector('input').addEventListener('input', debounce(() => tblxApply(t), 120));
  bar.querySelector('select').addEventListener('change', (e) => {
    const i = +e.target.value; e.target.value = '';
    if (isNaN(i)) return;
    const vals = tblxVisible(t).map(r => tblxText(r.cells[i])).filter(Boolean);
    copyText(vals.join('\n')); toast(`${fmtN(vals.length)} valori copiate din coloana „${tblxText(heads[i])}”`);
  });
  bar.querySelector('button').addEventListener('click', () => tblxCsv(t));
  if (!t.querySelector('th.sortable')) {
    heads.forEach((th, i) => {
      if (!tblxText(th) || th.classList.contains('selCol')) return;
      th.classList.add('tblxSort'); th.insertAdjacentHTML('beforeend', '<span class="tblxAr"></span>');
      th.title = (th.title ? th.title + ' -- ' : '') + 'click: sortează';
      th.addEventListener('click', (e) => { if (e.target.closest('a,button,input,select')) return; tblxSort(t, i, th); });
    });
  }
  new MutationObserver(() => { if (!t._tblxSorting) tblxApply(t); }).observe(t.tBodies[0], { childList: true });
  tblxApply(t);
}
const tblxScan = debounce(() => { document.querySelectorAll('main table').forEach(tblxEnhance); }, 250);
new MutationObserver(tblxScan).observe(document.querySelector('main'), { childList: true, subtree: true });
new ResizeObserver(() => { document.documentElement.style.setProperty('--tbH', $('#topbar').offsetHeight + 'px'); }).observe($('#topbar'));

// ======================================================================
// v51.1 -- bifele "Blocheaza" (IP Explorer / Endpoints) -> generatorul din
// Investigations: bara de jos arata cate sunt bifate, de pe orice pagina.
// ======================================================================
function selTrayRender() {
  const n = SELECTED.ip.size + SELECTED.subnet.size + SELECTED.path.size;
  $('#selTray').hidden = !n || CURRENT_PAGE === 'investigations';
  const parts = [];
  if (SELECTED.ip.size) parts.push(SELECTED.ip.size + (SELECTED.ip.size === 1 ? ' IP' : ' IP-uri'));
  if (SELECTED.subnet.size) parts.push(SELECTED.subnet.size + (SELECTED.subnet.size === 1 ? ' subnet' : ' subnet-uri'));
  if (SELECTED.path.size) parts.push(SELECTED.path.size + (SELECTED.path.size === 1 ? ' path' : ' path-uri'));
  $('#selTrayTxt').textContent = 'Bifate pentru blocare: ' + parts.join(', ');
}
const _v511RuleGen = updateRuleGen;
updateRuleGen = function () { const r = _v511RuleGen.apply(this, arguments); selTrayRender(); return r; };
document.addEventListener('click', (e) => {
  const g = e.target.closest('[data-rg-go]');
  if (g) { e.preventDefault(); const [pg, sel] = g.dataset.rgGo.split('|'); gotoCard(pg, sel); return; }
  if (e.target.closest('#selTrayGo')) { gotoCard('investigations', '#ruleGenCard'); return; }
  if (e.target.closest('#selTrayClr')) {
    SELECTED.ip.clear(); SELECTED.subnet.clear(); SELECTED.path.clear();
    document.querySelectorAll('input.ruleCheck:checked').forEach(c => { c.checked = false; });
    updateRuleGen();
  }
});
const _v511Show = showPage;
showPage = function () { const r = _v511Show.apply(this, arguments); selTrayRender(); return r; };
