// =========================================================================
// 1. GLOBAL STATE & INITIALIZATION
// =========================================================================
let activeTab = 'radar';
let masterCveData = []; 
let newsData = [];
let metadata = {};
let cweMap = {};
let configuredNewsSources = [];
let selectedNewsSource = 'All';

// Filter States
let radarState = {
  sort: 'priority', // priority, epss, severity, newest
  severities: new Set(),
  hasPoc: false,
  hasNuclei: false
};

let vendorState = {
  sort: 'newest', // newest, priority, severity
  severities: new Set(),
  vendors: new Set()
};

async function fetchJsonFile(possiblePaths) {
  for (const p of possiblePaths) {
    try {
      const res = await fetch(p, { cache: 'no-store' });
      if (res.ok) return await res.json();
    } catch (_) {}
  }
  return null;
}

// 100-Point Composite Threat Priority Score (Hoisted)
function computeThreatPriorityScore(item) {
  const isKev = item.is_kev ? 35 : 0;
  const hasPoc = item.has_poc ? 20 : 0;
  const hasNuclei = item.has_nuclei ? 15 : 0;
  const epssVal = Math.min(1, Math.max(0, parseFloat(item.epss) || 0));
  const epssPts = epssVal * 15;
  const cvssVal = Math.min(10, Math.max(0, parseFloat(item.cvss) || 0));
  const cvssPts = (cvssVal / 10) * 15;
  return isKev + hasPoc + hasNuclei + epssPts + cvssPts;
}

async function initDashboard() {
  initTheme();
  // setupGlobalSearchListener(); // Make sure search.js has this defined

  const [master, news, meta, cwes] = await Promise.all([
    fetchJsonFile(['data/cve_master.json', './data/cve_master.json', '../docs/data/cve_master.json']),
    fetchJsonFile(['data/news.json', './data/news.json', '../docs/data/news.json']),
    fetchJsonFile(['data/sync_meta.json', './data/sync_meta.json', '../docs/data/sync_meta.json']),
    fetchJsonFile(['data/cwe_definitions.json', './data/cwe_definitions.json', '../data/cwe_definitions.json'])
  ]);

  if (cwes) cweMap = cwes;

  if (master) {
    masterCveData = master;
    masterCveData.forEach(item => {
      item.priorityScore = computeThreatPriorityScore(item);
      item.severityStr = getCvssSeverity(item.cvss);
    });
  }

  if (news) {
    newsData = news;
    configuredNewsSources = [...new Set(newsData.map(n => n.source).filter(Boolean))];
  }

  if (meta) {
    metadata = meta;
    const syncEl = document.getElementById('meta-sync-time');
    if (syncEl) syncEl.textContent = meta.last_sync || 'Unavailable';
  }

  updateRadarFilters();
  updateVendorFilters();
  renderNewsSourcePills();
  renderNewsView();
}

// =========================================================================
// 2. FILTERING & SORTING LOGIC (RADAR & VENDOR)
// =========================================================================
function toggleRadarFilter(type, value) {
  const btn = document.getElementById(
    type === 'severity' ? `btn-radar-sev-${value.toLowerCase()}` : `btn-radar-${value}`
  );
  
  if (type === 'severity') {
    if (radarState.severities.has(value)) radarState.severities.delete(value);
    else radarState.severities.add(value);
  } else if (type === 'flag') {
    if (value === 'poc') radarState.hasPoc = !radarState.hasPoc;
    if (value === 'nuclei') radarState.hasNuclei = !radarState.hasNuclei;
  }
  
  btn.classList.toggle('bg-indigo-600');
  btn.classList.toggle('text-white');
  btn.classList.toggle('border-transparent');
  btn.classList.toggle('bg-white/50');
  btn.classList.toggle('text-slate-600');
  
  updateRadarFilters();
}

function updateRadarFilters() {
  radarState.sort = document.getElementById('radar-sort').value;
  
  let filtered = masterCveData.filter(item => {
    // Only show active threats in radar by default
    const isRadarWorthy = item.is_kev || item.has_poc || item.has_nuclei || item.epss >= 0.05;
    if (!isRadarWorthy) return false;

    if (radarState.severities.size > 0 && !radarState.severities.has(item.severityStr)) return false;
    if (radarState.hasPoc && !item.has_poc) return false;
    if (radarState.hasNuclei && !item.has_nuclei) return false;
    
    return true;
  });

  filtered.sort((a, b) => {
    if (radarState.sort === 'priority') return b.priorityScore - a.priorityScore;
    if (radarState.sort === 'epss') return (b.epss || 0) - (a.epss || 0);
    if (radarState.sort === 'newest') return (b.date_added || '').localeCompare(a.date_added || '');
    if (radarState.sort === 'severity') return (b.cvss || 0) - (a.cvss || 0);
    return 0;
  });

  renderExploitRadar(filtered.slice(0, 100));
}

function toggleVendorFilter(type, value) {
  const safeId = value.toLowerCase().replace(/\s+/g, '');
  const btn = document.getElementById(`btn-vendor-${type === 'severity' ? 'sev-' : ''}${safeId}`);
  
  if (type === 'severity') {
    if (vendorState.severities.has(value)) vendorState.severities.delete(value);
    else vendorState.severities.add(value);
  } else if (type === 'vendor') {
    if (vendorState.vendors.has(value)) vendorState.vendors.delete(value);
    else vendorState.vendors.add(value);
  }
  
  btn.classList.toggle('bg-indigo-600');
  btn.classList.toggle('text-white');
  btn.classList.toggle('border-transparent');
  btn.classList.toggle('bg-white/50');
  btn.classList.toggle('text-slate-600');
  
  updateVendorFilters();
}

function updateVendorFilters() {
  vendorState.sort = document.getElementById('vendor-sort').value;
  
  let filtered = masterCveData.filter(item => {
    if (!item.vendors || item.vendors.length === 0) return false;
    if (vendorState.severities.size > 0 && !vendorState.severities.has(item.severityStr)) return false;
    if (vendorState.vendors.size > 0) {
      const hasMatch = item.vendors.some(v => vendorState.vendors.has(v));
      if (!hasMatch) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    if (vendorState.sort === 'newest') return (b.date_added || '').localeCompare(a.date_added || '');
    if (vendorState.sort === 'priority') return b.priorityScore - a.priorityScore;
    if (vendorState.sort === 'severity') return (b.cvss || 0) - (a.cvss || 0);
    return 0;
  });

  renderVendorFocus(filtered.slice(0, 100));
}

// =========================================================================
// 3. SIDEBAR COLLAPSE / EXPAND LOGIC
// =========================================================================
const sidebarEl = document.getElementById('sidebar');
const chevronEl = document.getElementById('sidebar-chevron');

function toggleSidebar() {
  const isCollapsed = sidebarEl.classList.toggle('collapsed');
  if (chevronEl) {
    chevronEl.style.transform = isCollapsed ? 'rotate(180deg)' : 'rotate(0deg)';
  }
}

function expandSidebar() {
  if (sidebarEl.classList.contains('collapsed')) {
    sidebarEl.classList.remove('collapsed');
    if (chevronEl) chevronEl.style.transform = 'rotate(0deg)';
  }
}

function expandAndFocus(inputId) {
  expandSidebar();
  setTimeout(() => {
    const el = document.getElementById(inputId);
    if (el) el.focus();
  }, 160);
}

// =========================================================================
// 4. THEME SWITCHER
// =========================================================================
const sunIcon = document.getElementById('theme-icon-sun');
const moonIcon = document.getElementById('theme-icon-moon');
const sunIconCol = document.getElementById('theme-icon-sun-collapsed');
const moonIconCol = document.getElementById('theme-icon-moon-collapsed');
const themeBadge = document.getElementById('theme-mode-badge');

function syncThemeIcons(isDark) {
  if (isDark) {
    document.documentElement.classList.add('dark');
    sunIcon?.classList.remove('hidden');
    moonIcon?.classList.add('hidden');
    sunIconCol?.classList.remove('hidden');
    moonIconCol?.classList.add('hidden');
    if (themeBadge) themeBadge.textContent = 'Dark';
  } else {
    document.documentElement.classList.remove('dark');
    sunIcon?.classList.add('hidden');
    moonIcon?.classList.remove('hidden');
    sunIconCol?.classList.add('hidden');
    moonIconCol?.classList.remove('hidden');
    if (themeBadge) themeBadge.textContent = 'Light';
  }
}

function initTheme() {
  const saved = localStorage.getItem('watcher_theme');
  const isDark = saved ? saved === 'dark' : true;
  syncThemeIcons(isDark);
}

function toggleTheme() {
  const isDark = document.documentElement.classList.contains('dark');
  localStorage.setItem('watcher_theme', isDark ? 'light' : 'dark');
  syncThemeIcons(!isDark);
}

// =========================================================================
// 5. TAB NAVIGATION
// =========================================================================
function switchTab(tabName) {
  activeTab = tabName;
  ['radar', 'vendor', 'cve-search','news', 'brief'].forEach(t => {
    document.getElementById(`nav-${t}`)?.classList.toggle('active', t === tabName);
    document.getElementById(`view-${t}`)?.classList.toggle('hidden', t !== tabName);
  });

  document.getElementById('search-view')?.classList.add('hidden');

  const titles = {
    radar: 'EXPLOIT RADAR',
    vendor: 'VENDOR FOCUS',
    'cve-search': 'CVE LOOKUP',
    news: 'CURATED THREAT NEWS',
    brief: 'THREAT BRIEF GENERATOR'
  };
  const titleEl = document.getElementById('workspace-title');
  if (titleEl) titleEl.textContent = titles[tabName] || 'EXPLOIT RADAR';

  if (tabName === 'cve-search' && document.getElementById('search-cve-rows')?.children.length === 0) {
    addSearchCveRow();
  }

  if (tabName === 'brief' && currentBriefItems.length === 0) {
    generateThreatBrief();
  }
}

// =========================================================================
// 6. EXPANDABLE DESCRIPTION & CVSS BADGE HELPERS
// =========================================================================
function toggleReadMore(btn) {
  const wrapper = btn.parentElement;
  const shortEl = wrapper.querySelector('.short-text');
  const fullEl = wrapper.querySelector('.full-text');
  const isHidden = fullEl.classList.contains('hidden');

  fullEl.classList.toggle('hidden', !isHidden);
  shortEl.classList.toggle('hidden', isHidden);
  btn.textContent = isHidden ? 'Show less' : 'Read more';
}

function formatExpandableText(text, limit = 155) {
  if (!text) return '<span class="italic text-slate-400">No description available.</span>';
  if (text.length <= limit) return `<span>${text}</span>`;
  const truncated = text.substring(0, limit).trim() + '...';
  return `
    <span>
      <span class="short-text">${truncated}</span>
      <span class="full-text hidden">${text}</span>
      <button onclick="toggleReadMore(this)" class="ml-1 text-indigo-500 dark:text-indigo-400 hover:underline font-semibold text-[11px] cursor-pointer">Read more</button>
    </span>
  `;
}

function getCvssSeverity(score) {
  if (score === null || score === undefined || score === '') return 'N/A';
  const val = parseFloat(score);
  if (isNaN(val)) return 'N/A';
  if (val >= 9.0) return 'Critical';
  if (val >= 7.0) return 'High';
  if (val >= 4.0) return 'Medium';
  if (val > 0) return 'Low';
  return 'None';
}

function formatCvssBadge(score, cveId) {
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  if (score === null || score === undefined || score === '' || isNaN(parseFloat(score))) {
    return `<a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs font-mono font-semibold px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-400 border border-slate-400/20 hover:underline" title="Inspect on NVD">N/A</a>`;
  }
  const val = parseFloat(score);
  const severity = getCvssSeverity(val);

  let style = 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30';
  if (val >= 9.0) {
    style = 'bg-gradient-to-r from-amber-500/20 to-rose-500/25 text-amber-700 dark:text-amber-300 border-amber-500/45 shadow-sm shadow-amber-500/10';
  } else if (val >= 7.0) {
    style = 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/40';
  } else if (val >= 4.0) {
    style = 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-300 border-yellow-500/40';
  }
  return `
    <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs font-mono font-bold px-3 py-1 rounded-full border ${style} hover:scale-105 transition-transform" title="View CVSS Specification on NIST NVD">
      ${val.toFixed(1)} ${severity}
    </a>
  `;
}

// =========================================================================
// 7. STANDARDIZED GLASSMORPHIC CARD BUILDER
// =========================================================================
function buildStandardThreatCard(item, cardType = 'radar_kev') {
  const cveId = item.cve_id;
  
  // Use robust Master array logic
  const vendorName = (item.vendors && item.vendors.length > 0) ? item.vendors.join(', ') : (item.vendor || 'Unknown');
  const productName = (item.products && item.products.length > 0) ? `- ${item.products.join(', ')}` : (item.product && item.product !== 'Unknown' ? `- ${item.product}` : '');
  const vendorProduct = `${vendorName} ${productName}`.trim();

  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`;
  const pocUrl = `https://github.com/nomi-sec/PoC-in-GitHub/search?q=${cveId}`;
  const nucleiUrl = `https://github.com/projectdiscovery/nuclei-templates/search?q=${cveId}`;

  let glowClass = 'vendor-card-glow';
  if (cardType === 'radar_kev' || item.is_kev) glowClass = 'kev-card-glow';
  else if (cardType === 'radar_early') glowClass = 'early-card-glow';

  let dateWellMarkup = `
    <div class="recessed-box rounded-xl px-3.5 py-2 my-3 text-[11px] font-mono text-slate-500 dark:text-slate-400">
      Detected Date: <span class="font-semibold text-slate-800 dark:text-slate-200">${item.date_added || item.date || item.first_seen || '-'}</span>
    </div>
  `;

  const hasEpss = item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0;
  const epssBadge = hasEpss
    ? `<span class="px-3 py-1 rounded-full bg-slate-500/10 dark:bg-slate-800/90 text-slate-700 dark:text-slate-200 border border-slate-300/80 dark:border-slate-700 font-mono font-semibold">
        EPSS: ${(parseFloat(item.epss) * 100).toFixed(2)}%
       </span>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/5 text-slate-400 border border-slate-300/40 dark:border-slate-800 font-mono">EPSS: -</span>`;

  const pocBadge = item.has_poc
    ? `<a href="${pocUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40 font-semibold hover:bg-emerald-500/25 transition-colors">PoC: Available</a>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-300/50 dark:border-slate-800">PoC: Not Available</span>`;

  const nucleiBadge = item.has_nuclei
    ? `<a href="${nucleiUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/40 font-semibold hover:bg-sky-500/25 transition-colors">Nuclei Template: Ready</a>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-300/50 dark:border-slate-800">Nuclei Template: Not Ready</span>`;

  const kevBadge = (cardType === 'radar_kev' || item.is_kev)
    ? `<a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/45 font-bold hover:bg-rose-500/30 transition-colors">CISA KEV</a>`
    : '';

  return `
    <article class="neu-glass-card ${glowClass} rounded-2xl p-5 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between gap-2 mb-1">
          <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-lg font-extrabold font-mono tracking-tight text-slate-900 dark:text-white hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors">
            ${cveId}
          </a>
          ${formatCvssBadge(item.cvss, cveId)}
        </div>
        <h3 class="text-xs font-semibold text-indigo-600 dark:text-indigo-300 mb-2.5">
          ${vendorProduct}
        </h3>
        <div class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
          ${formatExpandableText(item.description || item.vuln_name, 160)}
        </div>
        ${dateWellMarkup}
      </div>
      <div class="pt-2 border-t border-slate-200/70 dark:border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px]">
        ${kevBadge}
        ${epssBadge}
        ${pocBadge}
        ${nucleiBadge}
      </div>
    </article>
  `;
}

// =========================================================================
// 8. RENDERING VIEWS (RADAR, VENDORS, NEWS)
// =========================================================================
function renderExploitRadar(filteredItems) {
  const kevList = filteredItems.filter(i => i.is_kev);
  const earlyList = filteredItems.filter(i => !i.is_kev);

  document.getElementById('kpi-kev-count').textContent = kevList.length;
  document.getElementById('kpi-early-count').textContent = earlyList.length;

  const kevContainer = document.getElementById('radar-kev-list');
  const earlyContainer = document.getElementById('radar-early-list');

  if (kevList.length === 0) {
    kevContainer.innerHTML = `<div class="neu-glass-card rounded-2xl p-8 text-center text-xs text-slate-400">No CISA KEV entries found.</div>`;
  } else {
    kevContainer.innerHTML = kevList.map(item => buildStandardThreatCard(item, 'radar_kev')).join('');
  }

  if (earlyList.length === 0) {
    earlyContainer.innerHTML = `<div class="neu-glass-card rounded-2xl p-8 text-center text-xs text-slate-400">No Early Warning entries found.</div>`;
  } else {
    earlyContainer.innerHTML = earlyList.map(item => buildStandardThreatCard(item, 'radar_early')).join('');
  }
}

function renderVendorFocus(filteredItems) {
  const container = document.getElementById('vendor-grid');
  
  if (filteredItems.length === 0) {
    container.innerHTML = `
      <div class="col-span-full neu-glass-card rounded-2xl p-10 text-center text-sm text-slate-400">
        No advisories matched the current vendor & severity filters.
      </div>
    `;
    return;
  }

  container.innerHTML = filteredItems
    .map(item => buildStandardThreatCard(item, 'vendor'))
    .join('');
}

function renderNewsSourcePills() {
  const container = document.getElementById('news-source-pills');
  const sources = ['All', ...configuredNewsSources];

  container.innerHTML = sources.map(s => `
    <button 
      onclick="filterNewsSource('${s}')" 
      class="px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all ${
        s === selectedNewsSource 
          ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/30' 
          : 'neu-glass-card text-slate-600 dark:text-slate-300 hover:border-indigo-500/40'
      }"
    >
      ${s}
    </button>
  `).join('');
}

function filterNewsSource(sName) {
  selectedNewsSource = sName;
  renderNewsSourcePills();
  renderNewsView();
}

function renderNewsView() {
  const container = document.getElementById('news-grid');
  let filtered = newsData || [];
  if (selectedNewsSource !== 'All') {
    filtered = filtered.filter(n => (n.source || '').toLowerCase() === selectedNewsSource.toLowerCase());
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="col-span-full neu-glass-card rounded-2xl p-10 text-center text-sm text-slate-400">
        No curated articles found for <strong class="text-slate-700 dark:text-slate-200">${selectedNewsSource}</strong>.
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(article => `
    <article class="neu-glass-card vendor-card-glow rounded-2xl p-5 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
          <span class="font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">${article.source}</span>
          <span>${article.published || ''}</span>
        </div>

        <a href="${article.url}" target="_blank" rel="noopener noreferrer" class="text-base font-bold text-slate-900 dark:text-white hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors block mb-2.5 leading-snug">
          ${article.title}
        </a>

        <div class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-4">
          ${formatExpandableText(article.snippet, 175)}
        </div>
      </div>

      <div class="pt-3 border-t border-slate-200/70 dark:border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px]">
        ${(article.matched_cves || []).map(cve => `
          <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener noreferrer" class="font-mono font-bold px-2.5 py-1 rounded-full bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border border-indigo-500/30 hover:underline">
            ${cve}
          </a>
        `).join('')}
        ${(article.matched_vendors || article.vendors || []).map(v => `
          <span class="px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-600 dark:text-slate-300 border border-slate-300/50 dark:border-slate-700 font-medium">
            ${v}
          </span>
        `).join('')}
      </div>
    </article>
  `).join('');
}

// =========================================================================
// 9. THREAT BRIEF GENERATOR (TOP 5 / TOP 10 / CUSTOM + TEAMS WEBHOOK)
// =========================================================================
let briefMode = 'top5'; // 'top5' | 'top10' | 'custom'
let currentBriefItems = [];
let currentBriefOverviewHtml = '';
let currentBriefOverviewPlain = '';

function setBriefMode(mode) {
  briefMode = mode;
  ['top5', 'top10', 'custom'].forEach(m => {
    const btn = document.getElementById(`brief-mode-${m}`);
    if (!btn) return;
    if (m === mode) {
      btn.className = 'px-4 py-2 rounded-xl text-xs font-bold transition-all bg-indigo-600 text-white shadow-md shadow-indigo-500/30';
    } else {
      btn.className = 'px-4 py-2 rounded-xl text-xs font-bold transition-all neu-glass-card text-slate-600 dark:text-slate-300 hover:border-indigo-500/40';
    }
  });

  const customBuilder = document.getElementById('brief-custom-builder');
  if (customBuilder) {
    customBuilder.classList.toggle('hidden', mode !== 'custom');
    if (mode === 'custom' && document.getElementById('custom-cve-rows')?.children.length === 0) {
      addCustomCveRow();
    }
  }
}

function addCustomCveRow(yearVal = '', idVal = '') {
  const container = document.getElementById('custom-cve-rows');
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'custom-cve-row neu-inset rounded-xl p-1.5 flex items-center gap-1';

  row.innerHTML = `
    <span class="font-mono text-xs font-bold text-indigo-600 dark:text-indigo-400 pl-1.5 shrink-0">CVE-</span>
    <input type="text" placeholder="Year" maxlength="4" value="${yearVal}" inputmode="numeric" class="custom-cve-year w-12 bg-white/70 dark:bg-slate-900/80 border border-slate-300/60 dark:border-slate-700/70 rounded-lg px-1 py-1 text-center font-mono text-xs font-semibold focus:outline-none focus:border-indigo-500 text-slate-800 dark:text-slate-100 shrink-0" />
    <span class="font-mono text-slate-400 text-xs shrink-0">-</span>
    <input type="text" placeholder="ID" maxlength="7" value="${idVal}" inputmode="numeric" class="custom-cve-id w-16 bg-white/70 dark:bg-slate-900/80 border border-slate-300/60 dark:border-slate-700/70 rounded-lg px-1.5 py-1 text-center font-mono text-xs font-semibold focus:outline-none focus:border-indigo-500 text-slate-800 dark:text-slate-100 shrink-0" />
    <button type="button" onclick="addCustomCveRow()" title="Add another CVE" class="p-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm transition-all shrink-0 cursor-pointer">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4" /></svg>
    </button>
    <button type="button" onclick="removeCustomCveRow(this)" title="Remove row" class="p-1.5 rounded-lg hover:bg-rose-500/15 text-slate-400 hover:text-rose-500 transition-all shrink-0 cursor-pointer">✕</button>
  `;

  const yearInput = row.querySelector('.custom-cve-year');
  const idInput = row.querySelector('.custom-cve-id');
  yearInput.addEventListener('input', (e) => {
    if (e.target.value.length === 4) idInput.focus();
  });

  container.appendChild(row);
  yearInput.focus();
}

function removeCustomCveRow(btn) {
  const container = document.getElementById('custom-cve-rows');
  if (!container) return;
  if (container.children.length > 1) {
    btn.closest('.custom-cve-row').remove();
  } else {
    const row = btn.closest('.custom-cve-row');
    row.querySelector('.custom-cve-year').value = '';
    row.querySelector('.custom-cve-id').value = '';
  }
}

// Build unified lookup pool of all synced CVEs directly from master data
function getLocalCvePoolMap() {
  const map = new Map();
  masterCveData.forEach(item => {
    const cid = item.cve_id.toUpperCase();
    map.set(cid, {
      cve_id: cid,
      date_added: item.date_added || '-',
      cvss: item.cvss,
      description: item.description || '',
      vendor: (item.vendors && item.vendors.length > 0) ? item.vendors.join(', ') : 'Unknown',
      product: (item.products && item.products.length > 0) ? item.products.join(', ') : 'Unknown',
      epss: item.epss,
      is_kev: item.is_kev,
      has_nuclei: item.has_nuclei,
      has_poc: item.has_poc
    });
  });
  return map;
}

async function fetchAndValidateCustomCve(cveId, localMap) {
  const upperId = cveId.toUpperCase();
  if (localMap.has(upperId)) {
    return localMap.get(upperId);
  }

  const parts = upperId.split('-');
  if (parts.length !== 3) return null;
  const year = parts[1];
  const num = parts[2];
  const prefix = num.length > 3 ? num.slice(0, -3) + 'xxx' : '0xxx';

  const cveListUrl = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${prefix}/${upperId}.json`;

  try {
    const res = await fetch(cveListUrl);
    if (!res.ok) return null;
    const data = await res.json();

    const state = data?.cveMetadata?.state || '';
    if (state.toUpperCase() === 'REJECTED') return null;

    const containers = data.containers || {};
    const cna = containers.cna || {};

    let desc = '';
    for (const d of (cna.descriptions || [])) {
      if ((d.lang || 'en').startsWith('en')) {
        desc = d.value || '';
        break;
      }
    }

    let vendor = 'Unknown';
    let product = 'Unknown';
    const affList = [...(cna.affected || [])];
    for (const adp of (containers.adp || [])) {
      if (Array.isArray(adp.affected)) affList.push(...adp.affected);
    }
    for (const aff of affList) {
      if (vendor === 'Unknown' && aff.vendor && !['n/a', 'unknown'].includes(aff.vendor.toLowerCase())) vendor = aff.vendor;
      if (product === 'Unknown' && aff.product && !['n/a', 'unknown'].includes(aff.product.toLowerCase())) product = aff.product;
    }

    let cvss = null;
    const allMetrics = [...(cna.metrics || [])];
    for (const adp of (containers.adp || [])) {
      if (Array.isArray(adp.metrics)) allMetrics.push(...adp.metrics);
    }
    for (const tier of [['cvssV3_1', 'cvssV3_0'], ['cvssV4_0', 'cvssV2_0']]) {
      for (const k of tier) {
        for (const m of allMetrics) {
          if (m && m[k] && m[k].baseScore !== undefined) {
            cvss = parseFloat(m[k].baseScore);
            break;
          }
        }
        if (cvss !== null) break;
      }
      if (cvss !== null) break;
    }

    const pubRaw = data?.cveMetadata?.datePublished || '';
    const dateAdded = pubRaw ? pubRaw.slice(0, 10) : '-';

    let epss = null;
    try {
      const epssRes = await fetch(`https://api.first.org/data/v1/epss?cve=${upperId}`);
      if (epssRes.ok) {
        const epssJson = await epssRes.json();
        if (epssJson.data && epssJson.data.length > 0) epss = parseFloat(epssJson.data[0].epss);
      }
    } catch (_) {}

    return {
      cve_id: upperId,
      date_added: dateAdded,
      cvss,
      description: desc || 'No description provided.',
      vendor,
      product,
      epss,
      is_kev: false,
      has_nuclei: false,
      has_poc: false
    };
  } catch (_) {
    return null;
  }
}

async function generateThreatBrief() {
  const btnText = document.getElementById('btn-generate-text');
  const invalidBanner = document.getElementById('brief-invalid-banner');
  if (invalidBanner) invalidBanner.classList.add('hidden');
  if (btnText) btnText.textContent = 'Generating...';

  const localMap = getLocalCvePoolMap();
  let selectedItems = [];
  const invalidCves = [];

  if (briefMode === 'top5' || briefMode === 'top10') {
    const limit = briefMode === 'top5' ? 5 : 10;
    const allItems = Array.from(localMap.values());

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 45);
    const cutoffStr = cutoff.toISOString().slice(0, 10);

    const recentPool = allItems.filter(i => (i.date_added || '') >= cutoffStr);
    const candidatePool = recentPool.length >= limit ? recentPool : allItems;

    selectedItems = candidatePool
      .map(item => ({ ...item, priorityScore: computeThreatPriorityScore(item) }))
      .sort((a, b) => {
        if (b.priorityScore !== a.priorityScore) return b.priorityScore - a.priorityScore;
        return (b.date_added || '').localeCompare(a.date_added || '');
      })
      .slice(0, limit);
  } else {
    const rows = document.querySelectorAll('#custom-cve-rows .custom-cve-row');
    const requestedIds = [];

    rows.forEach(r => {
      const y = (r.querySelector('.custom-cve-year')?.value || '').trim();
      const id = (r.querySelector('.custom-cve-id')?.value || '').trim();
      if (!y && !id) return;
      const candidate = `CVE-${y}-${id}`.toUpperCase();
      if (!/^CVE-\d{4}-\d{4,7}$/.test(candidate)) {
        invalidCves.push(candidate);
      } else if (!requestedIds.includes(candidate)) {
        requestedIds.push(candidate);
      }
    });

    for (const cid of requestedIds) {
      const resolved = await fetchAndValidateCustomCve(cid, localMap);
      if (resolved) {
        selectedItems.push({ ...resolved, priorityScore: computeThreatPriorityScore(resolved) });
      } else {
        invalidCves.push(cid);
      }
    }
  }

  if (btnText) btnText.textContent = 'Generate Brief';

  if (invalidCves.length > 0 && invalidBanner) {
    invalidBanner.textContent = `Excluded invalid or unpublished CVE IDs: ${invalidCves.join(', ')}`;
    invalidBanner.classList.remove('hidden');
  }

  currentBriefItems = selectedItems;
  renderBriefReport(selectedItems);
}

function renderBriefReport(items) {
  const tsEl = document.getElementById('brief-report-timestamp');
  const overviewEl = document.getElementById('brief-overview-text');
  const tbodyEl = document.getElementById('brief-table-body');

  const nowStr = new Date().toLocaleString('en-IN', {
    timeZone: 'Asia/Kolkata',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  }) + ' IST';

  if (tsEl) tsEl.textContent = `Generated: ${nowStr}`;

  if (!items || items.length === 0) {
    currentBriefOverviewHtml = '<p>No valid vulnerabilities selected for this brief.</p>';
    currentBriefOverviewPlain = 'No valid vulnerabilities selected for this brief.';
    if (overviewEl) overviewEl.innerHTML = currentBriefOverviewHtml;
    if (tbodyEl) {
      tbodyEl.innerHTML = `<tr><td colspan="10" class="py-8 text-center text-slate-400">No valid CVEs to display. Add valid CVE IDs or switch to Auto Top 5 / Top 10.</td></tr>`;
    }
    return;
  }

  const total = items.length;
  const critCount = items.filter(i => getCvssSeverity(i.cvss) === 'Critical').length;
  const highCount = items.filter(i => getCvssSeverity(i.cvss) === 'High').length;
  const kevCount = items.filter(i => i.is_kev).length;
  const pocCount = items.filter(i => i.has_poc).length;
  const nucleiCount = items.filter(i => i.has_nuclei).length;
  const vendors = [...new Set(items.map(i => i.vendor).filter(v => v && v !== 'Unknown'))];
  const vendorSummary = vendors.length > 0 ? vendors.slice(0, 6).join(', ') : 'multiple enterprise vendors';

  const topCve = items[0];
  const topCveScore = topCve.cvss ? `${parseFloat(topCve.cvss).toFixed(1)} (${getCvssSeverity(topCve.cvss)})` : 'N/A';

  currentBriefOverviewHtml = `
    <p>
      <strong>Executive Threat Overview:</strong> This brief analyzes <strong>${total}</strong> high-priority vulnerabilities impacting <strong>${vendorSummary}</strong>. 
      Of the tracked advisories, <strong>${critCount}</strong> are rated <strong>Critical</strong> and <strong>${highCount}</strong> are rated <strong>High</strong> severity under CVSS v3.x scoring.
      Active threat telemetry indicates that <strong>${kevCount}</strong> ${kevCount === 1 ? 'vulnerability is' : 'vulnerabilities are'} confirmed exploited in the wild (<strong>CISA KEV</strong>), 
      <strong>${pocCount}</strong> have public Proof-of-Concept (PoC) exploit code on GitHub, and <strong>${nucleiCount}</strong> have automated Nuclei detection templates ready.
    </p>
    <p>
      <strong>Key Prioritization Insight:</strong> Immediate remediation should focus on <strong>${topCve.cve_id}</strong> (${topCve.vendor} ${topCve.product !== 'Unknown' ? topCve.product : ''}, CVSS ${topCveScore})${kevCount > 0 ? ' alongside all CISA KEV cataloged entries' : ''}, as active exploitation signals and public weaponization significantly elevate near-term breach probability.
    </p>
  `;

  currentBriefOverviewPlain = `Executive Threat Overview: This brief analyzes ${total} high-priority vulnerabilities impacting ${vendorSummary}. Of the tracked advisories, ${critCount} are rated Critical and ${highCount} are rated High severity under CVSS v3.x scoring. Active threat telemetry indicates that ${kevCount} are confirmed exploited in the wild (CISA KEV), ${pocCount} have public PoC exploit code on GitHub, and ${nucleiCount} have automated Nuclei detection templates ready.\n\nKey Prioritization Insight: Immediate remediation should focus on ${topCve.cve_id} (${topCve.vendor}, CVSS ${topCveScore}), as active exploitation signals and public weaponization significantly elevate near-term breach probability.`;

  if (overviewEl) overviewEl.innerHTML = currentBriefOverviewHtml;

  if (tbodyEl) {
    tbodyEl.innerHTML = items.map(item => {
      const cveId = item.cve_id;
      const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
      const scoreVal = (item.cvss !== null && item.cvss !== undefined && !isNaN(parseFloat(item.cvss))) ? parseFloat(item.cvss).toFixed(1) : 'N/A';
      const severity = getCvssSeverity(item.cvss);

      let sevBadgeStyle = 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30';
      if (severity === 'Critical') sevBadgeStyle = 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
      else if (severity === 'High') sevBadgeStyle = 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40';
      else if (severity === 'Medium') sevBadgeStyle = 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';

      const affected = item.product && item.product !== 'Unknown' ? `${item.vendor} - ${item.product}` : (item.vendor || 'Unknown');
      const epssText = (item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0) ? `${(parseFloat(item.epss) * 100).toFixed(2)}%` : '-';

      return `
        <tr class="hover:bg-indigo-500/5 transition-colors align-top">
          <td class="py-3 px-3.5 font-mono font-bold whitespace-nowrap"><a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-indigo-600 dark:text-indigo-400 hover:underline">${cveId}</a></td>
          <td class="py-3 px-3.5 font-mono whitespace-nowrap text-slate-600 dark:text-slate-300">${item.date_added || '-'}</td>
          <td class="py-3 px-3.5 font-mono font-bold whitespace-nowrap">${scoreVal}</td>
          <td class="py-3 px-3.5 whitespace-nowrap"><span class="px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${sevBadgeStyle}">${severity}</span></td>
          <td class="py-3 px-3.5 text-slate-600 dark:text-slate-300 leading-relaxed min-w-[260px]">${formatExpandableText(item.description, 140)}</td>
          <td class="py-3 px-3.5 font-semibold text-slate-800 dark:text-slate-200">${affected}</td>
          <td class="py-3 px-3.5 font-mono whitespace-nowrap">${epssText}</td>
          <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.is_kev ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}">${item.is_kev ? 'Yes (In KEV)' : 'No'}</td>
          <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.has_nuclei ? 'text-sky-600 dark:text-sky-400' : 'text-slate-400'}">${item.has_nuclei ? 'Ready' : 'Not Ready'}</td>
          <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.has_poc ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}">${item.has_poc ? 'Available' : 'Not Available'}</td>
        </tr>
      `;
    }).join('');
  }
}

function buildExportableHtmlBrief() {
  const rowsHtml = currentBriefItems.map(item => {
    const cveId = item.cve_id;
    const scoreVal = (item.cvss !== null && item.cvss !== undefined && !isNaN(parseFloat(item.cvss))) ? parseFloat(item.cvss).toFixed(1) : 'N/A';
    const severity = getCvssSeverity(item.cvss);
    const affected = item.product && item.product !== 'Unknown' ? `${item.vendor} - ${item.product}` : (item.vendor || 'Unknown');
    const epssText = (item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0) ? `${(parseFloat(item.epss) * 100).toFixed(2)}%` : '-';

    return `
      <tr>
        <td style="border:1px solid #cbd5e1;padding:8px;font-family:monospace;font-weight:bold;"><a href="https://nvd.nist.gov/vuln/detail/${cveId}">${cveId}</a></td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.date_added || '-'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;font-weight:bold;">${scoreVal}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;font-weight:bold;">${severity}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.description || ''}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${affected}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${epssText}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.is_kev ? 'Yes' : 'No'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.has_nuclei ? 'Ready' : 'Not Ready'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.has_poc ? 'Available' : 'Not Available'}</td>
      </tr>
    `;
  }).join('');

  return `
    <div>
      <h3>Watcher Vulnerability Intelligence Brief</h3>
      ${currentBriefOverviewHtml}
      <table style="border-collapse:collapse;width:100%;font-size:12px;margin-top:12px;">
        <thead>
          <tr style="background-color:#1e293b;color:#ffffff;text-align:left;">
            <th style="border:1px solid #cbd5e1;padding:8px;">Vulnerability (CVE ID)</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">Date Added</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">CVSS (v3.x) Score</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">Severity</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">Description</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">Affected Products</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">EPSS Score</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">CISA KEV</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">Nuclei Template</th>
            <th style="border:1px solid #cbd5e1;padding:8px;">PoC in GitHub</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    </div>
  `;
}

async function copyThreatBrief() {
  if (!currentBriefItems || currentBriefItems.length === 0) return;
  const htmlContent = buildExportableHtmlBrief();
  const copyBtnText = document.getElementById('btn-copy-text');

  const mdRows = currentBriefItems.map(i => {
    const scoreVal = (i.cvss !== null && i.cvss !== undefined && !isNaN(parseFloat(i.cvss))) ? parseFloat(i.cvss).toFixed(1) : 'N/A';
    const sev = getCvssSeverity(i.cvss);
    const aff = i.product && i.product !== 'Unknown' ? `${i.vendor} - ${i.product}` : (i.vendor || 'Unknown');
    const epss = (i.epss !== null && i.epss !== undefined && parseFloat(i.epss) > 0) ? `${(parseFloat(i.epss) * 100).toFixed(2)}%` : '-';
    return `| ${i.cve_id} | ${i.date_added || '-'} | ${scoreVal} | ${sev} | ${(i.description || '').replace(/\|/g, ' ')} | ${aff} | ${epss} | ${i.is_kev ? 'Yes' : 'No'} | ${i.has_nuclei ? 'Ready' : 'Not Ready'} | ${i.has_poc ? 'Available' : 'Not Available'} |`;
  }).join('\n');

  const plainContent = `Watcher Vulnerability Intelligence Brief\n\n${currentBriefOverviewPlain}\n\n| Vulnerability (CVE ID) | Date Added | CVSS (v3.x) Score | Severity | Description | Affected Products | EPSS Score | CISA KEV | Nuclei Template | PoC in GitHub |\n|---|---|---|---|---|---|---|---|---|---|\n${mdRows}`;

  try {
    if (window.ClipboardItem) {
      const item = new ClipboardItem({
        'text/html': new Blob([htmlContent], { type: 'text/html' }),
        'text/plain': new Blob([plainContent], { type: 'text/plain' })
      });
      await navigator.clipboard.write([item]);
    } else {
      await navigator.clipboard.writeText(plainContent);
    }
    if (copyBtnText) {
      copyBtnText.textContent = 'Copied!';
      setTimeout(() => { copyBtnText.textContent = 'Copy Brief'; }, 2000);
    }
  } catch (_) {
    await navigator.clipboard.writeText(plainContent);
  }
}

function toggleTeamsWebhookBox() {
  const panel = document.getElementById('teams-webhook-panel');
  const input = document.getElementById('teams-webhook-url');
  if (!panel) return;
  panel.classList.toggle('hidden');
  const savedUrl = localStorage.getItem('watcher_teams_webhook');
  if (savedUrl && input && !input.value) {
    input.value = savedUrl;
  }
}

async function sendBriefToTeams() {
  const input = document.getElementById('teams-webhook-url');
  const statusEl = document.getElementById('teams-status-msg');
  const webhookUrl = (input?.value || '').trim();

  if (!webhookUrl) {
    alert('Please paste a valid Microsoft Teams Webhook URL.');
    return;
  }
  localStorage.setItem('watcher_teams_webhook', webhookUrl);
  const htmlReport = buildExportableHtmlBrief();

  const payload = {
    title: 'Watcher Vulnerability Intelligence Brief',
    text: htmlReport
  };

  if (statusEl) {
    statusEl.textContent = 'Sending brief to Microsoft Teams...';
    statusEl.className = 'text-[11px] font-medium text-indigo-500 block';
  }

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      mode: 'no-cors',
      headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
      body: JSON.stringify(payload)
    });
    if (statusEl) {
      statusEl.textContent = 'Brief dispatched to Microsoft Teams channel!';
      statusEl.className = 'text-[11px] font-semibold text-emerald-500 block';
    }
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = `Failed to send to Teams: ${err.message}`;
      statusEl.className = 'text-[11px] font-semibold text-rose-500 block';
    }
  }
}

// =========================================================================
// 10. DEDICATED CVE SEARCH & TABLE GENERATOR
// =========================================================================
let currentCveTableItems = [];

function addSearchCveRow(yearVal = '', idVal = '') {
  const container = document.getElementById('search-cve-rows');
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'search-cve-row neu-inset rounded-xl p-1.5 flex items-center gap-1';

  row.innerHTML = `
    <span class="font-mono text-xs font-bold text-indigo-600 dark:text-indigo-400 pl-1.5 shrink-0">CVE-</span>
    <input type="text" placeholder="Year" maxlength="4" value="${yearVal}" inputmode="numeric" class="search-cve-year w-12 bg-white/70 dark:bg-slate-900/80 border border-slate-300/60 dark:border-slate-700/70 rounded-lg px-1 py-1 text-center font-mono text-xs font-semibold focus:outline-none focus:border-indigo-500 text-slate-800 dark:text-slate-100 shrink-0" />
    <span class="font-mono text-slate-400 text-xs shrink-0">-</span>
    <input type="text" placeholder="ID" maxlength="7" value="${idVal}" inputmode="numeric" class="search-cve-id w-16 bg-white/70 dark:bg-slate-900/80 border border-slate-300/60 dark:border-slate-700/70 rounded-lg px-1.5 py-1 text-center font-mono text-xs font-semibold focus:outline-none focus:border-indigo-500 text-slate-800 dark:text-slate-100 shrink-0" />
    <button type="button" onclick="addSearchCveRow()" title="Add another CVE" class="p-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm transition-all shrink-0 cursor-pointer">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4" /></svg>
    </button>
    <button type="button" onclick="removeSearchCveRow(this)" title="Remove row" class="p-1.5 rounded-lg hover:bg-rose-500/15 text-slate-400 hover:text-rose-500 transition-all shrink-0 cursor-pointer">✕</button>
  `;

  const yearInput = row.querySelector('.search-cve-year');
  const idInput = row.querySelector('.search-cve-id');
  yearInput.addEventListener('input', (e) => {
    if (e.target.value.length === 4) idInput.focus();
  });
  idInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') executeCveSearchTable();
  });

  container.appendChild(row);
  yearInput.focus();
}

function removeSearchCveRow(btn) {
  const container = document.getElementById('search-cve-rows');
  if (!container) return;
  if (container.children.length > 1) {
    btn.closest('.search-cve-row').remove();
  } else {
    const row = btn.closest('.search-cve-row');
    row.querySelector('.search-cve-year').value = '';
    row.querySelector('.search-cve-id').value = '';
  }
}

async function executeCveSearchTable() {
  const btnText = document.getElementById('btn-cve-search-text');
  const invalidBanner = document.getElementById('cve-search-invalid-banner');
  const tbodyEl = document.getElementById('cve-search-table-body');
  const countBadge = document.getElementById('cve-search-count');

  if (invalidBanner) invalidBanner.classList.add('hidden');
  if (btnText) btnText.textContent = 'Searching...';

  const rows = document.querySelectorAll('#search-cve-rows .search-cve-row');
  const requestedIds = [];
  const invalidCves = [];

  rows.forEach(r => {
    const y = (r.querySelector('.search-cve-year')?.value || '').trim();
    const id = (r.querySelector('.search-cve-id')?.value || '').trim();
    if (!y && !id) return;
    const candidate = `CVE-${y}-${id}`.toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(candidate)) {
      invalidCves.push(candidate);
    } else if (!requestedIds.includes(candidate)) {
      requestedIds.push(candidate);
    }
  });

  if (requestedIds.length === 0) {
    if (btnText) btnText.textContent = 'Generate Table';
    alert('Please enter at least one valid CVE ID.');
    return;
  }

  const localMap = getLocalCvePoolMap();
  const resolvedItems = [];

  for (const cid of requestedIds) {
    const resolved = await fetchAndValidateCustomCve(cid, localMap);
    if (resolved) {
      resolvedItems.push(resolved);
    } else {
      invalidCves.push(cid);
    }
  }

  if (btnText) btnText.textContent = 'Generate Table';

  if (invalidCves.length > 0 && invalidBanner) {
    invalidBanner.textContent = `Excluded invalid or unpublished CVE IDs: ${invalidCves.join(', ')}`;
    invalidBanner.classList.remove('hidden');
  }

  currentCveTableItems = resolvedItems;
  if (countBadge) countBadge.textContent = `${resolvedItems.length} entr${resolvedItems.length === 1 ? 'y' : 'ies'}`;

  if (resolvedItems.length === 0) {
    tbodyEl.innerHTML = `<tr><td colspan="10" class="py-8 text-center text-slate-400">No valid vulnerability records found for the requested CVE IDs.</td></tr>`;
    return;
  }

  tbodyEl.innerHTML = resolvedItems.map(item => {
    const cveId = item.cve_id;
    const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
    const scoreVal = (item.cvss !== null && item.cvss !== undefined && !isNaN(parseFloat(item.cvss))) ? parseFloat(item.cvss).toFixed(1) : 'N/A';
    const severity = getCvssSeverity(item.cvss);

    let sevBadgeStyle = 'bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30';
    if (severity === 'Critical') sevBadgeStyle = 'bg-rose-500/20 text-rose-700 dark:text-rose-300 border-rose-500/40';
    else if (severity === 'High') sevBadgeStyle = 'bg-orange-500/20 text-orange-700 dark:text-orange-300 border-orange-500/40';
    else if (severity === 'Medium') sevBadgeStyle = 'bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/40';

    const affected = item.product && item.product !== 'Unknown' ? `${item.vendor} - ${item.product}` : (item.vendor || 'Unknown');
    const epssText = (item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0) ? `${(parseFloat(item.epss) * 100).toFixed(2)}%` : '-';

    return `
      <tr class="hover:bg-indigo-500/5 transition-colors align-top">
        <td class="py-3 px-3.5 font-mono font-bold whitespace-nowrap"><a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-indigo-600 dark:text-indigo-400 hover:underline">${cveId}</a></td>
        <td class="py-3 px-3.5 font-mono whitespace-nowrap text-slate-600 dark:text-slate-300">${item.date_added || '-'}</td>
        <td class="py-3 px-3.5 font-mono font-bold whitespace-nowrap">${scoreVal}</td>
        <td class="py-3 px-3.5 whitespace-nowrap"><span class="px-2.5 py-0.5 rounded-full text-[11px] font-bold border ${sevBadgeStyle}">${severity}</span></td>
        <td class="py-3 px-3.5 text-slate-600 dark:text-slate-300 leading-relaxed min-w-[260px]">${formatExpandableText(item.description, 140)}</td>
        <td class="py-3 px-3.5 font-semibold text-slate-800 dark:text-slate-200">${affected}</td>
        <td class="py-3 px-3.5 font-mono whitespace-nowrap">${epssText}</td>
        <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.is_kev ? 'text-rose-600 dark:text-rose-400' : 'text-slate-400'}">${item.is_kev ? 'Yes (In KEV)' : 'No'}</td>
        <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.has_nuclei ? 'text-sky-600 dark:text-sky-400' : 'text-slate-400'}">${item.has_nuclei ? 'Ready' : 'Not Ready'}</td>
        <td class="py-3 px-3.5 whitespace-nowrap font-semibold ${item.has_poc ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}">${item.has_poc ? 'Available' : 'Not Available'}</td>
      </tr>
    `;
  }).join('');
}

async function copyCveSearchTable() {
  if (!currentCveTableItems || currentCveTableItems.length === 0) {
    alert('No table data to copy. Generate a table first.');
    return;
  }

  const copyBtnText = document.getElementById('btn-copy-cve-table-text');
  const rowsHtml = currentCveTableItems.map(item => {
    const scoreVal = (item.cvss !== null && item.cvss !== undefined && !isNaN(parseFloat(item.cvss))) ? parseFloat(item.cvss).toFixed(1) : 'N/A';
    const severity = getCvssSeverity(item.cvss);
    const affected = item.product && item.product !== 'Unknown' ? `${item.vendor} - ${item.product}` : (item.vendor || 'Unknown');
    const epssText = (item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0) ? `${(parseFloat(item.epss) * 100).toFixed(2)}%` : '-';

    return `
      <tr>
        <td style="border:1px solid #cbd5e1;padding:8px;font-family:monospace;font-weight:bold;"><a href="https://nvd.nist.gov/vuln/detail/${item.cve_id}">${item.cve_id}</a></td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.date_added || '-'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;font-weight:bold;">${scoreVal}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;font-weight:bold;">${severity}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.description || ''}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${affected}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${epssText}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.is_kev ? 'Yes' : 'No'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.has_nuclei ? 'Ready' : 'Not Ready'}</td>
        <td style="border:1px solid #cbd5e1;padding:8px;">${item.has_poc ? 'Available' : 'Not Available'}</td>
      </tr>
    `;
  }).join('');

  const htmlContent = `
    <table style="border-collapse:collapse;width:100%;font-size:12px;">
      <thead>
        <tr style="background-color:#1e293b;color:#ffffff;text-align:left;">
          <th style="border:1px solid #cbd5e1;padding:8px;">Vulnerability (CVE ID)</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">Date Added</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">CVSS (v3.x) Score</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">Severity</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">Description</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">Affected Products</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">EPSS Score</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">CISA KEV</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">Nuclei Template</th>
          <th style="border:1px solid #cbd5e1;padding:8px;">PoC in GitHub</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>
  `;

  const mdRows = currentCveTableItems.map(i => {
    const scoreVal = (i.cvss !== null && i.cvss !== undefined && !isNaN(parseFloat(i.cvss))) ? parseFloat(i.cvss).toFixed(1) : 'N/A';
    const sev = getCvssSeverity(i.cvss);
    const aff = i.product && i.product !== 'Unknown' ? `${i.vendor} - ${i.product}` : (i.vendor || 'Unknown');
    const epss = (i.epss !== null && i.epss !== undefined && parseFloat(i.epss) > 0) ? `${(parseFloat(i.epss) * 100).toFixed(2)}%` : '-';
    return `| ${i.cve_id} | ${i.date_added || '-'} | ${scoreVal} | ${sev} | ${(i.description || '').replace(/\|/g, ' ')} | ${aff} | ${epss} | ${i.is_kev ? 'Yes' : 'No'} | ${i.has_nuclei ? 'Ready' : 'Not Ready'} | ${i.has_poc ? 'Available' : 'Not Available'} |`;
  }).join('\n');

  const plainContent = `| Vulnerability (CVE ID) | Date Added | CVSS (v3.x) Score | Severity | Description | Affected Products | EPSS Score | CISA KEV | Nuclei Template | PoC in GitHub |\n|---|---|---|---|---|---|---|---|---|---|\n${mdRows}`;

  try {
    if (window.ClipboardItem) {
      const item = new ClipboardItem({
        'text/html': new Blob([htmlContent], { type: 'text/html' }),
        'text/plain': new Blob([plainContent], { type: 'text/plain' })
      });
      await navigator.clipboard.write([item]);
    } else {
      await navigator.clipboard.writeText(plainContent);
    }
    if (copyBtnText) {
      copyBtnText.textContent = 'Copied!';
      setTimeout(() => { copyBtnText.textContent = 'Copy Table'; }, 2000);
    }
  } catch (_) {
    await navigator.clipboard.writeText(plainContent);
  }
}

// Trigger initial load
initDashboard();