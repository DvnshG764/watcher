// Live State Containers (Populated strictly from backend JSON feeds)
let trendingData = { confirmed_in_wild: [], early_warning: [] };
let vendorData = [];
let newsData = [];
let cweMap = {};
let configuredVendors = [];
let configuredNewsSources = [];
let selectedVendor = 'All';
let selectedNewsSource = 'All';
let activeTab = 'radar';

// =========================================================================
// 1. SIDEBAR COLLAPSE / EXPAND LOGIC (Pure CSS Class Driven)
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
// 2. THEME SWITCHER (DARK / LIGHT)
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
// 3. TAB NAVIGATION
// =========================================================================
function switchTab(tabName) {
  activeTab = tabName;
  ['radar', 'vendor', 'news'].forEach(t => {
    document.getElementById(`nav-${t}`)?.classList.toggle('active', t === tabName);
    document.getElementById(`view-${t}`)?.classList.toggle('hidden', t !== tabName);
  });

  document.getElementById('search-view')?.classList.add('hidden');

  const titles = {
    radar: 'EXPLOIT RADAR',
    vendor: 'VENDOR FOCUS',
    news: 'CURATED THREAT NEWS'
  };
  const titleEl = document.getElementById('workspace-title');
  if (titleEl) titleEl.textContent = titles[tabName] || 'EXPLOIT RADAR';
}

// =========================================================================
// 4. EXPANDABLE DESCRIPTION & CVSS BADGE HELPERS
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

function formatCvssBadge(score, cveId) {
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  if (score === null || score === undefined || score === '') {
    return `<a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs font-mono font-semibold px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-400 border border-slate-400/20 hover:underline" title="Inspect on NVD">CVSS N/A</a>`;
  }
  const val = parseFloat(score);
  let style = 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  if (val >= 9.0) {
    style = 'bg-gradient-to-r from-amber-500/20 to-rose-500/25 text-amber-700 dark:text-amber-300 border-amber-500/45 shadow-sm shadow-amber-500/10';
  } else if (val >= 7.0) {
    style = 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/40';
  } else if (val >= 4.0) {
    style = 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-300 border-yellow-500/40';
  }
  return `
    <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs font-mono font-bold px-3 py-1 rounded-full border ${style} hover:scale-105 transition-transform" title="View CVSS Specification on NIST NVD">
      CVSS ${val.toFixed(1)}
    </a>
  `;
}

// =========================================================================
// 5. STANDARDIZED GLASSMORPHIC CARD BUILDER
// =========================================================================
function buildStandardThreatCard(item, cardType = 'radar_kev') {
  const cveId = item.cve_id;
  const vendorName = item.vendor || 'Unknown';
  const productName = item.product && item.product !== 'Unknown' ? `- ${item.product}` : '';
  const vendorProduct = `${vendorName} ${productName}`.trim();

  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`;
  const pocUrl = `https://github.com/nomi-sec/PoC-in-GitHub/search?q=${cveId}`;
  const nucleiUrl = `https://github.com/projectdiscovery/nuclei-templates/search?q=${cveId}`;

  // Glow Perimeter Class
  let glowClass = 'vendor-card-glow';
  if (cardType === 'radar_kev' || item.is_kev) glowClass = 'kev-card-glow';
  else if (cardType === 'radar_early') glowClass = 'early-card-glow';

  // Date Well Markup
  let dateWellMarkup = '';
  if (cardType === 'radar_kev') {
    dateWellMarkup = `
      <div class="recessed-box rounded-xl px-3.5 py-2 my-3 grid grid-cols-2 items-center text-[11px] font-mono">
        <div class="text-slate-500 dark:text-slate-400">
          Added Date: <span class="font-semibold text-slate-800 dark:text-slate-200">${item.date_added || '-'}</span>
        </div>
        <div class="text-right text-slate-500 dark:text-slate-400 border-l border-slate-300/50 dark:border-slate-700/60 pl-3">
          Due Date: <span class="font-semibold text-rose-600 dark:text-rose-400">${item.due_date || '-'}</span>
        </div>
      </div>
    `;
  } else {
    dateWellMarkup = `
      <div class="recessed-box rounded-xl px-3.5 py-2 my-3 text-[11px] font-mono text-slate-500 dark:text-slate-400">
        Detected Date: <span class="font-semibold text-slate-800 dark:text-slate-200">${item.date_added || item.date || item.first_seen || '-'}</span>
      </div>
    `;
  }

  // Static EPSS Pill (No Link)
  const hasEpss = item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0;
  const epssBadge = hasEpss
    ? `<span class="px-3 py-1 rounded-full bg-slate-500/10 dark:bg-slate-800/90 text-slate-700 dark:text-slate-200 border border-slate-300/80 dark:border-slate-700 font-mono font-semibold">
        EPSS: ${(parseFloat(item.epss) * 100).toFixed(2)}%
       </span>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/5 text-slate-400 border border-slate-300/40 dark:border-slate-800 font-mono">
        EPSS: -
       </span>`;

  // PoC Pill
  const pocBadge = item.has_poc
    ? `<a href="${pocUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/40 font-semibold hover:bg-emerald-500/25 transition-colors" title="Search Exploit PoC on GitHub">
        PoC: Available
       </a>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-300/50 dark:border-slate-800">
        PoC: Not Available
       </span>`;

  // Nuclei Pill
  const nucleiBadge = item.has_nuclei
    ? `<a href="${nucleiUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/40 font-semibold hover:bg-sky-500/25 transition-colors" title="View Nuclei Template on GitHub">
        Nuclei Template: Ready
       </a>`
    : `<span class="px-3 py-1 rounded-full bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-300/50 dark:border-slate-800">
        Nuclei Template: Not Ready
       </span>`;

  // CISA KEV Pill
  const kevBadge = (cardType === 'radar_kev' || item.is_kev)
    ? `<a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" class="px-3 py-1 rounded-full bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/45 font-bold hover:bg-rose-500/30 transition-colors" title="View in CISA KEV Catalog">
        CISA KEV
       </a>`
    : '';

  return `
    <article class="neu-glass-card ${glowClass} rounded-2xl p-5 flex flex-col justify-between">
      <div>
        <!-- Row 1: Enlarged Clickable CVE ID + CVSS Pill -->
        <div class="flex items-center justify-between gap-2 mb-1">
          <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-lg font-extrabold font-mono tracking-tight text-slate-900 dark:text-white hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors" title="Open Official NIST NVD Specification">
            ${cveId}
          </a>
          ${formatCvssBadge(item.cvss, cveId)}
        </div>

        <!-- Row 2: Vendor - Product -->
        <h3 class="text-xs font-semibold text-indigo-600 dark:text-indigo-300 mb-2.5">
          ${vendorProduct}
        </h3>

        <!-- Row 3: Expandable Description -->
        <div class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
          ${formatExpandableText(item.description || item.vuln_name, 160)}
        </div>

        <!-- Row 4: Recessed Date Box -->
        ${dateWellMarkup}
      </div>

      <!-- Row 5: Stacked Intelligence Pills -->
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
// 6. RENDER VIEWS (RADAR, VENDORS, NEWS)
// =========================================================================
function renderRadar() {
  const kevList = trendingData.confirmed_in_wild || [];
  const earlyList = trendingData.early_warning || [];

  document.getElementById('kpi-kev-count').textContent = kevList.length;
  document.getElementById('kpi-early-count').textContent = earlyList.length;

  const kevContainer = document.getElementById('radar-kev-list');
  const earlyContainer = document.getElementById('radar-early-list');

  if (kevList.length === 0) {
    kevContainer.innerHTML = `<div class="neu-glass-card rounded-2xl p-8 text-center text-xs text-slate-400">No CISA KEV entries loaded.</div>`;
  } else {
    kevContainer.innerHTML = kevList.map(item => buildStandardThreatCard(item, 'radar_kev')).join('');
  }

  if (earlyList.length === 0) {
    earlyContainer.innerHTML = `<div class="neu-glass-card rounded-2xl p-8 text-center text-xs text-slate-400">No Early Warning entries loaded.</div>`;
  } else {
    earlyContainer.innerHTML = earlyList.map(item => buildStandardThreatCard(item, 'radar_early')).join('');
  }
}

function renderVendorPills() {
  const container = document.getElementById('vendor-pills');
  const vendors = ['All', ...configuredVendors];

  container.innerHTML = vendors.map(v => `
    <button 
      onclick="filterVendor('${v}')" 
      class="px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all ${
        v === selectedVendor 
          ? 'bg-indigo-600 text-white shadow-md shadow-indigo-500/30' 
          : 'neu-glass-card text-slate-600 dark:text-slate-300 hover:border-indigo-500/40'
      }"
    >
      ${v}
    </button>
  `).join('');
}

function filterVendor(vName) {
  selectedVendor = vName;
  renderVendorPills();
  renderVendorView();
}

function renderVendorView() {
  const container = document.getElementById('vendor-grid');
  let filtered = vendorData || [];
  if (selectedVendor !== 'All') {
    filtered = filtered.filter(v => (v.vendor || '').toLowerCase() === selectedVendor.toLowerCase());
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="col-span-full neu-glass-card rounded-2xl p-10 text-center text-sm text-slate-400">
        No advisories currently indexed for <strong class="text-slate-700 dark:text-slate-200">${selectedVendor}</strong>.
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
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
        ${(article.matched_vendors || []).map(v => `
          <span class="px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-600 dark:text-slate-300 border border-slate-300/50 dark:border-slate-700 font-medium">
            ${v}
          </span>
        `).join('')}
      </div>
    </article>
  `).join('');
}

// =========================================================================
// 7. STRUCTURED CVE-YYYY-NNNNN NVD LOOKUP (Sidebar Search 2)
// =========================================================================
function triggerDirectNvdSearch() {
  const yearEl = document.getElementById('nvd-year');
  const idEl = document.getElementById('nvd-id');
  const year = yearEl.value.trim();
  const id = idEl.value.trim();

  if (!/^\d{4}$/.test(year) || !/^\d{4,7}$/.test(id)) {
    alert('Please enter a valid 4-digit Year (e.g., 2026) and 4-to-7 digit CVE ID (e.g., 38077).');
    return;
  }

  const fullCve = `CVE-${year}-${id}`;
  window.open(`https://nvd.nist.gov/vuln/detail/${fullCve}`, '_blank');
}

document.getElementById('nvd-year')?.addEventListener('input', (e) => {
  if (e.target.value.length === 4) {
    document.getElementById('nvd-id')?.focus();
  }
});
document.getElementById('nvd-id')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') triggerDirectNvdSearch();
});

// =========================================================================
// 8. LIVE DATA & CONFIG LOADER (Strictly from Backend & Config JSONs)
// =========================================================================
async function fetchJsonFile(possiblePaths) {
  for (const p of possiblePaths) {
    try {
      const res = await fetch(p, { cache: 'no-store' });
      if (res.ok) return await res.json();
    } catch (_) {}
  }
  return null;
}

async function initDashboard() {
  initTheme();

  const [trending, vendors, news, meta, cfgVendors, cfgFeeds, cwes] = await Promise.all([
    fetchJsonFile(['data/trending.json', './data/trending.json', '../docs/data/trending.json']),
    fetchJsonFile(['data/vendors.json', './data/vendors.json', '../docs/data/vendors.json']),
    fetchJsonFile(['data/news.json', './data/news.json', '../docs/data/news.json']),
    fetchJsonFile(['data/sync_meta.json', './data/sync_meta.json', '../docs/data/sync_meta.json']),
    // Dynamically fetch from synced config_vendors.json or directly from ../config/vendors.json
    fetchJsonFile(['data/config_vendors.json', './data/config_vendors.json', '../config/vendors.json']),
    // Dynamically fetch from synced config_feeds.json or directly from ../config/feeds.json
    fetchJsonFile(['data/config_feeds.json', './data/config_feeds.json', '../config/feeds.json']),
    fetchJsonFile(['data/cwe_definitions.json', './data/cwe_definitions.json', '../data/cwe_definitions.json'])
  ]);

  if (trending) trendingData = trending;
  if (vendors) vendorData = vendors;
  if (news) newsData = news;
  if (cwes) cweMap = cwes;

  // Populate Vendor Filter Pills dynamically from config/vendors.json
  if (cfgVendors && typeof cfgVendors === 'object' && !Array.isArray(cfgVendors)) {
    configuredVendors = Object.keys(cfgVendors);
  } else if (Array.isArray(vendorData)) {
    configuredVendors = [...new Set(vendorData.map(v => v.vendor).filter(Boolean))];
  }

  // Populate News Source Filter Pills dynamically from config/feeds.json
  if (cfgFeeds && Array.isArray(cfgFeeds)) {
    configuredNewsSources = cfgFeeds.map(f => f.name).filter(Boolean);
  } else if (Array.isArray(newsData)) {
    configuredNewsSources = [...new Set(newsData.map(n => n.source).filter(Boolean))];
  }

  const syncEl = document.getElementById('meta-sync-time');
  if (syncEl) {
    syncEl.textContent = (meta && meta.last_sync) ? meta.last_sync : 'Unavailable';
  }

  renderRadar();
  renderVendorPills();
  renderVendorView();
  renderNewsSourcePills();
  renderNewsView();
}

initDashboard();