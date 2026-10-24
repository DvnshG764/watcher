// State holders
let trendingData = { confirmed_in_wild: [], early_warning: [] };
let vendorData = [];
let newsData = [];
let configuredVendors = [];
let configuredNewsSources = [];
let selectedVendor = 'All';
let selectedNewsSource = 'All';

// -------------------------------------------------------------
// 1. THEME TOGGLE (Dark / Light)
// -------------------------------------------------------------
const themeToggleBtn = document.getElementById('theme-toggle');
const sunIcon = document.getElementById('theme-icon-sun');
const moonIcon = document.getElementById('theme-icon-moon');

function initTheme() {
  const isDark = localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches);
  if (isDark) {
    document.documentElement.classList.add('dark');
    sunIcon.classList.remove('hidden');
    moonIcon.classList.add('hidden');
  } else {
    document.documentElement.classList.remove('dark');
    sunIcon.classList.add('hidden');
    moonIcon.classList.remove('hidden');
  }
}

themeToggleBtn.addEventListener('click', () => {
  const isDark = document.documentElement.classList.contains('dark');
  if (isDark) {
    document.documentElement.classList.remove('dark');
    localStorage.theme = 'light';
    sunIcon.classList.add('hidden');
    moonIcon.classList.remove('hidden');
  } else {
    document.documentElement.classList.add('dark');
    localStorage.theme = 'dark';
    sunIcon.classList.remove('hidden');
    moonIcon.classList.add('hidden');
  }
});

// -------------------------------------------------------------
// 2. TAB SWITCHING
// -------------------------------------------------------------
function switchTab(tabName) {
  document.querySelectorAll('nav button, .flex.md\\:hidden button').forEach(b => {
    b.classList.remove('bg-indigo-600', 'text-white');
    b.classList.add('text-gray-600', 'dark:text-gray-300');
  });

  const activeBtn = document.getElementById(`tab-${tabName}`);
  if (activeBtn) {
    activeBtn.classList.remove('text-gray-600', 'dark:text-gray-300');
    activeBtn.classList.add('bg-indigo-600', 'text-white');
  }

  ['radar', 'vendor', 'news'].forEach(t => {
    const el = document.getElementById(`view-${t}`);
    if (el) el.classList.add('hidden');
  });

  const targetView = document.getElementById(`view-${tabName}`);
  if (targetView) targetView.classList.remove('hidden');

  document.getElementById('search-view').classList.add('hidden');
}

// -------------------------------------------------------------
// 3. UI HELPERS (Read More, CVSS & Badges)
// -------------------------------------------------------------
function toggleReadMore(btn) {
  const parent = btn.parentElement;
  const fullText = parent.querySelector('.full-text');
  const shortText = parent.querySelector('.short-text');

  if (fullText.classList.contains('hidden')) {
    fullText.classList.remove('hidden');
    shortText.classList.add('hidden');
    btn.textContent = 'Show less';
  } else {
    fullText.classList.add('hidden');
    shortText.classList.remove('hidden');
    btn.textContent = 'Read more';
  }
}

function formatExpandableText(text, limit = 160) {
  if (!text) return '<span class="text-gray-400 italic">No description provided.</span>';
  if (text.length <= limit) return `<span>${text}</span>`;

  const short = text.substring(0, limit) + '...';
  return `
    <div>
      <span class="short-text">${short}</span>
      <span class="full-text hidden">${text}</span>
      <button onclick="toggleReadMore(this)" class="text-indigo-500 hover:underline text-[11px] font-semibold ml-1 cursor-pointer">Read more</button>
    </div>
  `;
}

// CVSS link routes directly to NVD
function formatCvssBadge(score, cveId) {
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  if (score === null || score === undefined || score === '') {
    return `<a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-400 border border-gray-200 dark:border-darkBorder hover:underline" title="View CVSS on NVD">CVSS N/A</a>`;
  }
  const val = parseFloat(score);
  let colorClasses = 'bg-gray-100 dark:bg-darkBase text-gray-700 dark:text-gray-300 border-gray-300 dark:border-darkBorder';
  if (val >= 9.0) {
    colorClasses = 'bg-red-100 dark:bg-red-950/80 text-red-700 dark:text-red-300 border-red-300 dark:border-red-900 font-bold';
  } else if (val >= 7.0) {
    colorClasses = 'bg-orange-100 dark:bg-orange-950/80 text-orange-700 dark:text-orange-300 border-orange-300 dark:border-orange-900 font-bold';
  } else if (val >= 4.0) {
    colorClasses = 'bg-amber-100 dark:bg-amber-950/80 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-900 font-semibold';
  }
  return `<a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-xs px-2 py-0.5 rounded border ${colorClasses} hover:underline" title="View CVSS Specification on NVD">CVSS ${val.toFixed(1)}</a>`;
}

// -------------------------------------------------------------
// STANDARDIZED CARD BUILDER (RADAR, VENDOR, AND SEARCH)
// -------------------------------------------------------------
function buildStandardThreatCard(item, cardType = 'radar_kev') {
  const vendorName = item.vendor || 'Unknown';
  const productName = item.product && item.product !== 'Unknown' ? `- ${item.product}` : '';
  const vendorProduct = `${vendorName} ${productName}`.trim();

  const cveId = item.cve_id;
  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;

  // Interactive Target URLs
  const cisaUrl = `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cveId}`;
  const epssUrl = `https://api.first.org/epss?cve=${cveId}`;
  const pocUrl = `https://github.com/nomi-sec/PoC-in-GitHub/search?q=${cveId}`;
  const nucleiUrl = `https://github.com/projectdiscovery/nuclei-templates/search?q=${cveId}`;

  // Date Section Layout
  let dateMarkup = '';
  if (cardType === 'radar_kev') {
    dateMarkup = `
      <div class="grid grid-cols-2 text-[11px] text-gray-500 dark:text-gray-400 py-1">
        <div><span class="font-medium text-gray-700 dark:text-gray-300">Added Date:</span> ${item.date_added || '-'}</div>
        <div class="text-right"><span class="font-medium text-gray-700 dark:text-gray-300">Due Date:</span> ${item.due_date || '-'}</div>
      </div>
    `;
  } else {
    // Exploit Radar & Vendor Focus: Detected Date only
    dateMarkup = `
      <div class="text-[11px] text-gray-500 dark:text-gray-400 py-1">
        <span class="font-medium text-gray-700 dark:text-gray-300">Detected Date:</span> ${item.date_added || item.date || item.first_seen || '-'}
      </div>
    `;
  }

  // EPSS Badge: Disabled link if score is not present
  const hasEpss = (item.epss !== null && item.epss !== undefined && parseFloat(item.epss) > 0);
  const epssBadge = hasEpss
    ? `<a href="${epssUrl}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-700 dark:text-gray-300 border border-gray-300 dark:border-darkBorder font-mono font-medium hover:border-indigo-500 transition-colors" title="Inspect EPSS Probability on FIRST.org">
        EPSS: ${(parseFloat(item.epss) * 100).toFixed(2)}%
       </a>`
    : `<span class="px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-400 border border-gray-200 dark:border-darkBorder font-mono">
        EPSS: -
       </span>`;

  const pocStatus = item.has_poc
    ? `<a href="${pocUrl}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950/80 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 font-semibold hover:underline" title="View Exploit PoCs on GitHub">PoC: Available</a>`
    : `<span class="px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-darkBorder">PoC: Not Available</span>`;

  const nucleiStatus = item.has_nuclei
    ? `<a href="${nucleiUrl}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-950/80 text-blue-700 dark:text-blue-300 border border-blue-300 dark:border-blue-800 font-semibold hover:underline" title="View Nuclei Templates on GitHub">Nuclei Template: Ready</a>`
    : `<span class="px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-darkBorder">Nuclei Template: Not Ready</span>`;

  const kevBadge = (cardType === 'radar_kev' || item.is_kev)
    ? `<a href="${cisaUrl}" target="_blank" rel="noopener noreferrer" class="px-2 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-900 font-bold hover:underline" title="View CISA KEV Catalog Listing">CISA KEV</a>`
    : '';

  return `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
      <div>
        <!-- Row 1: Enlarged CVE ID Button (NVD Link) & CVSS Score (NVD Link) -->
        <div class="flex items-center justify-between gap-2 mb-1.5">
          <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-base font-bold font-mono text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 hover:underline tracking-wide" title="Inspect full NVD specification">
            ${cveId}
          </a>
          ${formatCvssBadge(item.cvss, cveId)}
        </div>

        <!-- Row 2: Vendor - Product -->
        <h3 class="text-xs font-semibold text-gray-800 dark:text-gray-200 mb-2">${vendorProduct}</h3>

        <!-- Row 3: Description -->
        <div class="text-xs text-gray-600 dark:text-gray-400 leading-relaxed mb-3">
          ${formatExpandableText(item.description || item.vuln_name, 160)}
        </div>

        <!-- Divider 1 -->
        <div class="border-t border-gray-200 dark:border-darkBorder/60 my-2.5"></div>

        <!-- Row 4: Dates -->
        ${dateMarkup}

        <!-- Divider 2 -->
        <div class="border-t border-gray-200 dark:border-darkBorder/60 my-2.5"></div>

        <!-- Row 5: Interactive Status Badges -->
        <div class="flex flex-wrap items-center gap-1.5 text-[11px] pt-1">
          ${kevBadge}
          ${epssBadge}
          ${pocStatus}
          ${nucleiStatus}
        </div>
      </div>
    </div>
  `;
}

// -------------------------------------------------------------
// 4. DATA LOADER
// -------------------------------------------------------------
async function fetchWithFallback(filename) {
  const paths = [`data/${filename}`, `./data/${filename}`, `../data/${filename}`];
  for (const path of paths) {
    try {
      const res = await fetch(path);
      if (res.ok) return await res.json();
    } catch (e) {}
  }
  return null;
}

async function loadData() {
  try {
    const [trending, vendors, news, meta, cfgVendors, cfgFeeds] = await Promise.all([
      fetchWithFallback('trending.json'),
      fetchWithFallback('vendors.json'),
      fetchWithFallback('news.json'),
      fetchWithFallback('sync_meta.json'),
      fetchWithFallback('config_vendors.json'),
      fetchWithFallback('config_feeds.json')
    ]);

    if (trending) {
      trendingData = trending;
      renderRadar();
    }
    if (vendors) {
      vendorData = vendors;
    }
    if (news) {
      newsData = news;
    }
    if (meta) {
      renderMeta(meta);
    }

    // Ingest vendor config for dynamic UI pills
    if (cfgVendors && typeof cfgVendors === 'object') {
      configuredVendors = Object.keys(cfgVendors);
    } else if (vendorData) {
      configuredVendors = [...new Set(vendorData.map(v => v.vendor))];
    }
    renderVendorPills();
    renderVendorView();

    // Ingest feeds config for dynamic UI pills
    if (cfgFeeds && Array.isArray(cfgFeeds)) {
      configuredNewsSources = cfgFeeds.map(f => f.name);
    } else if (newsData) {
      configuredNewsSources = [...new Set(newsData.map(n => n.source))];
    }
    renderNewsSourcePills();
    renderNews();

  } catch (err) {
    console.error('[Watcher] Render error:', err);
  }
}

function renderMeta(meta) {
  const syncTimeEl = document.getElementById('meta-sync-time');
  if (syncTimeEl && meta && meta.last_sync) {
    syncTimeEl.textContent = meta.last_sync;
  }
}

// -------------------------------------------------------------
// 5. RENDER RADAR (CISA KEV & Exploit Radar)
// -------------------------------------------------------------
function renderRadar() {
  const kevContainer = document.getElementById('radar-kev-list');
  const earlyContainer = document.getElementById('radar-early-list');

  document.getElementById('kev-count').textContent = `${trendingData.confirmed_in_wild.length} entries`;
  document.getElementById('early-count').textContent = `${trendingData.early_warning.length} alerts`;

  // Render CISA KEV Column
  kevContainer.innerHTML = trendingData.confirmed_in_wild
    .map(item => buildStandardThreatCard(item, 'radar_kev'))
    .join('');

  // Render Exploit Radar Column
  earlyContainer.innerHTML = trendingData.early_warning
    .map(item => buildStandardThreatCard(item, 'radar_early'))
    .join('');
}

// -------------------------------------------------------------
// 6. RENDER VENDOR FOCUS (DYNAMIC FROM CONFIG)
// -------------------------------------------------------------
function renderVendorPills() {
  const container = document.getElementById('vendor-pills');
  const vendors = ['All', ...configuredVendors];

  container.innerHTML = vendors.map(v => `
    <button 
      onclick="filterVendor('${v}')" 
      class="vendor-btn px-3 py-1 rounded-full text-xs font-semibold transition-colors border ${
        v === selectedVendor 
          ? 'bg-indigo-600 text-white border-indigo-600' 
          : 'bg-white dark:bg-darkCard text-gray-600 dark:text-gray-300 border-gray-300 dark:border-darkBorder hover:bg-gray-100 dark:hover:bg-gray-800'
      }"
    >
      ${v}
    </button>
  `).join('');
}

function filterVendor(vendorName) {
  selectedVendor = vendorName;
  renderVendorPills();
  renderVendorView();
}

function renderVendorView() {
  const container = document.getElementById('vendor-grid');

  let filtered = vendorData;
  if (selectedVendor !== 'All') {
    filtered = filtered.filter(v => v.vendor.toLowerCase() === selectedVendor.toLowerCase());
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-gray-400 text-sm">No vulnerabilities found for the selected vendor.</div>`;
    return;
  }

  container.innerHTML = filtered
    .map(item => buildStandardThreatCard(item, 'vendor'))
    .join('');
}

// -------------------------------------------------------------
// 7. RENDER NEWS FEED (DYNAMIC FROM CONFIG)
// -------------------------------------------------------------
function renderNewsSourcePills() {
  const container = document.getElementById('news-source-pills');
  const sources = ['All', ...configuredNewsSources];

  container.innerHTML = sources.map(s => `
    <button 
      onclick="filterNewsSource('${s}')" 
      class="news-btn px-3 py-1 rounded-full text-xs font-semibold transition-colors border ${
        s === selectedNewsSource 
          ? 'bg-indigo-600 text-white border-indigo-600' 
          : 'bg-white dark:bg-darkCard text-gray-600 dark:text-gray-300 border-gray-300 dark:border-darkBorder hover:bg-gray-100 dark:hover:bg-gray-800'
      }"
    >
      ${s}
    </button>
  `).join('');
}

function filterNewsSource(sourceName) {
  selectedNewsSource = sourceName;
  renderNewsSourcePills();
  renderNews();
}

function renderNews() {
  const container = document.getElementById('news-grid');
  
  let filtered = newsData;
  if (selectedNewsSource !== 'All') {
    filtered = filtered.filter(n => n.source.toLowerCase() === selectedNewsSource.toLowerCase());
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-gray-400 text-sm">No news items found for the selected source.</div>`;
    return;
  }

  container.innerHTML = filtered.map(article => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
      <div>
        <!-- Row 1: Source & Published Timestamp Header -->
        <div class="flex items-center justify-between text-[11px] text-gray-400 mb-2">
          <span class="font-semibold text-indigo-500">${article.source}</span>
          <span>${article.published || ''}</span>
        </div>

        <!-- Row 2: Headline / Article Link -->
        <a href="${article.url}" target="_blank" rel="noopener noreferrer" class="text-sm font-bold text-gray-900 dark:text-gray-100 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors block mb-2 leading-snug">
          ${article.title}
        </a>

        <!-- Row 3: Description / Summary -->
        <div class="text-xs text-gray-600 dark:text-gray-400 leading-relaxed mb-3">
          ${formatExpandableText(article.snippet, 180)}
        </div>

        <!-- Divider 1 -->
        <div class="border-t border-gray-200 dark:border-darkBorder/60 my-2.5"></div>

        <!-- Row 4: Associated CVEs (Leading to NVD) & Vendors -->
        <div class="flex flex-wrap items-center gap-1.5 pt-1 text-[11px]">
          ${(article.matched_cves || []).map(cve => `
            <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener noreferrer" class="font-mono font-semibold px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/80 text-indigo-600 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900 hover:underline" title="Inspect ${cve} on NVD">
              ${cve}
            </a>
          `).join('')}
          ${(article.matched_vendors || []).map(v => `
            <span class="px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-darkBorder">
              ${v}
            </span>
          `).join('')}
        </div>
      </div>
    </div>
  `).join('');
}

// -------------------------------------------------------------
// 8. DIRECT NVD SEARCH HANDLER
// -------------------------------------------------------------
function executeDirectNvdSearch() {
  const inputEl = document.getElementById('nvd-direct-input');
  let val = inputEl.value.trim().toUpperCase();
  if (!val) return;

  if (!val.startsWith('CVE-')) {
    val = 'CVE-' + val;
  }
  
  // Format validation: CVE-YYYY-NNNNN
  const cvePattern = /^CVE-\d{4}-\d{4,7}$/;
  if (!cvePattern.test(val)) {
    alert("Please enter a valid format, e.g., CVE-2024-38077");
    return;
  }

  window.open(`https://nvd.nist.gov/vuln/detail/${val}`, '_blank');
  inputEl.value = '';
}

// Allow Enter key to trigger direct search
document.getElementById('nvd-direct-input')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    executeDirectNvdSearch();
  }
});

// -------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------
initTheme();
loadData();