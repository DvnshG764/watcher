// State holders
let trendingData = { confirmed_in_wild: [], early_warning: [] };
let vendorData = [];
let newsData = [];
let selectedVendor = 'All';

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
// 3. READ MORE TOGGLE HELPER
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
    const [trending, vendors, news, meta] = await Promise.all([
      fetchWithFallback('trending.json'),
      fetchWithFallback('vendors.json'),
      fetchWithFallback('news.json'),
      fetchWithFallback('sync_meta.json')
    ]);

    if (trending) {
      trendingData = trending;
      renderRadar();
    }
    if (vendors) {
      vendorData = vendors;
      renderVendorPills();
      renderVendorView();
    }
    if (news) {
      newsData = news;
      renderNews();
    }
    if (meta) {
      renderMeta(meta);
    }
  } catch (err) {
    console.error('[Watcher] Render error:', err);
  }
}

function renderMeta(meta) {
  const syncTimeEl = document.getElementById('meta-sync-time');
  const countsEl = document.getElementById('meta-counts');
  
  if (syncTimeEl && meta && meta.last_sync) {
    syncTimeEl.textContent = meta.last_sync;
  }
  if (countsEl && meta && meta.counts) {
    countsEl.textContent = `KEV: ${meta.counts.cisa_kev} | Pre-KEV Radar: ${meta.counts.early_warning} | Vendor Alerts: ${meta.counts.vendor_alerts} | News: ${meta.counts.news_articles}`;
  }
}

// -------------------------------------------------------------
// 5. RENDER EXPLOIT RADAR
// -------------------------------------------------------------
function renderRadar() {
  const kevContainer = document.getElementById('radar-kev-list');
  const earlyContainer = document.getElementById('radar-early-list');

  document.getElementById('kev-count').textContent = `${trendingData.confirmed_in_wild.length} entries`;
  document.getElementById('early-count').textContent = `${trendingData.early_warning.length} alerts`;

  // Render KEV Column
  kevContainer.innerHTML = trendingData.confirmed_in_wild.map(item => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm hover:border-red-500/50">
      <div class="flex items-start justify-between gap-2 mb-1.5">
        <div>
          <span class="text-sm font-bold text-red-600 dark:text-red-400 tracking-wide">${item.cve_id}</span>
          <h3 class="text-xs font-semibold text-gray-800 dark:text-gray-200">${item.vendor} / ${item.product}</h3>
        </div>
        <span class="text-[11px] font-bold px-2 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-900">
          CISA KEV
        </span>
      </div>

      <div class="text-xs text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">
        ${formatExpandableText(item.description || item.vuln_name, 150)}
      </div>

      <div class="flex flex-wrap items-center gap-1.5 pt-2 border-t border-gray-100 dark:border-darkBorder/60 text-[11px]">
        <span class="text-gray-500">Added: ${item.date_added}</span>
        ${item.due_date ? `<span class="text-gray-400">• Due: ${item.due_date}</span>` : ''}
        ${item.epss ? `<span class="ml-auto font-mono text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase font-semibold">EPSS ${(item.epss * 100).toFixed(1)}%</span>` : ''}
      </div>

      <div class="flex items-center gap-2 mt-2 pt-2 border-t border-gray-100 dark:border-darkBorder/40">
        <a href="https://nvd.nist.gov/vuln/detail/${item.cve_id}" target="_blank" class="text-[11px] text-indigo-500 hover:underline">NVD Spec</a>
        ${item.has_poc ? '<span class="text-[11px] text-amber-500 font-semibold">• PoC Available</span>' : ''}
        ${item.has_nuclei ? '<span class="text-[11px] text-blue-500 font-semibold">• Nuclei Template</span>' : ''}
      </div>
    </div>
  `).join('');

  // Render Early Warning Column
  earlyContainer.innerHTML = trendingData.early_warning.map(item => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm hover:border-amber-500/50">
      <div class="flex items-start justify-between gap-2 mb-1.5">
        <div>
          <span class="text-sm font-bold text-amber-600 dark:text-amber-400 tracking-wide">${item.cve_id}</span>
          <span class="text-xs text-gray-400 block">${item.first_seen || 'Recently Flagged'}</span>
        </div>
        <div class="flex items-center gap-1">
          ${item.cvss ? `<span class="text-xs font-bold px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase border border-gray-300 dark:border-darkBorder">${item.cvss}</span>` : ''}
          <span class="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
            EPSS ${(item.epss * 100).toFixed(1)}%
          </span>
        </div>
      </div>

      <div class="text-xs text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">
        ${formatExpandableText(item.description, 160)}
      </div>

      <div class="flex flex-wrap items-center gap-1.5 pt-2 border-t border-gray-100 dark:border-darkBorder/60 text-[11px]">
        ${item.has_poc ? '<span class="px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-600 dark:text-amber-300 border border-amber-300 dark:border-amber-900 font-semibold">PoC in GitHub</span>' : ''}
        ${item.has_nuclei ? '<span class="px-2 py-0.5 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-300 border border-blue-300 dark:border-blue-900 font-semibold">Nuclei Ready</span>' : ''}
        ${item.in_news ? '<span class="px-2 py-0.5 rounded bg-purple-50 dark:bg-purple-950/60 text-purple-600 dark:text-purple-300 border border-purple-300 dark:border-purple-900 font-semibold">In The News</span>' : ''}
        <a href="https://nvd.nist.gov/vuln/detail/${item.cve_id}" target="_blank" class="ml-auto text-indigo-500 hover:underline">Inspect →</a>
      </div>
    </div>
  `).join('');
}

// -------------------------------------------------------------
// 6. RENDER VENDOR FOCUS
// -------------------------------------------------------------
function renderVendorPills() {
  const container = document.getElementById('vendor-pills');
  const vendors = ['All', ...new Set(vendorData.map(v => v.vendor))];

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
  const exploitOnly = document.getElementById('vendor-exploit-filter').value === 'exploited';

  let filtered = vendorData;
  if (selectedVendor !== 'All') {
    filtered = filtered.filter(v => v.vendor === selectedVendor);
  }
  if (exploitOnly) {
    filtered = filtered.filter(v => v.is_kev || v.has_poc || v.has_nuclei);
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-gray-400 text-sm">No vulnerabilities found for the selected filter criteria.</div>`;
    return;
  }

  container.innerHTML = filtered.map(item => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
      <div>
        <div class="flex items-start justify-between gap-2 mb-2">
          <div>
            <span class="text-sm font-bold text-indigo-600 dark:text-indigo-400">${item.cve_id}</span>
            <h3 class="text-xs font-semibold text-gray-800 dark:text-gray-200">${item.vendor} ${item.product !== 'Unknown' ? '— ' + item.product : ''}</h3>
          </div>
          ${item.is_kev ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-red-100 dark:bg-red-950 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-900">KEV</span>' : ''}
        </div>
        <div class="text-xs text-gray-600 dark:text-gray-400 mb-3 leading-relaxed">
          ${formatExpandableText(item.description, 160)}
        </div>
      </div>

      <div class="pt-2 border-t border-gray-100 dark:border-darkBorder/60 flex items-center justify-between text-[11px]">
        <div class="flex items-center gap-1.5">
          ${item.has_poc ? '<span class="text-amber-500 font-bold">PoC</span>' : ''}
          ${item.has_nuclei ? '<span class="text-blue-500 font-bold">Nuclei</span>' : ''}
          <span class="font-mono text-gray-400">EPSS ${(item.epss * 100).toFixed(1)}%</span>
        </div>
        <a href="https://nvd.nist.gov/vuln/detail/${item.cve_id}" target="_blank" class="text-indigo-500 hover:underline">Details →</a>
      </div>
    </div>
  `).join('');
}

document.getElementById('vendor-exploit-filter').addEventListener('change', renderVendorView);

// -------------------------------------------------------------
// 7. RENDER CURATED NEWS FEED
// -------------------------------------------------------------
function renderNews() {
  const container = document.getElementById('news-grid');
  if (newsData.length === 0) {
    container.innerHTML = `<div class="col-span-full py-12 text-center text-gray-400 text-sm">No curated news items loaded.</div>`;
    return;
  }

  container.innerHTML = newsData.map(article => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between text-[11px] text-gray-400 mb-2">
          <span class="font-semibold text-indigo-500">${article.source}</span>
          <span>${article.published || ''}</span>
        </div>
        <a href="${article.url}" target="_blank" class="text-sm font-bold text-gray-900 dark:text-gray-100 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors block mb-2 leading-snug">
          ${article.title}
        </a>
        <div class="text-xs text-gray-600 dark:text-gray-400 mb-4 leading-relaxed">
          ${formatExpandableText(article.snippet, 180)}
        </div>
      </div>

      <div class="pt-2 border-t border-gray-100 dark:border-darkBorder/60 flex flex-wrap gap-1">
        ${(article.matched_cves || []).map(cve => `
          <button onclick="quickSearch('${cve}')" class="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900 hover:bg-indigo-100">
            ${cve}
          </button>
        `).join('')}
        ${(article.matched_vendors || []).map(v => `
          <span class="text-[10px] px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase text-gray-600 dark:text-gray-300 border border-gray-200 dark:border-darkBorder">
            ${v}
          </span>
        `).join('')}
      </div>
    </div>
  `).join('');
}

// -------------------------------------------------------------
// INITIALIZATION
// -------------------------------------------------------------
initTheme();
loadData();