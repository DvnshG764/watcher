// =========================================================================
// GLOBAL WATCHER SEARCH (Sidebar Search 1)
// =========================================================================
const globalSearchInput = document.getElementById('global-search');
const clearSearchBtn = document.getElementById('clear-search-btn');
const searchView = document.getElementById('search-view');
const searchResultsGrid = document.getElementById('search-results-grid');
const searchCountBadge = document.getElementById('search-count');

if (globalSearchInput) {
  globalSearchInput.addEventListener('input', (e) => {
    const q = (e.target.value || '').trim().toLowerCase();
    if (q.length === 0) {
      clearSearch();
      return;
    }
    if (clearSearchBtn) clearSearchBtn.classList.remove('hidden');
    executeWatcherSearch(q);
  });
}

function clearSearch() {
  if (globalSearchInput) globalSearchInput.value = '';
  if (clearSearchBtn) clearSearchBtn.classList.add('hidden');
  if (searchView) searchView.classList.add('hidden');
  if (typeof switchTab === 'function') {
    switchTab(typeof activeTab !== 'undefined' ? activeTab : 'radar');
  }
}

function executeWatcherSearch(query) {
  ['radar', 'vendor', 'news'].forEach(t => {
    const el = document.getElementById(`view-${t}`);
    if (el) el.classList.add('hidden');
  });
  if (searchView) searchView.classList.remove('hidden');

  const cards = [];
  const seenCves = new Set();

  // 1. Search CWEs
  Object.keys(cweMap || {}).forEach(cweId => {
    const item = cweMap[cweId] || {};
    const blob = `${cweId} ${item.name || ''} ${item.description || ''}`.toLowerCase();
    if (blob.includes(query)) {
      cards.push(`
        <article class="neu-glass-card vendor-card-glow rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between gap-2 mb-1">
              <a href="https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html" target="_blank" rel="noopener noreferrer" class="text-lg font-extrabold font-mono text-indigo-600 dark:text-indigo-400 hover:underline">
                ${cweId}: ${item.name || ''}
              </a>
              <span class="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border border-indigo-500/30">${item.severity || 'CWE'}</span>
            </div>
            <p class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mt-2">${item.description || ''}</p>
          </div>
        </article>
      `);
    }
  });

  // 2. Search CISA KEV
  ((trendingData && trendingData.confirmed_in_wild) || []).forEach(k => {
    const blob = `${k.cve_id || ''} ${k.vendor || ''} ${k.product || ''} ${k.description || ''} ${k.vuln_name || ''}`.toLowerCase();
    if (blob.includes(query)) {
      seenCves.add(k.cve_id);
      cards.push(buildStandardThreatCard(k, 'radar_kev'));
    }
  });

  // 3. Search Exploit Radar (Early Warning)
  ((trendingData && trendingData.early_warning) || []).forEach(w => {
    const blob = `${w.cve_id || ''} ${w.vendor || ''} ${w.product || ''} ${w.description || ''}`.toLowerCase();
    if (blob.includes(query) && !seenCves.has(w.cve_id)) {
      seenCves.add(w.cve_id);
      cards.push(buildStandardThreatCard(w, 'radar_early'));
    }
  });

  // 4. Search Vendor Focus Advisories (Deduplicated against KEV & Radar)
  (vendorData || []).forEach(v => {
    const blob = `${v.cve_id || ''} ${v.vendor || ''} ${v.product || ''} ${v.description || ''}`.toLowerCase();
    if (blob.includes(query) && !seenCves.has(v.cve_id)) {
      seenCves.add(v.cve_id);
      cards.push(buildStandardThreatCard(v, 'vendor'));
    }
  });

  // 5. Search News Feed
  (newsData || []).forEach(n => {
    const blob = `${n.title || ''} ${n.source || ''} ${n.snippet || ''} ${(n.matched_cves || []).join(' ')} ${(n.matched_vendors || []).join(' ')}`.toLowerCase();
    if (blob.includes(query)) {
      cards.push(`
        <article class="neu-glass-card vendor-card-glow rounded-2xl p-5 flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-2">
              <span class="font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-wider">${n.source || ''}</span>
              <span>${n.published || ''}</span>
            </div>
            <a href="${n.url || '#'}" target="_blank" rel="noopener noreferrer" class="text-base font-bold text-slate-900 dark:text-white hover:text-indigo-600 dark:hover:text-indigo-400 block mb-2 leading-snug">
              ${n.title || ''}
            </a>
            <div class="text-xs text-slate-600 dark:text-slate-300 leading-relaxed mb-3">
              ${typeof formatExpandableText === 'function' ? formatExpandableText(n.snippet, 175) : (n.snippet || '')}
            </div>
          </div>
          <div class="pt-3 border-t border-slate-200/70 dark:border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px]">
            ${(n.matched_cves || []).map(cve => `
              <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener noreferrer" class="font-mono font-bold px-2.5 py-1 rounded-full bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border border-indigo-500/30 hover:underline">
                ${cve}
              </a>
            `).join('')}
            ${(n.matched_vendors || []).map(v => `
              <span class="px-2.5 py-1 rounded-full bg-slate-500/10 text-slate-600 dark:text-slate-300 border border-slate-300/50 dark:border-slate-700 font-medium">
                ${v}
              </span>
            `).join('')}
          </div>
        </article>
      `);
    }
  });

  if (searchCountBadge) {
    searchCountBadge.textContent = `${cards.length} result${cards.length === 1 ? '' : 's'}`;
  }

  if (cards.length === 0) {
    searchResultsGrid.innerHTML = `
      <div class="col-span-full neu-glass-card rounded-2xl p-12 text-center space-y-3">
        <div class="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center mx-auto text-indigo-400">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-4.35-4.35M17 11a6 6 0 11-12 0 6 6 0 0112 0z" />
          </svg>
        </div>
        <p class="text-sm font-bold text-slate-800 dark:text-slate-100">
          No Results Found across Watcher. If you want to search up a particular CVE, try the CVE Search
        </p>
        <p class="text-xs text-slate-500 dark:text-slate-400">
          Use the <span class="font-mono font-semibold text-indigo-500">CVE-[Year]-[ID]</span> box in the left sidebar to query NIST NVD directly.
        </p>
      </div>
    `;
    return;
  }

  searchResultsGrid.innerHTML = cards.join('');
}