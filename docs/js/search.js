const searchInput = document.getElementById('global-search');
const clearBtn = document.getElementById('clear-search-btn');

function clearSearch() {
  if (searchInput) searchInput.value = '';
  if (clearBtn) clearBtn.classList.add('hidden');
  document.getElementById('search-view')?.classList.add('hidden');
  switchTab(activeTab || 'radar');
}

function executeGlobalSearch(rawQuery) {
  const q = (rawQuery || '').trim().toLowerCase();
  const searchView = document.getElementById('search-view');
  const resultsGrid = document.getElementById('search-results-grid');
  const countBadge = document.getElementById('search-count');

  if (!q) {
    clearSearch();
    return;
  }

  clearBtn?.classList.remove('hidden');

  // Hide all 5 primary views while showing Global Search Results
  ['radar', 'vendor', 'cve-search', 'news', 'brief'].forEach(t => {
    document.getElementById(`view-${t}`)?.classList.add('hidden');
  });
  searchView?.classList.remove('hidden');

  const matchedCves = (masterCveData || []).filter(item => {
    const cid = (item.cve_id || '').toLowerCase();
    const desc = (item.description || '').toLowerCase();
    const ven = (item.vendors || []).join(' ').toLowerCase();
    const prod = (item.products || []).join(' ').toLowerCase();
    return cid.includes(q) || desc.includes(q) || ven.includes(q) || prod.includes(q);
  }).slice(0, 60);

  if (countBadge) {
    countBadge.textContent = `${matchedCves.length} result${matchedCves.length === 1 ? '' : 's'}`;
  }

  if (matchedCves.length === 0) {
    resultsGrid.innerHTML = `
      <div class="col-span-full neu-glass-card rounded-2xl p-10 text-center text-sm text-slate-400">
        No vulnerabilities in the centralized store matched "<strong class="text-slate-700 dark:text-slate-200">${stripAndEscapeHtml(rawQuery)}</strong>".
      </div>
    `;
    return;
  }

  resultsGrid.innerHTML = matchedCves
    .map(item => buildStandardThreatCard(item, item.is_kev ? 'radar_kev' : 'vendor'))
    .join('');
}

searchInput?.addEventListener('input', (e) => {
  executeGlobalSearch(e.target.value);
});