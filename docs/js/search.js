let cweMap = {};

// Load static CWE definitions with path fallback
async function loadCWE() {
  const paths = ['data/cwe_definitions.json', './data/cwe_definitions.json', '../data/cwe_definitions.json', 'docs/data/cwe_definitions.json'];
  for (const p of paths) {
    try {
      const res = await fetch(p);
      if (res.ok) {
        cweMap = await res.json();
        break;
      }
    } catch (e) {}
  }
}
loadCWE();

const searchInput = document.getElementById('global-search');
const searchView = document.getElementById('search-view');
const searchList = document.getElementById('search-results-list');
const searchCount = document.getElementById('search-count');

searchInput.addEventListener('input', (e) => {
  const query = e.target.value.trim().toLowerCase();
  if (query.length < 2) {
    // Only hide the dropdown view; DO NOT wipe searchInput.value
    searchView.classList.add('hidden');
    return;
  }
  executeSearch(query);
});

function quickSearch(term) {
  searchInput.value = term;
  executeSearch(term.toLowerCase());
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function clearSearch() {
  searchInput.value = '';
  searchView.classList.add('hidden');
}

function executeSearch(query) {
  searchView.classList.remove('hidden');
  const results = [];

  // 1. Search CWEs (IDs and definitions)
  Object.keys(cweMap).forEach(cweId => {
    const item = cweMap[cweId];
    if (cweId.toLowerCase().includes(query) || item.name.toLowerCase().includes(query) || (item.description && item.description.toLowerCase().includes(query))) {
      results.push({
        type: 'CWE Weakness',
        title: `${cweId}: ${item.name}`,
        subtitle: `Severity: ${item.severity || 'UNKNOWN'}`,
        desc: item.description,
        badge: 'CWE',
        link: `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`
      });
    }
  });

  // 2. Search KEV
  (trendingData.confirmed_in_wild || []).forEach(k => {
    const blob = `${k.cve_id} ${k.vendor} ${k.product} ${k.description}`.toLowerCase();
    if (blob.includes(query)) {
      results.push({
        type: 'Vulnerability (KEV)',
        title: k.cve_id,
        subtitle: `${k.vendor} / ${k.product}`,
        desc: k.description,
        badge: 'CISA KEV',
        link: `https://nvd.nist.gov/vuln/detail/${k.cve_id}`
      });
    }
  });

  // 3. Search Early Warning Radar
  (trendingData.early_warning || []).forEach(w => {
    const blob = `${w.cve_id} ${w.description}`.toLowerCase();
    if (blob.includes(query)) {
      results.push({
        type: 'Early Warning',
        title: w.cve_id,
        subtitle: `EPSS: ${(w.epss * 100).toFixed(1)}%`,
        desc: w.description,
        badge: 'Radar',
        link: `https://nvd.nist.gov/vuln/detail/${w.cve_id}`
      });
    }
  });

  // 4. Search News Feed
  (newsData || []).forEach(n => {
    const blob = `${n.title} ${n.snippet} ${(n.matched_cves || []).join(' ')} ${(n.matched_vendors || []).join(' ')}`.toLowerCase();
    if (blob.includes(query)) {
      results.push({
        type: 'News Mention',
        title: n.title,
        subtitle: n.source,
        desc: n.snippet,
        badge: 'News',
        link: n.url
      });
    }
  });

  searchCount.textContent = `${results.length} result${results.length === 1 ? '' : 's'}`;

  if (results.length === 0) {
    searchList.innerHTML = `
      <div class="col-span-full py-8 text-center text-sm text-gray-400">
        No direct matches found. Try searching a specific CVE ID, CWE-XX, or vendor name.
      </div>
    `;
    return;
  }

  searchList.innerHTML = results.slice(0, 18).map(res => `
    <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between gap-2 mb-1.5">
          <span class="text-xs font-bold text-indigo-500 uppercase">${res.type}</span>
          <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase border border-gray-300 dark:border-darkBorder">${res.badge}</span>
        </div>
        <h4 class="text-sm font-bold text-gray-900 dark:text-gray-100 mb-0.5">${res.title}</h4>
        <div class="text-xs font-medium text-gray-500 mb-2">${res.subtitle}</div>
        <p class="text-xs text-gray-600 dark:text-gray-400 line-clamp-3 leading-relaxed mb-3">${res.desc}</p>
      </div>
      <a href="${res.link}" target="_blank" class="text-xs text-indigo-500 hover:underline pt-2 border-t border-gray-100 dark:border-darkBorder/60">
        Inspect Details →
      </a>
    </div>
  `).join('');
}