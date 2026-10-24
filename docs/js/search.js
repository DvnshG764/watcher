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
    searchView.classList.add('hidden');
    return;
  }
  executeSearch(query);
});

function clearSearch() {
  searchInput.value = '';
  searchView.classList.add('hidden');
}

function executeSearch(query) {
  searchView.classList.remove('hidden');
  const resultsHtml = [];

  // 1. Search CWEs
  Object.keys(cweMap).forEach(cweId => {
    const item = cweMap[cweId];
    if (cweId.toLowerCase().includes(query) || item.name.toLowerCase().includes(query) || (item.description && item.description.toLowerCase().includes(query))) {
      resultsHtml.push(`
        <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between gap-2 mb-1.5">
              <span class="text-xs font-bold text-indigo-500 uppercase">CWE Weakness</span>
              <span class="text-[10px] font-bold px-2 py-0.5 rounded bg-gray-100 dark:bg-darkBase border border-gray-300 dark:border-darkBorder">CWE</span>
            </div>
            <a href="https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html" target="_blank" rel="noopener noreferrer" class="text-base font-bold font-mono text-indigo-600 dark:text-indigo-400 hover:underline">
              ${cweId}: ${item.name}
            </a>
            <div class="text-xs font-medium text-gray-500 my-1">Severity: ${item.severity || 'UNKNOWN'}</div>
            <p class="text-xs text-gray-600 dark:text-gray-400 line-clamp-3 leading-relaxed mb-3">${item.description}</p>
          </div>
          <a href="https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html" target="_blank" rel="noopener noreferrer" class="text-xs text-indigo-500 hover:underline pt-2 border-t border-gray-100 dark:border-darkBorder/60">
            MITRE Definition →
          </a>
        </div>
      `);
    }
  });

  // 2. Search KEV (Standardized Cards)
  (trendingData.confirmed_in_wild || []).forEach(k => {
    const blob = `${k.cve_id} ${k.vendor} ${k.product} ${k.description}`.toLowerCase();
    if (blob.includes(query)) {
      resultsHtml.push(buildStandardThreatCard(k, 'radar_kev'));
    }
  });

  // 3. Search Exploit Radar (Standardized Cards)
  (trendingData.early_warning || []).forEach(w => {
    const blob = `${w.cve_id} ${w.vendor} ${w.product} ${w.description}`.toLowerCase();
    if (blob.includes(query)) {
      resultsHtml.push(buildStandardThreatCard(w, 'radar_early'));
    }
  });

  // 4. Search News Feed
  (newsData || []).forEach(n => {
    const blob = `${n.title} ${n.snippet} ${(n.matched_cves || []).join(' ')} ${(n.matched_vendors || []).join(' ')}`.toLowerCase();
    if (blob.includes(query)) {
      resultsHtml.push(`
        <div class="vuln-card p-4 rounded-xl border border-gray-200 dark:border-darkBorder bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between">
          <div>
            <div class="flex items-center justify-between text-[11px] text-gray-400 mb-2">
              <span class="font-semibold text-indigo-500">${n.source}</span>
              <span>${n.published || ''}</span>
            </div>
            <a href="${n.url}" target="_blank" rel="noopener noreferrer" class="text-sm font-bold text-gray-900 dark:text-gray-100 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors block mb-2 leading-snug">
              ${n.title}
            </a>
            <div class="text-xs text-gray-600 dark:text-gray-400 leading-relaxed mb-3">
              ${formatExpandableText(n.snippet, 180)}
            </div>
          </div>
        </div>
      `);
    }
  });

  // 5. Fallback for CVEs not present in active datasets
  const cveFormatMatch = query.match(/cve-\d{4}-\d{4,7}/i);
  if (cveFormatMatch && resultsHtml.length === 0) {
    const rawCve = cveFormatMatch[0].toUpperCase();
    resultsHtml.push(`
      <div class="vuln-card p-4 rounded-xl border border-indigo-300 dark:border-indigo-800 bg-white dark:bg-darkCard shadow-sm flex flex-col justify-between col-span-full max-w-lg">
        <div>
          <span class="text-xs font-bold text-indigo-500 uppercase tracking-wide">External NVD Lookup</span>
          <h4 class="text-base font-bold font-mono text-gray-900 dark:text-gray-100 my-1">${rawCve}</h4>
          <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">
            This CVE is not currently indexed in active Watcher threat feeds. You can query the National Vulnerability Database directly.
          </p>
        </div>
        <a href="https://nvd.nist.gov/vuln/detail/${rawCve}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center justify-center px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold transition-colors">
          Open ${rawCve} on NVD →
        </a>
      </div>
    `);
  }

  searchCount.textContent = `${resultsHtml.length} result${resultsHtml.length === 1 ? '' : 's'}`;

  if (resultsHtml.length === 0) {
    searchList.innerHTML = `
      <div class="col-span-full py-8 text-center text-sm text-gray-400">
        No matches found in active Watcher feeds. Use the <strong>CVE-YYYY-NNNNN</strong> box in the navbar for direct NVD lookups.
      </div>
    `;
    return;
  }

  searchList.innerHTML = resultsHtml.join('');
}