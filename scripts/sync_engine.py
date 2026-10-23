import os
import re
import json
import logging
from datetime import datetime, timezone, timedelta
from dateutil import parser as date_parser
import requests
import feedparser
import shutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "docs", "data")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Watcher/1.0"
}
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def load_json(filepath, default):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading {filepath}: {e}")
    return default

def save_json(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logging.info(f"Saved {filepath}")

# -------------------------------------------------------------
# 1. FETCH CISA KEV
# -------------------------------------------------------------
def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    logging.info("Fetching CISA KEV catalog...")
    kev_map = {}
    try:
        res = requests.get(url, headers=HEADERS, timeout=15)
        if res.status_code == 200:
            for item in res.json().get("vulnerabilities", []):
                cve_id = item.get("cveID", "").strip().upper()
                if cve_id:
                    kev_map[cve_id] = {
                        "cve_id": cve_id,
                        "vendor": item.get("vendorProject", "Unknown"),
                        "product": item.get("product", "Unknown"),
                        "vuln_name": item.get("vulnerabilityName", ""),
                        "date_added": item.get("dateAdded", ""),
                        "description": item.get("shortDescription", ""),
                        "required_action": item.get("requiredAction", ""),
                        "due_date": item.get("dueDate", ""),
                        "ransomware_use": item.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": item.get("notes", "")
                    }
            logging.info(f"Loaded {len(kev_map)} CISA KEV items.")
    except Exception as e:
        logging.error(f"Failed to fetch CISA KEV: {e}")
    return kev_map

# -------------------------------------------------------------
# 2. FETCH PUBLIC EXPLOITS (PoC-in-GitHub & Nuclei)
# -------------------------------------------------------------
def fetch_poc_and_nuclei():
    logging.info("Fetching public exploit signals (PoC-in-GitHub & Nuclei)...")
    poc_cves = set()
    nuclei_cves = set()

    gh_headers = dict(HEADERS)
    gh_token = os.getenv("GITHUB_TOKEN")
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"

    current_year = datetime.now(timezone.utc).year
    for year in [current_year, current_year - 1]:
        try:
            url = f"https://api.github.com/repos/nomi-sec/PoC-in-GitHub/contents/{year}"
            res = requests.get(url, headers=gh_headers, timeout=15)
            if res.status_code == 200:
                for item in res.json():
                    matches = CVE_REGEX.findall(item.get("name", ""))
                    for m in matches:
                        poc_cves.add(m.upper())
        except Exception as e:
            logging.error(f"Error fetching PoC repo contents for {year}: {e}")

    try:
        url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
        res = requests.get(url, headers=gh_headers, timeout=15)
        if res.status_code == 200:
            for folder in res.json()[-3:]:
                if folder.get("type") == "dir":
                    y_res = requests.get(folder.get("url"), headers=gh_headers, timeout=15)
                    if y_res.status_code == 200:
                        for f in y_res.json():
                            matches = CVE_REGEX.findall(f.get("name", ""))
                            for m in matches:
                                nuclei_cves.add(m.upper())
    except Exception as e:
        logging.error(f"Error fetching Nuclei templates: {e}")

    logging.info(f"Identified {len(poc_cves)} PoCs and {len(nuclei_cves)} Nuclei templates.")
    return poc_cves, nuclei_cves

# -------------------------------------------------------------
# 3. FETCH EPSS PROBABILITIES
# -------------------------------------------------------------
def fetch_epss(cve_list):
    if not cve_list:
        return {}
    logging.info(f"Fetching EPSS scores for {len(cve_list)} candidate CVEs...")
    epss_map = {}
    chunk_size = 80
    cve_list = list(set(cve_list))

    for i in range(0, len(cve_list), chunk_size):
        chunk = cve_list[i:i + chunk_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            res = requests.get(url, headers=HEADERS, timeout=12)
            if res.status_code == 200:
                for entry in res.json().get("data", []):
                    cve_id = entry.get("cve", "").upper()
                    try:
                        epss_map[cve_id] = {
                            "epss": float(entry.get("epss", 0.0)),
                            "percentile": float(entry.get("percentile", 0.0))
                        }
                    except ValueError:
                        epss_map[cve_id] = {"epss": 0.0, "percentile": 0.0}
        except Exception as e:
            logging.error(f"Error fetching EPSS chunk: {e}")
    return epss_map

# -------------------------------------------------------------
# 4. FETCH AND NORMALIZE NEWS FEEDS (STRICT CHRONOLOGICAL SORT)
# -------------------------------------------------------------
def fetch_news(vendor_rules):
    feeds_config = load_json(os.path.join(CONFIG_DIR, "feeds.json"), [])
    logging.info(f"Fetching security news from {len(feeds_config)} sources...")
    articles = []

    for feed_info in feeds_config:
        source_name = feed_info.get("name", "Unknown Source")
        url = feed_info.get("url")
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            feed = feedparser.parse(resp.content)

            for entry in feed.entries[:25]:
                title = entry.get("title", "")
                link = entry.get("link", "")
                summary = entry.get("summary", "")
                pub_raw = entry.get("published", "") or entry.get("updated", "")

                # Parse date to Unix timestamp for precise multi-source sorting
                dt_obj = None
                try:
                    dt_obj = date_parser.parse(pub_raw) if pub_raw else datetime.now(timezone.utc)
                except Exception:
                    dt_obj = datetime.now(timezone.utc)

                text_corpus = f"{title} {summary}"
                matched_cves = [c.upper() for c in set(CVE_REGEX.findall(text_corpus))]

                matched_vendors = []
                for v_name, aliases in vendor_rules.items():
                    if any(re.search(r'\b' + re.escape(a) + r'\b', text_corpus, re.IGNORECASE) for a in aliases):
                        matched_vendors.append(v_name)

                clean_summary = re.sub(r'<[^>]+>', '', summary).strip()

                articles.append({
                    "title": title,
                    "url": link,
                    "source": source_name,
                    "published": dt_obj.strftime("%Y-%m-%d %H:%M UTC"),
                    "timestamp": dt_obj.timestamp(),
                    "snippet": clean_summary,
                    "matched_cves": matched_cves,
                    "matched_vendors": list(set(matched_vendors))
                })
        except Exception as e:
            logging.error(f"Failed parsing feed {source_name}: {e}")

    # Sort strictly by timestamp descending so sources interleave naturally
    articles = sorted(articles, key=lambda x: x.get("timestamp", 0), reverse=True)
    logging.info(f"Loaded {len(articles)} chronological news items.")
    return articles

# -------------------------------------------------------------
# 5. FETCH RECENT NVD DELTA
# -------------------------------------------------------------
def fetch_nvd_recent():
    logging.info("Querying NVD API 2.0 delta...")
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_date}&lastModEndDate={end_date}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY

    recent_nvd = {}
    try:
        res = requests.get(url, headers=nvd_headers, timeout=15)
        if res.status_code == 200:
            for item in res.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "").upper()
                if not cve_id:
                    continue

                cvss_score = None
                metrics = cve.get("metrics", {})
                for m_ver in ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30"]:
                    if m_ver in metrics and len(metrics[m_ver]) > 0:
                        cvss_score = metrics[m_ver][0].get("cvssData", {}).get("baseScore")
                        break

                desc_text = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc_text = d.get("value")
                        break

                recent_nvd[cve_id] = {
                    "cve_id": cve_id,
                    "cvss": cvss_score,
                    "description": desc_text,
                    "published": cve.get("published", "")
                }
    except Exception as e:
        logging.warning(f"NVD delta query bypassed: {e}")

    return recent_nvd

# -------------------------------------------------------------
# 6. ENRICH DESCRIPTIONS FROM MITRE CVELIST V5 (FAST SESSION)
# -------------------------------------------------------------
def enrich_cve_description(cve_id, session=None):
    """Fetches real description from CVEProject raw repo if NVD had no record"""
    try:
        parts = cve_id.split("-")
        if len(parts) == 3:
            year = parts[1]
            num = parts[2]
            prefix = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}/{cve_id}.json"
            
            req_func = session.get if session else requests.get
            r = req_func(raw_url, headers=HEADERS, timeout=4)
            if r.status_code == 200:
                data = r.json()
                containers = data.get("containers", {}).get("cna", {})
                descriptions = containers.get("descriptions", [])
                for d in descriptions:
                    if d.get("lang", "en").startswith("en"):
                        return d.get("value", "")
    except Exception:
        pass
    return ""

# -------------------------------------------------------------
# MAIN COMPILATION ENGINE
# -------------------------------------------------------------
def main():
    vendor_rules = load_json(os.path.join(CONFIG_DIR, "vendors.json"), {})
    
    cisa_kev = fetch_cisa_kev()
    poc_cves, nuclei_cves = fetch_poc_and_nuclei()
    news_articles = fetch_news(vendor_rules)
    nvd_delta = fetch_nvd_recent()

    # Aggregate candidate CVEs for EPSS scoring
    candidate_cves = set(list(cisa_kev.keys())[:150])
    candidate_cves.update(poc_cves)
    candidate_cves.update(nuclei_cves)
    for art in news_articles:
        candidate_cves.update(art.get("matched_cves", []))
    candidate_cves.update(list(nvd_delta.keys()))

    epss_data = fetch_epss(list(candidate_cves))

    # --- 1. TRENDING / EXPLOIT RADAR ---
    # Column 1: KEV
    confirmed_kev = []
    sorted_kev = sorted(cisa_kev.values(), key=lambda x: x.get("date_added", ""), reverse=True)
    for k in sorted_kev[:40]:
        cve_id = k["cve_id"]
        epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        confirmed_kev.append({
            **k,
            "epss": epss_info["epss"],
            "has_poc": cve_id in poc_cves,
            "has_nuclei": cve_id in nuclei_cves
        })

    # Column 2: Early Warning (Pre-KEV)
    early_candidates = []
    radar_candidates = candidate_cves - set(cisa_kev.keys())
    for cve_id in radar_candidates:
        has_poc = cve_id in poc_cves
        has_nuclei = cve_id in nuclei_cves
        epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        in_news = any(cve_id in art["matched_cves"] for art in news_articles)

        if has_poc or has_nuclei or in_news or epss_info["epss"] >= 0.15:
            nvd_info = nvd_delta.get(cve_id, {})
            early_candidates.append({
                "cve_id": cve_id,
                "cvss": nvd_info.get("cvss", None),
                "description": nvd_info.get("description", ""),
                "epss": epss_info["epss"],
                "epss_percentile": epss_info["percentile"],
                "has_poc": has_poc,
                "has_nuclei": has_nuclei,
                "in_news": in_news,
                "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d")
            })

    # CRITICAL: Sort and take TOP 40 FIRST before making any external calls
    early_candidates = sorted(
        early_candidates, 
        key=lambda x: (x["has_poc"] or x["has_nuclei"], x["epss"]), 
        reverse=True
    )[:40]

    # Enrich descriptions ONLY for the top 40 candidates using a shared session
    logging.info(f"Enriching descriptions for top {len(early_candidates)} early warning CVEs...")
    with requests.Session() as session:
        session.headers.update(HEADERS)
        for item in early_candidates:
            if not item["description"]:
                enriched = enrich_cve_description(item["cve_id"], session=session)
                if enriched:
                    item["description"] = enriched
                else:
                    item["description"] = f"Active exploit signal detected via {'PoC repository' if item['has_poc'] else 'Nuclei scanner'}. Exploit probability: {(item['epss']*100):.1f}%."

    early_warning = early_candidates

    save_json(os.path.join(DATA_DIR, "trending.json"), {
        "confirmed_in_wild": confirmed_kev,
        "early_warning": early_warning
    })

    # --- 2. VENDOR FOCUS ---
    vendor_feed = []
    all_vulns_pool = {k["cve_id"]: {**k, "is_kev": True} for k in sorted_kev}
    for cve_id, n in nvd_delta.items():
        if cve_id not in all_vulns_pool:
            all_vulns_pool[cve_id] = {
                "cve_id": cve_id,
                "vendor": "Unknown",
                "product": "Unknown",
                "description": n["description"],
                "date_added": n["published"][:10] if n.get("published") else "",
                "is_kev": False
            }

    for cve_id, item in all_vulns_pool.items():
        search_blob = f"{item.get('vendor','')} {item.get('product','')} {item.get('description','')}".lower()
        matched_vendor_key = None
        for v_name, aliases in vendor_rules.items():
            if any(a.lower() in search_blob for a in aliases):
                matched_vendor_key = v_name
                break

        if matched_vendor_key:
            epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
            vendor_feed.append({
                "cve_id": cve_id,
                "vendor": matched_vendor_key,
                "product": item.get("product", "Unknown"),
                "description": item.get("description", ""),
                "date": item.get("date_added", ""),
                "is_kev": item.get("is_kev", False),
                "has_poc": cve_id in poc_cves,
                "has_nuclei": cve_id in nuclei_cves,
                "epss": epss_info["epss"]
            })

    vendor_feed = sorted(vendor_feed, key=lambda x: x.get("date", ""), reverse=True)
    save_json(os.path.join(DATA_DIR, "vendors.json"), vendor_feed)

    # --- 3. CURATED NEWS FEED ---
    save_json(os.path.join(DATA_DIR, "news.json"), news_articles)

    # --- 4. SYNC METADATA ---
    save_json(os.path.join(DATA_DIR, "sync_meta.json"), {
        "last_sync": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": {
            "cisa_kev": len(cisa_kev),
            "early_warning": len(early_warning),
            "vendor_alerts": len(vendor_feed),
            "news_articles": len(news_articles)
        }
    })

    # Ensure cwe_definitions is always available inside docs/data/
    src_cwe = os.path.join(BASE_DIR, "data", "cwe_definitions.json")
    dst_cwe = os.path.join(DATA_DIR, "cwe_definitions.json")
    if os.path.exists(src_cwe):
        shutil.copyfile(src_cwe, dst_cwe)
    
    logging.info("Sync completed successfully.")

if __name__ == "__main__":
    main()