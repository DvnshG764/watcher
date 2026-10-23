import os
import re
import json
import logging
from datetime import datetime, timezone, timedelta
import requests
import feedparser

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "data")

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
            catalog = res.json()
            for item in catalog.get("vulnerabilities", []):
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
# 2. FETCH PUBLIC EXPLOITS (nomi-sec PoC-in-GitHub & Nuclei)
# -------------------------------------------------------------
def fetch_poc_and_nuclei():
    logging.info("Fetching public exploit signals (PoC-in-GitHub & Nuclei)...")
    poc_cves = set()
    nuclei_cves = set()

    # Query recent PoC repos updated on GitHub
    try:
        github_headers = dict(HEADERS)
        gh_token = os.getenv("GITHUB_TOKEN")
        if gh_token:
            github_headers["Authorization"] = f"token {gh_token}"

        # Fetch recent commits from nomi-sec/PoC-in-GitHub
        poc_api_url = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits?per_page=100"
        res = requests.get(poc_api_url, headers=github_headers, timeout=15)
        if res.status_code == 200:
            commits = res.json()
            for c in commits:
                msg = c.get("commit", {}).get("message", "")
                matches = CVE_REGEX.findall(msg)
                for m in matches:
                    poc_cves.add(m.upper())
            logging.info(f"Found {len(poc_cves)} CVEs with recent PoC repos.")
    except Exception as e:
        logging.error(f"Error fetching PoC repository signals: {e}")

    # Fetch recently merged Nuclei CVE templates
    try:
        nuclei_api = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
        res = requests.get(nuclei_api, headers=github_headers, timeout=15)
        if res.status_code == 200:
            dirs = res.json()
            # Inspect the newest year folders (e.g. 2024, 2025, 2026)
            for folder in dirs[-3:]:
                if folder.get("type") == "dir":
                    year_url = folder.get("url")
                    y_res = requests.get(year_url, headers=github_headers, timeout=15)
                    if y_res.status_code == 200:
                        for f in y_res.json():
                            matches = CVE_REGEX.findall(f.get("name", ""))
                            for m in matches:
                                nuclei_cves.add(m.upper())
            logging.info(f"Found {len(nuclei_cves)} CVEs with active Nuclei templates.")
    except Exception as e:
        logging.error(f"Error fetching Nuclei templates: {e}")

    return poc_cves, nuclei_cves

# -------------------------------------------------------------
# 3. FETCH EPSS PROBABILITIES (FIRST.org)
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
        cve_param = ",".join(chunk)
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
        try:
            res = requests.get(url, headers=HEADERS, timeout=12)
            if res.status_code == 200:
                data = res.json().get("data", [])
                for entry in data:
                    cve_id = entry.get("cve", "").upper()
                    try:
                        epss_score = float(entry.get("epss", 0.0))
                        percentile = float(entry.get("percentile", 0.0))
                    except ValueError:
                        epss_score, percentile = 0.0, 0.0
                    epss_map[cve_id] = {
                        "epss": epss_score,
                        "percentile": percentile
                    }
        except Exception as e:
            logging.error(f"Error fetching EPSS chunk: {e}")
    return epss_map

# -------------------------------------------------------------
# 4. FETCH AND PARSE OSINT RSS NEWS FEEDS
# -------------------------------------------------------------
def fetch_news(vendor_rules):
    feeds_config = load_json(os.path.join(CONFIG_DIR, "feeds.json"), [])
    logging.info(f"Fetching security news from {len(feeds_config)} sources...")
    articles = []

    for feed_info in feeds_config:
        source_name = feed_info.get("name", "Unknown Source")
        url = feed_info.get("url")
        try:
            # Using requests session with User-Agent to avoid Cloudflare 403 on BleepingComputer
            resp = requests.get(url, headers=HEADERS, timeout=15)
            feed = feedparser.parse(resp.content)

            for entry in feed.entries[:20]:
                title = entry.get("title", "")
                link = entry.get("link", "")
                summary = entry.get("summary", "")
                pub_date = entry.get("published", "") or entry.get("updated", "")

                text_corpus = f"{title} {summary}"
                matched_cves = list(set(CVE_REGEX.findall(text_corpus)))
                matched_cves = [c.upper() for c in matched_cves]

                matched_vendors = []
                for vendor_name, aliases in vendor_rules.items():
                    for alias in aliases:
                        if re.search(r'\b' + re.escape(alias) + r'\b', text_corpus, re.IGNORECASE):
                            matched_vendors.append(vendor_name)
                            break

                # Clean summary text to keep card snippet short
                clean_summary = re.sub(r'<[^>]+>', '', summary).strip()
                if len(clean_summary) > 240:
                    clean_summary = clean_summary[:237] + "..."

                articles.append({
                    "title": title,
                    "url": link,
                    "source": source_name,
                    "published": pub_date,
                    "snippet": clean_summary,
                    "matched_cves": matched_cves,
                    "matched_vendors": list(set(matched_vendors))
                })
        except Exception as e:
            logging.error(f"Failed parsing feed {source_name} ({url}): {e}")

    # Sort articles newest first
    logging.info(f"Parsed {len(articles)} total articles.")
    return articles

# -------------------------------------------------------------
# 5. FETCH RECENT NVD DELTA (LAST 48 HOURS)
# -------------------------------------------------------------
def fetch_nvd_recent():
    logging.info("Querying NVD API 2.0 delta...")
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_date}&lastModEndDate={end_date}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY

    recent_nvd = {}
    try:
        res = requests.get(url, headers=nvd_headers, timeout=25)
        if res.status_code == 200:
            items = res.json().get("vulnerabilities", [])
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "").upper()
                if not cve_id:
                    continue

                # Extract CVSS
                cvss_score = None
                metrics = cve.get("metrics", {})
                for metric_ver in ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_ver in metrics and len(metrics[metric_ver]) > 0:
                        cvss_data = metrics[metric_ver][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        break

                # Extract description
                descriptions = cve.get("descriptions", [])
                desc_text = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value")
                        break

                recent_nvd[cve_id] = {
                    "cve_id": cve_id,
                    "cvss": cvss_score,
                    "description": desc_text,
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", "")
                }
            logging.info(f"Retrieved {len(recent_nvd)} recently modified CVEs from NVD.")
    except Exception as e:
        logging.error(f"Error querying NVD API delta: {e}")
    return recent_nvd

# -------------------------------------------------------------
# MAIN COMPILATION ENGINE
# -------------------------------------------------------------
def main():
    vendor_rules = load_json(os.path.join(CONFIG_DIR, "vendors.json"), {})
    
    # 1. Fetch feeds
    cisa_kev = fetch_cisa_kev()
    poc_cves, nuclei_cves = fetch_poc_and_nuclei()
    news_articles = fetch_news(vendor_rules)
    nvd_delta = fetch_nvd_recent()

    # Collect all candidate CVEs to score with EPSS
    candidate_cves = set(list(cisa_kev.keys())[:150]) # latest KEVs
    candidate_cves.update(poc_cves)
    candidate_cves.update(nuclei_cves)
    for art in news_articles:
        candidate_cves.update(art.get("matched_cves", []))
    candidate_cves.update(list(nvd_delta.keys()))

    epss_data = fetch_epss(list(candidate_cves))

    # -------------------------------------------------------------
    # BUILD DATASET 1: TRENDING (Exploit Radar)
    # -------------------------------------------------------------
    # Column 1: Confirmed in the Wild (Latest 40 CISA KEVs)
    confirmed_kev = []
    # Sort KEV entries by dateAdded descending
    sorted_kev = sorted(cisa_kev.values(), key=lambda x: x.get("date_added", ""), reverse=True)
    for k in sorted_kev[:40]:
        cve_id = k["cve_id"]
        epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        confirmed_kev.append({
            **k,
            "epss": epss_info["epss"],
            "epss_percentile": epss_info["percentile"],
            "has_poc": cve_id in poc_cves,
            "has_nuclei": cve_id in nuclei_cves
        })

    # Column 2: Early Warning Radar (Pre-KEV: High EPSS, PoC, or Nuclei, but NOT in KEV)
    early_warning = []
    radar_candidates = candidate_cves - set(cisa_kev.keys())
    for cve_id in radar_candidates:
        has_poc = cve_id in poc_cves
        has_nuclei = cve_id in nuclei_cves
        epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
        in_news = any(cve_id in art["matched_cves"] for art in news_articles)

        # Early Warning threshold: Has PoC, Has Nuclei, In News, or EPSS > 15%
        if has_poc or has_nuclei or in_news or epss_info["epss"] >= 0.15:
            nvd_info = nvd_delta.get(cve_id, {})
            early_warning.append({
                "cve_id": cve_id,
                "cvss": nvd_info.get("cvss", None),
                "description": nvd_info.get("description", "Vulnerability detected in active OSINT monitoring."),
                "epss": epss_info["epss"],
                "epss_percentile": epss_info["percentile"],
                "has_poc": has_poc,
                "has_nuclei": has_nuclei,
                "in_news": in_news,
                "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d")
            })

    # Sort Early Warning by EPSS descending
    early_warning = sorted(early_warning, key=lambda x: (x["has_poc"] or x["has_nuclei"], x["epss"]), reverse=True)[:50]

    trending_data = {
        "confirmed_in_wild": confirmed_kev,
        "early_warning": early_warning
    }
    save_json(os.path.join(DATA_DIR, "trending.json"), trending_data)

    # -------------------------------------------------------------
    # BUILD DATASET 2: VENDOR FOCUS
    # -------------------------------------------------------------
    vendor_feed = []
    # Match KEV and NVD delta against your 10-15 vendors
    all_vulns_pool = {}
    for k in sorted_kev:
        all_vulns_pool[k["cve_id"]] = {
            "cve_id": k["cve_id"],
            "vendor": k["vendor"],
            "product": k["product"],
            "description": k["description"],
            "date": k["date_added"],
            "is_kev": True
        }
    for cve_id, n in nvd_delta.items():
        if cve_id not in all_vulns_pool:
            all_vulns_pool[cve_id] = {
                "cve_id": cve_id,
                "vendor": "Unknown",
                "product": "Unknown",
                "description": n["description"],
                "date": n["published"][:10] if n.get("published") else "",
                "is_kev": False
            }

    for cve_id, item in all_vulns_pool.items():
        search_blob = f"{item['vendor']} {item['product']} {item['description']}".lower()
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
                "product": item["product"],
                "description": item["description"],
                "date": item["date"],
                "is_kev": item["is_kev"],
                "has_poc": cve_id in poc_cves,
                "has_nuclei": cve_id in nuclei_cves,
                "epss": epss_info["epss"]
            })

    # Sort newest date first
    vendor_feed = sorted(vendor_feed, key=lambda x: x.get("date", ""), reverse=True)
    save_json(os.path.join(DATA_DIR, "vendors.json"), vendor_feed)

    # -------------------------------------------------------------
    # BUILD DATASET 3: NEWS FEED
    # -------------------------------------------------------------
    save_json(os.path.join(DATA_DIR, "news.json"), news_articles)

    # -------------------------------------------------------------
    # BUILD DATASET 4: SYNC METADATA
    # -------------------------------------------------------------
    meta = {
        "last_sync": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": {
            "cisa_kev": len(cisa_kev),
            "early_warning": len(early_warning),
            "vendor_alerts": len(vendor_feed),
            "news_articles": len(news_articles)
        }
    }
    save_json(os.path.join(DATA_DIR, "sync_meta.json"), meta)
    logging.info("Sync completed successfully.")

if __name__ == "__main__":
    main()