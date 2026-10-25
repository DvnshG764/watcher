import os
import re
import time
import json
import logging
import shutil
from datetime import datetime, timezone, timedelta
from dateutil import parser as date_parser
import requests
import feedparser

IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now_str():
    return datetime.now(IST).strftime("%I:%M %p, %d-%m-%Y (IST)")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "docs", "data")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Watcher/2.0"
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
# HELPER: STRICT CVSS EXTRACTION (v3.1 -> v3.0 -> v4.0 -> v2.0)
# -------------------------------------------------------------
def extract_nvd_cvss(cve_obj):
    """
    Extracts CVSS score from NVD API 2.0 'cve' dictionary.
    Strictly prioritizes v3.1 -> v3.0 -> v4.0 -> v2.0.
    Prefers NVD 'Primary' assessment over 'Secondary' within each version tier.
    """
    metrics = cve_obj.get("metrics", {})
    if not metrics:
        return None

    for m_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
        m_list = metrics.get(m_ver)
        if not m_list or not isinstance(m_list, list):
            continue

        # Sort so "Primary" (NIST NVD) comes before "Secondary" (CNA/ADP)
        sorted_list = sorted(m_list, key=lambda x: 0 if x.get("type") == "Primary" else 1)
        for entry in sorted_list:
            score = entry.get("cvssData", {}).get("baseScore")
            if score is not None:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    continue
    return None

def extract_cvelist_cvss(containers):
    """
    Extracts CVSS from CVE5 containers (both 'cna' and 'adp' CISA Vulnrichment).
    Pass 1: Search ALL containers for v3.1 or v3.0 first.
    Pass 2: Fallback to v4.0 or v2.0 only if v3.x is completely absent.
    """
    if not containers or not isinstance(containers, dict):
        return None

    all_metric_blocks = []
    cna = containers.get("cna", {})
    if isinstance(cna, dict) and isinstance(cna.get("metrics"), list):
        all_metric_blocks.extend(cna.get("metrics"))

    adp_list = containers.get("adp", [])
    if isinstance(adp_list, list):
        for adp in adp_list:
            if isinstance(adp, dict) and isinstance(adp.get("metrics"), list):
                all_metric_blocks.extend(adp.get("metrics"))

    # Priority Tier 1: CVSS v3.1 & v3.0
    # Priority Tier 2: CVSS v4.0 & v2.0 (Fallback only if v3.x is absent)
    for tier_keys in [["cvssV3_1", "cvssV3_0"], ["cvssV4_0", "cvssV2_0"]]:
        for key in tier_keys:
            for metric in all_metric_blocks:
                if isinstance(metric, dict) and key in metric and isinstance(metric[key], dict):
                    score = metric[key].get("baseScore")
                    if score is not None:
                        try:
                            return float(score)
                        except (ValueError, TypeError):
                            continue
    return None

# -------------------------------------------------------------
# 0. LOAD EXISTING LOCAL CACHE (AUTO-HEALS MISSING SCORES)
# -------------------------------------------------------------
def load_existing_cve_cache():
    """
    Loads previously saved CVEs from docs/data/ so already-resolved CVSS scores
    and vendor/product names are retained without redundant API hits.
    """
    cache = {}
    trending_prev = load_json(os.path.join(DATA_DIR, "trending.json"), {})
    vendors_prev = load_json(os.path.join(DATA_DIR, "vendors.json"), [])

    pool = []
    if isinstance(trending_prev, dict):
        pool.extend(trending_prev.get("confirmed_in_wild", []))
        pool.extend(trending_prev.get("early_warning", []))
    if isinstance(vendors_prev, list):
        pool.extend(vendors_prev)

    for item in pool:
        cid = item.get("cve_id")
        if not cid:
            continue
        existing = cache.get(cid, {})
        cache[cid] = {
            "cvss": item.get("cvss") if item.get("cvss") is not None else existing.get("cvss"),
            "vendor": item.get("vendor") if item.get("vendor") not in [None, "", "Unknown"] else existing.get("vendor", "Unknown"),
            "product": item.get("product") if item.get("product") not in [None, "", "Unknown"] else existing.get("product", "Unknown"),
            "description": item.get("description") if item.get("description") else existing.get("description", "")
        }
    return cache

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
# 4. FETCH AND NORMALIZE NEWS FEEDS
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

                dt_obj = None
                try:
                    dt_obj = date_parser.parse(pub_raw) if pub_raw else datetime.now(timezone.utc)
                    if dt_obj.tzinfo is None:
                        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                except Exception:
                    dt_obj = datetime.now(timezone.utc)

                text_corpus = f"{title} {summary}"
                matched_cves = [c.upper() for c in set(CVE_REGEX.findall(text_corpus))]

                matched_vendors = []
                for v_name, aliases in vendor_rules.items():
                    if any(re.search(r'\b' + re.escape(a) + r'\b', text_corpus, re.IGNORECASE) for a in aliases):
                        matched_vendors.append(v_name)

                clean_summary = re.sub(r'<[^>]+>', '', summary).strip()
                dt_ist = dt_obj.astimezone(IST)

                articles.append({
                    "title": title,
                    "url": link,
                    "source": source_name,
                    "published": dt_ist.strftime("%I:%M %p, %d-%m-%Y (IST)"),
                    "timestamp": dt_obj.timestamp(),
                    "snippet": clean_summary,
                    "matched_cves": matched_cves,
                    "matched_vendors": list(set(matched_vendors))
                })
        except Exception as e:
            logging.error(f"Failed parsing feed {source_name}: {e}")

    articles = sorted(articles, key=lambda x: x.get("timestamp", 0), reverse=True)
    logging.info(f"Loaded {len(articles)} chronological news items.")
    return articles

# -------------------------------------------------------------
# 5. FETCH RECENT NVD DELTA (PRIORITIZING CVSS v3.1 / v3.0)
# -------------------------------------------------------------
def fetch_nvd_recent():
    logging.info("Querying NVD API 2.0 delta...")
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_date}&lastModEndDate={end_date}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY

    recent_nvd = {}
    try:
        res = requests.get(url, headers=nvd_headers, timeout=20)
        if res.status_code == 200:
            for item in res.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "").upper()
                if not cve_id:
                    continue

                cvss_score = extract_nvd_cvss(cve)

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

def fetch_nvd_single_cve(cve_id, session=None):
    """
    Fallback direct query to NVD API 2.0 for a specific CVE when cvelistV5
    does not yet contain a CVSS score.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY

    req_func = session.get if session else requests.get
    try:
        res = req_func(url, headers=nvd_headers, timeout=8)
        if res.status_code == 200:
            vulns = res.json().get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                score = extract_nvd_cvss(cve)
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                return score, desc
        elif res.status_code in [403, 429]:
            time.sleep(1.5)
    except Exception:
        pass
    return None, ""

# -------------------------------------------------------------
# 6. ENRICH DESCRIPTIONS, CVSS (v3 PREFERRED), VENDOR/PRODUCT
# -------------------------------------------------------------
def enrich_cve_details(cve_id, session=None, local_cache=None, allow_nvd_fallback=True):
    cached = (local_cache or {}).get(cve_id, {})
    desc = cached.get("description", "")
    cvss = cached.get("cvss", None)
    vendor = cached.get("vendor", "Unknown")
    product = cached.get("product", "Unknown")

    # If we already have all fields cached from a previous run, return immediately
    if cvss is not None and desc and vendor != "Unknown" and product != "Unknown":
        return desc, cvss, vendor, product

    try:
        parts = cve_id.split("-")
        if len(parts) == 3:
            year = parts[1]
            num = parts[2]
            prefix = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}/{cve_id}.json"
            
            req_func = session.get if session else requests.get
            r = req_func(raw_url, headers=HEADERS, timeout=5)
            if r.status_code == 200:
                data = r.json()
                containers = data.get("containers", {})
                cna = containers.get("cna", {})
                
                # Extract Description
                if not desc:
                    for d in cna.get("descriptions", []):
                        if d.get("lang", "en").startswith("en"):
                            desc = d.get("value", "")
                            break

                # Extract Vendor and Product from CNA or ADP
                affected_list = list(cna.get("affected", []))
                for adp in containers.get("adp", []):
                    if isinstance(adp, dict) and isinstance(adp.get("affected"), list):
                        affected_list.extend(adp.get("affected"))

                for aff in affected_list:
                    if not isinstance(aff, dict):
                        continue
                    vendor_val = aff.get("vendor", "")
                    product_val = aff.get("product", "")
                    if vendor == "Unknown" and vendor_val and vendor_val.lower() not in ["n/a", "unknown"]:
                        vendor = vendor_val
                    if product == "Unknown" and product_val and product_val.lower() not in ["n/a", "unknown"]:
                        product = product_val

                # Extract CVSS across CNA + ADP (v3.1/v3.0 preferred over v4.0)
                if cvss is None:
                    cvss = extract_cvelist_cvss(containers)
    except Exception:
        pass

    # Direct NVD API fallback if CVSS is still None
    if cvss is None and allow_nvd_fallback:
        nvd_score, nvd_desc = fetch_nvd_single_cve(cve_id, session=session)
        if nvd_score is not None:
            cvss = nvd_score
        if not desc and nvd_desc:
            desc = nvd_desc

    return desc, cvss, vendor, product

# -------------------------------------------------------------
# MAIN COMPILATION ENGINE
# -------------------------------------------------------------
def main():
    vendor_rules = load_json(os.path.join(CONFIG_DIR, "vendors.json"), {})
    local_cache = load_existing_cve_cache()
    
    cisa_kev = fetch_cisa_kev()
    poc_cves, nuclei_cves = fetch_poc_and_nuclei()
    news_articles = fetch_news(vendor_rules)
    nvd_delta = fetch_nvd_recent()

cisa_kev = fetch_cisa_kev()
    poc_cves, nuclei_cves = fetch_poc_and_nuclei()
    news_articles = fetch_news(vendor_rules)
    nvd_delta = fetch_nvd_recent()

    # Override cached CVSS scores with fresh NVD modifications from the last 5 days
    for cid, nvd_info in nvd_delta.items():
        if nvd_info.get("cvss") is not None:
            if cid not in local_cache:
                local_cache[cid] = {}
            local_cache[cid]["cvss"] = nvd_info["cvss"]
    
    # Aggregate candidate CVEs for EPSS scoring
    candidate_cves = set(list(cisa_kev.keys())[:150])
    candidate_cves.update(poc_cves)
    candidate_cves.update(nuclei_cves)
    for art in news_articles:
        candidate_cves.update(art.get("matched_cves", []))
    candidate_cves.update(list(nvd_delta.keys()))

    epss_data = fetch_epss(list(candidate_cves))

    with requests.Session() as session:
        session.headers.update(HEADERS)

        # --- 1. TRENDING: KEV (Confirmed in the Wild) ---
        confirmed_kev = []
        sorted_kev = sorted(cisa_kev.values(), key=lambda x: x.get("date_added", ""), reverse=True)
        for k in sorted_kev[:40]:
            cve_id = k["cve_id"]
            epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
            
            cvss_score = nvd_delta.get(cve_id, {}).get("cvss")
            if cvss_score is None:
                _, cvss_score, _, _ = enrich_cve_details(
                    cve_id, session=session, local_cache=local_cache, allow_nvd_fallback=True
                )

            confirmed_kev.append({
                **k,
                "cvss": cvss_score,
                "epss": epss_info["epss"],
                "has_poc": cve_id in poc_cves,
                "has_nuclei": cve_id in nuclei_cves
            })
            # Update local_cache so Vendor Focus can reuse this score immediately
            local_cache[cve_id] = {
                "cvss": cvss_score,
                "vendor": k.get("vendor", "Unknown"),
                "product": k.get("product", "Unknown"),
                "description": k.get("description", "")
            }

        # --- 2. TRENDING: Exploit Radar (Pre-KEV) ---
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
                    "vendor": "Unknown",
                    "product": "Unknown",
                    "cvss": nvd_info.get("cvss", None),
                    "description": nvd_info.get("description", ""),
                    "epss": epss_info["epss"],
                    "epss_percentile": epss_info["percentile"],
                    "has_poc": has_poc,
                    "has_nuclei": has_nuclei,
                    "in_news": in_news,
                    "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d")
                })

        early_candidates = sorted(
            early_candidates, 
            key=lambda x: (x["has_poc"] or x["has_nuclei"], x["epss"]), 
            reverse=True
        )[:40]

        logging.info(f"Enriching CVSS, vendor, and descriptions for top {len(early_candidates)} Exploit Radar CVEs...")
        for item in early_candidates:
            cid = item["cve_id"]
            enriched_desc, enriched_cvss, enriched_vendor, enriched_product = enrich_cve_details(
                cid, session=session, local_cache=local_cache, allow_nvd_fallback=True
            )
            if not item["description"]:
                item["description"] = enriched_desc if enriched_desc else f"Active exploit signal detected via {'PoC repository' if item['has_poc'] else 'Nuclei scanner'}."
            if item["cvss"] is None:
                item["cvss"] = enriched_cvss
            if enriched_vendor != "Unknown":
                item["vendor"] = enriched_vendor
            if enriched_product != "Unknown":
                item["product"] = enriched_product

            local_cache[cid] = {
                "cvss": item["cvss"],
                "vendor": item["vendor"],
                "product": item["product"],
                "description": item["description"]
            }

        early_warning = early_candidates

        # --- 3. VENDOR FOCUS ---
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
                    "is_kev": False,
                    "cvss": n.get("cvss")
                }

        # Group per vendor (up to 40 newest per configured vendor) so no vendor tab is starved
        vendor_counts = {v: 0 for v in vendor_rules.keys()}
        sorted_pool = sorted(all_vulns_pool.values(), key=lambda x: x.get("date_added", ""), reverse=True)

        for item in sorted_pool:
            cve_id = item["cve_id"]
            search_blob = f"{item.get('vendor','')} {item.get('product','')} {item.get('description','')}".lower()
            matched_vendor_key = None
            for v_name, aliases in vendor_rules.items():
                if any(a.lower() in search_blob for a in aliases):
                    matched_vendor_key = v_name
                    break

            if matched_vendor_key and vendor_counts.get(matched_vendor_key, 0) < 35:
                vendor_counts[matched_vendor_key] = vendor_counts.get(matched_vendor_key, 0) + 1
                epss_info = epss_data.get(cve_id, {"epss": 0.0, "percentile": 0.0})
                v_cvss = item.get("cvss")
                if v_cvss is None and cve_id in local_cache:
                    v_cvss = local_cache[cve_id].get("cvss")

                vendor_feed.append({
                    "cve_id": cve_id,
                    "vendor": matched_vendor_key,
                    "product": item.get("product", "Unknown"),
                    "description": item.get("description", ""),
                    "date": item.get("date_added", ""),
                    "is_kev": item.get("is_kev", False),
                    "has_poc": cve_id in poc_cves,
                    "has_nuclei": cve_id in nuclei_cves,
                    "epss": epss_info["epss"],
                    "cvss": v_cvss
                })

        vendor_feed = sorted(vendor_feed, key=lambda x: x.get("date", ""), reverse=True)

        logging.info(f"Enriching {len(vendor_feed)} Vendor Focus items...")
        for idx, v_item in enumerate(vendor_feed):
            if v_item["cvss"] is None or v_item["product"] == "Unknown":
                # Allow NVD single-CVE fallback for the top 60 uncached items to respect rate limits
                _, v_cvss, _, v_product = enrich_cve_details(
                    v_item["cve_id"],
                    session=session,
                    local_cache=local_cache,
                    allow_nvd_fallback=(idx < 60)
                )
                if v_item["cvss"] is None:
                    v_item["cvss"] = v_cvss
                if v_item["product"] == "Unknown" and v_product != "Unknown":
                    v_item["product"] = v_product

    # Save output datasets
    save_json(os.path.join(DATA_DIR, "trending.json"), {
        "confirmed_in_wild": confirmed_kev,
        "early_warning": early_warning
    })
    save_json(os.path.join(DATA_DIR, "vendors.json"), vendor_feed)
    save_json(os.path.join(DATA_DIR, "news.json"), news_articles)
    save_json(os.path.join(DATA_DIR, "sync_meta.json"), {
        "last_sync": get_ist_now_str(),
        "counts": {
            "cisa_kev": len(cisa_kev),
            "early_warning": len(early_warning),
            "vendor_alerts": len(vendor_feed),
            "news_articles": len(news_articles)
        }
    })

    # Ensure configs are mirrored to docs/data/ for dynamic frontend filters
    for cfg in ["cwe_definitions.json"]:
        src = os.path.join(BASE_DIR, "data", cfg)
        dst = os.path.join(DATA_DIR, cfg)
        if os.path.exists(src):
            shutil.copyfile(src, dst)

    for cfg in ["vendors.json", "feeds.json"]:
        src = os.path.join(CONFIG_DIR, cfg)
        dst = os.path.join(DATA_DIR, f"config_{cfg}")
        if os.path.exists(src):
            shutil.copyfile(src, dst)

    logging.info("Sync completed successfully.")

if __name__ == "__main__":
    main()
