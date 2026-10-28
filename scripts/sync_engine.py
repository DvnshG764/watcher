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
from bs4 import BeautifulSoup
import re

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

#Fetch vendor RSS and Web Scraper
def fetch_vendor_advisories():
    """Fetches advisories from Cisco, Fortinet, Palo Alto (RSS) and Check Point (Web)."""
    logging.info("Fetching Vendor RSS and Web Advisories...")
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    vendor_data = {}

    rss_feeds = {
        "Cisco": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "Fortinet": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "Palo Alto": "https://security.paloaltonetworks.com/rss.xml"
    }

    # 1. Parse RSS Feeds
    for vendor, url in rss_feeds.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                desc = entry.get("description", entry.get("title", ""))
                date_pub = entry.get("published", entry.get("updated", ""))
                # Format date to YYYY-MM-DD
                try:
                    if entry.get("published_parsed"):
                        date_pub = time.strftime("%Y-%m-%d", entry.published_parsed)
                except:
                    pass
                
                # Extract all CVEs in this entry
                text_blob = f"{entry.get('title', '')} {desc}"
                found_cves = set(c.upper() for c in cve_pattern.findall(text_blob))
                
                for cve in found_cves:
                    if cve not in vendor_data:
                        vendor_data[cve] = {"vendors": set(), "description": desc, "date_added": date_pub}
                    vendor_data[cve]["vendors"].add(vendor)
                    # If this description is longer/better, replace it
                    if len(desc) > len(vendor_data[cve]["description"]):
                        vendor_data[cve]["description"] = desc
        except Exception as e:
            logging.error(f"Failed to fetch {vendor} RSS: {e}")

    # 2. Scrape Check Point (Web HTML)
    try:
        r = requests.get("https://advisories.checkpoint.com/advisories/", headers=HEADERS, timeout=10)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            # Extract text from main containers to avoid header/footer junk
            main_content = soup.get_text(separator=" ")
            found_cves = set(c.upper() for c in cve_pattern.findall(main_content))
            
            for cve in found_cves:
                if cve not in vendor_data:
                    vendor_data[cve] = {"vendors": set(), "description": "Check Point Security Advisory", "date_added": datetime.now(timezone.utc).strftime("%Y-%m-%d")}
                vendor_data[cve]["vendors"].add("Check Point")
    except Exception as e:
        logging.error(f"Failed to scrape Check Point: {e}")

    return vendor_data



# -------------------------------------------------------------
# 4. FETCH AND NORMALIZE NEWS FEEDS
# -------------------------------------------------------------
def fetch_news(vendor_rules):
    logging.info("Fetching curated threat news...")
    news_feeds = load_json(os.path.join(CONFIG_DIR, "feeds.json"), [])
    articles = []
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

    for feed_info in news_feeds:
        try:
            feed = feedparser.parse(feed_info["url"])
            for entry in feed.entries[:8]:
                text_blob = f"{entry.get('title','')} {entry.get('description','')} {entry.get('summary','')}"
                found_cves = list(set(c.upper() for c in cve_pattern.findall(text_blob)))
                
                # Fix for CISA ATOM feeds: check updated if published doesn't exist
                pub_date = entry.get("published", entry.get("updated", ""))
                
                # Vendor matching for News
                matched_vendors = []
                lower_blob = text_blob.lower()
                for v_name, aliases in vendor_rules.items():
                    if any(a.lower() in lower_blob for a in aliases):
                        matched_vendors.append(v_name)
                
                articles.append({
                    "title": entry.get("title", "No Title"),
                    "link": entry.get("link", ""),
                    "published": pub_date,
                    "source": feed_info.get("name", "Unknown"),
                    "matched_cves": found_cves,
                    "vendors": matched_vendors
                })
        except Exception as e:
            logging.error(f"Failed to fetch news from {feed_info.get('name')}: {e}")

    articles = sorted(articles, key=lambda x: x["published"], reverse=True)[:40]
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
    
    # 1. Fetch all intelligence sources
    cisa_kev = fetch_cisa_kev()
    poc_cves, nuclei_cves = fetch_poc_and_nuclei()
    news_articles = fetch_news(vendor_rules)
    nvd_delta = fetch_nvd_recent()
    vendor_advisories = fetch_vendor_advisories()

    # 2. Build the Global Candidate Pool
    master_cves = {}

    def init_cve(cid):
        if cid not in master_cves:
            master_cves[cid] = {
                "cve_id": cid,
                "date_added": "",
                "description": "",
                "vendors": set(),
                "products": set(),
                "is_kev": False,
                "has_poc": False,
                "has_nuclei": False,
                "in_news": False,
                "cvss": None,
                "epss": 0.0
            }

    # Inject CISA KEV
    for k in cisa_kev.values():
        cid = k["cve_id"]
        init_cve(cid)
        master_cves[cid]["is_kev"] = True
        master_cves[cid]["date_added"] = k.get("date_added", "")
        master_cves[cid]["description"] = k.get("description", "")
        if k.get("vendor") and k.get("vendor") != "Unknown":
            master_cves[cid]["vendors"].add(k.get("vendor"))
        if k.get("product") and k.get("product") != "Unknown":
            master_cves[cid]["products"].add(k.get("product"))

    # Inject NVD Delta
    for cid, nvd in nvd_delta.items():
        init_cve(cid)
        if not master_cves[cid]["date_added"]:
            master_cves[cid]["date_added"] = nvd.get("published", "")[:10]
        if not master_cves[cid]["description"]:
            master_cves[cid]["description"] = nvd.get("description", "")
        if master_cves[cid]["cvss"] is None:
            master_cves[cid]["cvss"] = nvd.get("cvss")

    # Inject Vendor Advisories (Cisco, Fortinet, PA, Check Point)
    for cid, adv in vendor_advisories.items():
        init_cve(cid)
        master_cves[cid]["vendors"].update(adv["vendors"])
        if not master_cves[cid]["date_added"]:
            master_cves[cid]["date_added"] = adv["date_added"]
        if not master_cves[cid]["description"]:
            master_cves[cid]["description"] = adv["description"]

    # Inject Flags
    for cid in poc_cves:
        init_cve(cid)
        master_cves[cid]["has_poc"] = True
    for cid in nuclei_cves:
        init_cve(cid)
        master_cves[cid]["has_nuclei"] = True
    for art in news_articles:
        for cid in art.get("matched_cves", []):
            init_cve(cid)
            master_cves[cid]["in_news"] = True

    # 3. EPSS Enrichment
    logging.info("Fetching EPSS for all candidates...")
    epss_data = fetch_epss(list(master_cves.keys()))
    for cid, info in epss_data.items():
        master_cves[cid]["epss"] = info.get("epss", 0.0)

    # 4. Text-Based Vendor Matching (For NVD/KEV descriptions)
    for cid, cve_obj in master_cves.items():
        search_blob = f"{' '.join(cve_obj['vendors'])} {' '.join(cve_obj['products'])} {cve_obj['description']}".lower()
        for v_name, aliases in vendor_rules.items():
            if any(a.lower() in search_blob for a in aliases):
                cve_obj["vendors"].add(v_name)

    # 5. Core Data Enrichment (CVSS, Product mapping for unknowns)
    # We only enrich high-value targets to save API time (KEV, PoC, Nuclei, News, or Vendor specific)
    enrich_targets = [
        cid for cid, c in master_cves.items() 
        if (c["is_kev"] or c["has_poc"] or c["has_nuclei"] or c["in_news"] or len(c["vendors"]) > 0 or c["epss"] > 0.05)
    ]
    
    logging.info(f"Enriching API data for {len(enrich_targets)} high-value CVEs...")
    with requests.Session() as session:
        session.headers.update(HEADERS)
        for idx, cid in enumerate(enrich_targets):
            # Only do deep NVD fallback for the most critical/recent 100 to save time
            allow_nvd = (idx < 100)
            if master_cves[cid]["cvss"] is None or not master_cves[cid]["description"]:
                en_desc, en_cvss, en_ven, en_prod = enrich_cve_details(
                    cid, session=session, local_cache=local_cache, allow_nvd_fallback=allow_nvd
                )
                if not master_cves[cid]["description"] and en_desc:
                    master_cves[cid]["description"] = en_desc
                if master_cves[cid]["cvss"] is None:
                    master_cves[cid]["cvss"] = en_cvss
                if en_ven != "Unknown":
                    master_cves[cid]["vendors"].add(en_ven)
                if en_prod != "Unknown":
                    master_cves[cid]["products"].add(en_prod)

            # Update cache
            local_cache[cid] = {
                "cvss": master_cves[cid]["cvss"],
                "description": master_cves[cid]["description"]
            }

    # 6. Format Master JSON for Output
    final_master_list = []
    for cid, c in master_cves.items():
        # Convert Sets to Lists for JSON serialization
        c["vendors"] = list(c["vendors"])
        c["products"] = list(c["products"])
        final_master_list.append(c)

    # Sort by date added (newest first)
    final_master_list = sorted(final_master_list, key=lambda x: x.get("date_added", ""), reverse=True)

    # Save to disk
    save_json(os.path.join(DATA_DIR, "cve_master.json"), final_master_list)
    save_json(os.path.join(DATA_DIR, "news.json"), news_articles)
    save_json(os.path.join(DATA_DIR, "sync_meta.json"), {
        "last_sync": get_ist_now_str(),
        "counts": {
            "master_cves": len(final_master_list),
            "news_articles": len(news_articles)
        }
    })

    # Copy configs
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

    logging.info("Master Sync completed successfully.")



if __name__ == "__main__":
    main()
