import os
import re
import time
import json
import logging
import shutil
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import feedparser
from bs4 import BeautifulSoup
from email.utils import parsedate_to_datetime

# =========================================================================
# CONFIGURATION & SETUP
# =========================================================================
IST = timezone(timedelta(hours=5, minutes=30))

def get_ist_now_str():
    return datetime.now(IST).strftime("%I:%M %p, %d-%m-%Y (IST)")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "config")
DATA_DIR = os.path.join(BASE_DIR, "docs", "data")
CACHE_FILE = os.path.join(DATA_DIR, "cve_cache.json")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9"
}

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

os.makedirs(DATA_DIR, exist_ok=True)


def create_pooled_session():
    """Creates a requests.Session with connection pooling and automatic retries."""
    session = requests.Session()
    session.headers.update(HEADERS)
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=30, pool_maxsize=30, max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


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


# =========================================================================
# TEXT, DATE & CVSS HELPERS
# =========================================================================
def clean_html_text(raw_html):
    """Strips HTML tags and collapses whitespace."""
    if not raw_html:
        return ""
    soup = BeautifulSoup(str(raw_html), "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()


def clean_cisa_description(raw_html):
    """Removes 'View CSAF' boilerplate and HTML tables from CISA advisory descriptions."""
    if not raw_html:
        return ""
    soup = BeautifulSoup(str(raw_html), "html.parser")
    for a in soup.find_all("a"):
        if "csaf" in a.get_text().lower():
            if a.parent and a.parent.name == "p":
                a.parent.decompose()
            else:
                a.decompose()
    for tbl in soup.find_all("table"):
        tbl.decompose()
    for h in soup.find_all(["h2", "h3"]):
        if h.get_text().strip().lower() in ["summary", "background"]:
            h.decompose()
    return re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()


def parse_cisa_date_from_link(link_url):
    """Extracts the exact publication date from CISA slugs like icsa-26-300-02 (Year 26, Julian day 300)."""
    m = re.search(r"(?:icsa|icsma|aa)-(\d{2})-(\d{3})", str(link_url), re.IGNORECASE)
    if m:
        yr = 2000 + int(m.group(1))
        day_of_year = int(m.group(2))
        try:
            dt = datetime(yr, 1, 1, 12, 0, tzinfo=timezone.utc) + timedelta(days=day_of_year - 1)
            dt_ist = dt.astimezone(IST)
            return (
                dt_ist.strftime("%Y-%m-%d"),
                dt_ist.strftime("%d %b %Y, %I:%M %p IST"),
                int(dt_ist.timestamp())
            )
        except Exception:
            pass
    return None


def parse_date_to_ist(raw_date_str, parsed_struct=None):
    """Converts any RSS/ISO date into (YYYY-MM-DD, 'DD Mon YYYY, HH:MM AM/PM IST', epoch)."""
    dt = None
    if parsed_struct:
        try:
            dt = datetime(*parsed_struct[:6], tzinfo=timezone.utc)
        except Exception:
            dt = None
    if not dt and raw_date_str:
        s = str(raw_date_str).strip()
        try:
            dt = parsedate_to_datetime(s)
        except Exception:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except Exception:
                try:
                    dt = datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except Exception:
                    dt = None
    if not dt:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_ist = dt.astimezone(IST)
    return (
        dt_ist.strftime("%Y-%m-%d"),
        dt_ist.strftime("%d %b %Y, %I:%M %p IST"),
        int(dt_ist.timestamp())
    )


def extract_cve_sentence_from_advisory(cve_id, raw_text):
    """Extracts the specific sentence/line for a single CVE from a multi-CVE vendor advisory."""
    cleaned = clean_html_text(raw_text)
    if not cleaned:
        return ""
    pattern = re.compile(
        rf"{re.escape(cve_id)}\s*[-:]\s*(?:\([a-zA-Z]+\)\s*)?(.+?)(?=CVE-\d{{4}}-\d{{4,7}}|$)",
        re.IGNORECASE
    )
    m = pattern.search(cleaned)
    if m and len(m.group(1).strip()) > 20:
        return m.group(1).strip()[:420]
    return cleaned[:420]


def fetch_raw_feed_bytes(url, session):
    """Fetches XML/RSS with fallback to system curl and AllOrigins proxy if WAF blocks runner IPs."""
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 200 and (
            b"<rss" in resp.content[:800] or b"<feed" in resp.content[:800] or b"<?xml" in resp.content[:800]
        ):
            return resp.content
    except Exception:
        pass

    try:
        cmd = [
            "curl", "-sL", "--max-time", "15",
            "-A", HEADERS["User-Agent"],
            "-H", "Accept: application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8",
            url
        ]
        out = subprocess.check_output(cmd)
        if out and (b"<rss" in out[:800] or b"<feed" in out[:800] or b"<?xml" in out[:800]):
            return out
    except Exception:
        pass

    try:
        proxy_url = f"https://api.allorigins.win/raw?url={requests.utils.quote(url, safe='')}"
        resp = session.get(proxy_url, timeout=15)
        if resp.status_code == 200 and (
            b"<rss" in resp.content[:800] or b"<feed" in resp.content[:800] or b"<?xml" in resp.content[:800]
        ):
            return resp.content
    except Exception:
        pass

    return None


def extract_nvd_cvss(cve_obj):
    """Strictly prioritizes CVSS v3.1 -> v3.0 -> v4.0 -> v2.0 (Primary over Secondary)."""
    metrics = cve_obj.get("metrics", {})
    if not metrics:
        return None
    for m_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"]:
        m_list = metrics.get(m_ver)
        if not m_list or not isinstance(m_list, list):
            continue
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
    """Extracts CVSS across both CNA and CISA ADP Vulnrichment containers (v3.x preferred)."""
    if not containers or not isinstance(containers, dict):
        return None
    all_metric_blocks = []
    cna = containers.get("cna", {})
    if isinstance(cna, dict) and isinstance(cna.get("metrics"), list):
        all_metric_blocks.extend(cna.get("metrics"))
    for adp in containers.get("adp", []) or []:
        if isinstance(adp, dict) and isinstance(adp.get("metrics"), list):
            all_metric_blocks.extend(adp.get("metrics"))

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


# =========================================================================
# 0. LOAD & SELF-HEAL LOCAL CVE CACHE
# =========================================================================
def load_existing_cve_cache():
    """Loads cached CVSS, descriptions, and vendor/product mappings from cve_cache.json & cve_master.json."""
    cache = load_json(CACHE_FILE, {})
    master_prev = load_json(os.path.join(DATA_DIR, "cve_master.json"), [])

    if isinstance(master_prev, list):
        for item in master_prev:
            cid = (item.get("cve_id") or "").upper()
            if not cid:
                continue
            existing = cache.get(cid, {})
            vendors_list = item.get("vendors") or []
            products_list = item.get("products") or []
            cache[cid] = {
                "cvss": item.get("cvss") if item.get("cvss") is not None else existing.get("cvss"),
                "description": item.get("description") or existing.get("description", ""),
                "vendor": vendors_list[0] if vendors_list else existing.get("vendor", "Unknown"),
                "product": products_list[0] if products_list else existing.get("product", "Unknown")
            }
    return cache


# =========================================================================
# 1. DATA INGESTION SOURCES
# =========================================================================
def fetch_cisa_kev(session):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    logging.info("Fetching CISA KEV catalog...")
    kev_map = {}
    try:
        res = session.get(url, timeout=15)
        if res.status_code == 200:
            for item in res.json().get("vulnerabilities", []):
                cve_id = item.get("cveID", "").strip().upper()
                if cve_id:
                    kev_map[cve_id] = {
                        "cve_id": cve_id,
                        "vendor": item.get("vendorProject", "Unknown"),
                        "product": item.get("product", "Unknown"),
                        "vuln_name": item.get("vulnerabilityName", ""),
                        "date_added": (item.get("dateAdded") or "")[:10],
                        "description": item.get("shortDescription", ""),
                        "due_date": (item.get("dueDate") or "")[:10]
                    }
            logging.info(f"Loaded {len(kev_map)} CISA KEV items.")
    except Exception as e:
        logging.error(f"Failed to fetch CISA KEV: {e}")
    return kev_map


def fetch_poc_and_nuclei(session):
    logging.info("Fetching public exploit signals (PoC-in-GitHub & Nuclei)...")
    poc_cves, nuclei_cves = set(), set()

    gh_headers = dict(HEADERS)
    gh_token = os.getenv("GITHUB_TOKEN")
    if gh_token:
        gh_headers["Authorization"] = f"token {gh_token}"

    current_year = datetime.now(timezone.utc).year
    for year in [current_year, current_year - 1]:
        try:
            url = f"https://api.github.com/repos/nomi-sec/PoC-in-GitHub/contents/{year}"
            res = session.get(url, headers=gh_headers, timeout=15)
            if res.status_code == 200:
                for item in res.json():
                    for m in CVE_REGEX.findall(item.get("name", "")):
                        poc_cves.add(m.upper())
        except Exception as e:
            logging.error(f"Error fetching PoC repo contents for {year}: {e}")

    try:
        url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/http/cves"
        res = session.get(url, headers=gh_headers, timeout=15)
        if res.status_code == 200:
            for folder in res.json()[-3:]:
                if folder.get("type") == "dir":
                    y_res = session.get(folder.get("url"), headers=gh_headers, timeout=15)
                    if y_res.status_code == 200:
                        for f in y_res.json():
                            for m in CVE_REGEX.findall(f.get("name", "")):
                                nuclei_cves.add(m.upper())
    except Exception as e:
        logging.error(f"Error fetching Nuclei templates: {e}")

    logging.info(f"Identified {len(poc_cves)} PoCs and {len(nuclei_cves)} Nuclei templates.")
    return poc_cves, nuclei_cves


def fetch_epss(cve_list, session):
    if not cve_list:
        return {}
    cve_list = list(set(cve_list))
    logging.info(f"Fetching EPSS scores for {len(cve_list)} candidate CVEs...")
    epss_map = {}
    chunk_size = 100

    for i in range(0, len(cve_list), chunk_size):
        chunk = cve_list[i:i + chunk_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            res = session.get(url, timeout=12)
            if res.status_code == 200:
                for entry in res.json().get("data", []):
                    cve_id = entry.get("cve", "").upper()
                    try:
                        epss_map[cve_id] = float(entry.get("epss", 0.0))
                    except ValueError:
                        epss_map[cve_id] = 0.0
        except Exception as e:
            logging.error(f"Error fetching EPSS chunk: {e}")
    return epss_map


def fetch_nvd_recent(session, days=5):
    logging.info("Querying NVD API 2.0 delta...")
    now = datetime.now(timezone.utc)
    start_date = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_date}&lastModEndDate={end_date}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY

    recent_nvd = {}
    try:
        res = session.get(url, headers=nvd_headers, timeout=25)
        if res.status_code == 200:
            for item in res.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "").upper()
                if not cve_id:
                    continue
                cvss_score = extract_nvd_cvss(cve)
                desc_text = next(
                    (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                recent_nvd[cve_id] = {
                    "cve_id": cve_id,
                    "cvss": cvss_score,
                    "description": desc_text,
                    "published": cve.get("published", "")
                }
    except Exception as e:
        logging.warning(f"NVD delta query bypassed: {e}")

    return recent_nvd


def fetch_vendor_advisories(session):
    """Fetches advisories from Cisco, Fortinet, Palo Alto (RSS) and Check Point (Web)."""
    logging.info("Fetching Vendor RSS and Web Advisories...")
    vendor_data = {}

    rss_feeds = {
        "Cisco": "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "Fortinet": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
        "Palo Alto": "https://security.paloaltonetworks.com/rss.xml"
    }

    for vendor, url in rss_feeds.items():
        try:
            xml_bytes = fetch_raw_feed_bytes(url, session)
            feed = feedparser.parse(xml_bytes) if xml_bytes else feedparser.parse(url)
            for entry in feed.entries:
                raw_desc = entry.get("description", "") or entry.get("summary", "") or entry.get("title", "")
                raw_date = entry.get("published", "") or entry.get("updated", "")
                parsed_t = entry.get("published_parsed") or entry.get("updated_parsed")
                iso_date, _, _ = parse_date_to_ist(raw_date, parsed_t)

                text_blob = f"{entry.get('title', '')} {clean_html_text(raw_desc)}"
                found_cves = set(c.upper() for c in CVE_REGEX.findall(text_blob))

                for cve in found_cves:
                    specific_desc = extract_cve_sentence_from_advisory(cve, raw_desc)
                    if cve not in vendor_data:
                        vendor_data[cve] = {
                            "vendors": set(),
                            "fallback_description": specific_desc,
                            "date_added": iso_date
                        }
                    vendor_data[cve]["vendors"].add(vendor)
        except Exception as e:
            logging.error(f"Failed to fetch {vendor} RSS: {e}")

    try:
        r = session.get("https://advisories.checkpoint.com/advisories/", timeout=15)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            today_iso = datetime.now(IST).strftime("%Y-%m-%d")
            for row in soup.find_all(["tr", "li", "div", "article"]):
                row_text = clean_html_text(row.get_text(separator=" "))
                if len(row_text) > 400:
                    continue
                found_cves = set(c.upper() for c in CVE_REGEX.findall(row_text))
                for cve in found_cves:
                    if cve not in vendor_data:
                        vendor_data[cve] = {
                            "vendors": set(),
                            "fallback_description": row_text if len(row_text) > 35 else "",
                            "date_added": today_iso
                        }
                    vendor_data[cve]["vendors"].add("Check Point")
    except Exception as e:
        logging.error(f"Failed to scrape Check Point: {e}")

    return vendor_data


def fetch_news(vendor_rules, session):
    logging.info("Fetching curated threat news...")
    news_feeds = load_json(os.path.join(CONFIG_DIR, "feeds.json"), [])
    articles = []

    if not any("cisa" in (f.get("name", "") + f.get("url", "")).lower() for f in news_feeds):
        news_feeds.append({
            "name": "CISA Advisories",
            "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"
        })

    for feed_info in news_feeds:
        source_name = feed_info.get("name", "Unknown")
        url = feed_info.get("url", "")
        if not url:
            continue

        is_cisa_feed = "cisa.gov" in url.lower() or "cisa" in source_name.lower()

        try:
            xml_data = fetch_raw_feed_bytes(url, session)
            feed = feedparser.parse(xml_data) if xml_data else feedparser.parse(url)
            logging.info(f"Feed '{source_name}' returned {len(feed.entries)} entries.")

            for entry in feed.entries[:15]:
                title = clean_html_text(entry.get("title", "No Title"))
                link = entry.get("link", "")
                if not link and entry.get("links"):
                    link = entry.links[0].get("href", "")

                raw_summary = entry.get("description", "") or entry.get("summary", "")
                if not raw_summary and entry.get("content"):
                    raw_summary = str(entry.get("content")[0].get("value", ""))

                full_raw_text = f"{title} {clean_html_text(raw_summary)}"
                found_cves = sorted(list(set(c.upper() for c in CVE_REGEX.findall(full_raw_text))))

                if is_cisa_feed:
                    clean_snippet = clean_cisa_description(raw_summary)
                else:
                    clean_snippet = clean_html_text(raw_summary)
                if not clean_snippet:
                    clean_snippet = title

                raw_date = (
                    entry.get("published")
                    or entry.get("updated")
                    or entry.get("dc_date")
                    or entry.get("date")
                    or ""
                )
                parsed_t = entry.get("published_parsed") or entry.get("updated_parsed")

                if not raw_date and not parsed_t and is_cisa_feed:
                    cisa_date_tuple = parse_cisa_date_from_link(link)
                    if cisa_date_tuple:
                        iso_date, ist_display, epoch_ts = cisa_date_tuple
                    else:
                        iso_date, ist_display, epoch_ts = parse_date_to_ist("", None)
                else:
                    iso_date, ist_display, epoch_ts = parse_date_to_ist(raw_date, parsed_t)

                matched_vendors = []
                lower_blob = full_raw_text.lower()
                for v_name, aliases in vendor_rules.items():
                    if any(a.lower() in lower_blob for a in aliases):
                        matched_vendors.append(v_name)

                articles.append({
                    "title": title,
                    "url": link,
                    "link": link,
                    "snippet": clean_snippet[:420],
                    "published": ist_display,
                    "date_iso": iso_date,
                    "epoch": epoch_ts,
                    "source": source_name,
                    "matched_cves": found_cves,
                    "matched_vendors": matched_vendors,
                    "vendors": matched_vendors
                })
        except Exception as e:
            logging.error(f"Failed to fetch news from {source_name} at {url}: {e}")

    articles = sorted(articles, key=lambda x: x.get("epoch", 0), reverse=True)[:80]
    return articles


# =========================================================================
# 2. CONCURRENT CVE ENRICHMENT (CVELISTV5 + NVD FALLBACK)
# =========================================================================
def fetch_nvd_single_cve(cve_id, session):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    nvd_headers = dict(HEADERS)
    if NVD_API_KEY:
        nvd_headers["apiKey"] = NVD_API_KEY
    try:
        res = session.get(url, headers=nvd_headers, timeout=8)
        if res.status_code == 200:
            vulns = res.json().get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                score = extract_nvd_cvss(cve)
                desc = next(
                    (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    ""
                )
                return score, desc
    except Exception:
        pass
    return None, ""


def enrich_cve_details(cve_id, session, local_cache, allow_nvd_fallback=False):
    cached = (local_cache or {}).get(cve_id, {})
    desc = cached.get("description", "")
    cvss = cached.get("cvss", None)
    vendor = cached.get("vendor", "Unknown")
    product = cached.get("product", "Unknown")

    if cvss is not None and desc and vendor != "Unknown" and product != "Unknown":
        return cve_id, desc, cvss, vendor, product

    try:
        parts = cve_id.split("-")
        if len(parts) == 3:
            year, num = parts[1], parts[2]
            prefix = num[:-3] + "xxx" if len(num) > 3 else "0xxx"
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{prefix}/{cve_id}.json"

            r = session.get(raw_url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                containers = data.get("containers", {})
                cna = containers.get("cna", {})

                if not desc:
                    for d in cna.get("descriptions", []):
                        if str(d.get("lang", "en")).startswith("en"):
                            desc = d.get("value", "")
                            break

                affected_list = list(cna.get("affected", []))
                for adp in containers.get("adp", []) or []:
                    if isinstance(adp, dict) and isinstance(adp.get("affected"), list):
                        affected_list.extend(adp.get("affected"))

                for aff in affected_list:
                    if not isinstance(aff, dict):
                        continue
                    v_val = aff.get("vendor", "")
                    p_val = aff.get("product", "")
                    if vendor == "Unknown" and v_val and v_val.lower() not in ["n/a", "unknown"]:
                        vendor = v_val
                    if product == "Unknown" and p_val and p_val.lower() not in ["n/a", "unknown"]:
                        product = p_val

                if cvss is None:
                    cvss = extract_cvelist_cvss(containers)
    except Exception:
        pass

    if cvss is None and allow_nvd_fallback:
        nvd_score, nvd_desc = fetch_nvd_single_cve(cve_id, session)
        if nvd_score is not None:
            cvss = nvd_score
        if not desc and nvd_desc:
            desc = nvd_desc

    return cve_id, desc, cvss, vendor, product


# =========================================================================
# MAIN COMPILATION ENGINE (CENTRALIZED CVE MASTER)
# =========================================================================
def main():
    vendor_rules = load_json(os.path.join(CONFIG_DIR, "vendors.json"), {})
    local_cache = load_existing_cve_cache()

    with create_pooled_session() as session:
        cisa_kev = fetch_cisa_kev(session)
        poc_cves, nuclei_cves = fetch_poc_and_nuclei(session)
        news_articles = fetch_news(vendor_rules, session)
        nvd_delta = fetch_nvd_recent(session)
        vendor_advisories = fetch_vendor_advisories(session)

        master_cves = {}

        def init_cve(cid):
            if cid not in master_cves:
                master_cves[cid] = {
                    "cve_id": cid,
                    "date_added": "",
                    "due_date": "",
                    "description": "",
                    "adv_fallback_desc": "",
                    "vendors": set(),
                    "products": set(),
                    "is_kev": False,
                    "has_poc": False,
                    "has_nuclei": False,
                    "in_news": False,
                    "cvss": None,
                    "epss": 0.0
                }

        # 1. Inject CISA KEV
        for k in cisa_kev.values():
            cid = k["cve_id"]
            init_cve(cid)
            master_cves[cid]["is_kev"] = True
            master_cves[cid]["date_added"] = k.get("date_added", "")
            master_cves[cid]["due_date"] = k.get("due_date", "")
            master_cves[cid]["description"] = clean_html_text(k.get("description", ""))
            if k.get("vendor") and k.get("vendor") != "Unknown":
                master_cves[cid]["vendors"].add(k.get("vendor"))
            if k.get("product") and k.get("product") != "Unknown":
                master_cves[cid]["products"].add(k.get("product"))

        # 2. Inject NVD Delta
        for cid, nvd in nvd_delta.items():
            init_cve(cid)
            if not master_cves[cid]["date_added"]:
                master_cves[cid]["date_added"] = (nvd.get("published") or "")[:10]
            if not master_cves[cid]["description"]:
                master_cves[cid]["description"] = clean_html_text(nvd.get("description", ""))
            if master_cves[cid]["cvss"] is None and nvd.get("cvss") is not None:
                master_cves[cid]["cvss"] = nvd.get("cvss")

        # 3. Inject Vendor Advisories (Keep advisory text as fallback so official per-CVE description wins)
        for cid, adv in vendor_advisories.items():
            init_cve(cid)
            master_cves[cid]["vendors"].update(adv["vendors"])
            if not master_cves[cid]["date_added"]:
                master_cves[cid]["date_added"] = (adv.get("date_added") or "")[:10]
            if adv.get("fallback_description"):
                master_cves[cid]["adv_fallback_desc"] = adv["fallback_description"]

        # 4. Inject Exploit & News Flags
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

        # 5. EPSS Enrichment
        epss_data = fetch_epss(list(master_cves.keys()), session)
        for cid, score in epss_data.items():
            master_cves[cid]["epss"] = score

        # 6. Parallel Core Data Enrichment (CVEListV5 + Top NVD Fallback)
        enrich_targets = [
            cid for cid, c in master_cves.items()
            if (c["is_kev"] or c["has_poc"] or c["has_nuclei"] or c["in_news"] or len(c["vendors"]) > 0 or c["epss"] >= 0.05)
        ]

        logging.info(f"Enriching API data concurrently for {len(enrich_targets)} high-value CVEs...")
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(
                    enrich_cve_details,
                    cid,
                    session,
                    local_cache,
                    allow_nvd_fallback=(idx < 60)
                ): cid
                for idx, cid in enumerate(enrich_targets)
            }

            for future in as_completed(futures):
                try:
                    cid, en_desc, en_cvss, en_ven, en_prod = future.result()
                    if not master_cves[cid]["description"] and en_desc:
                        master_cves[cid]["description"] = clean_html_text(en_desc)
                    if master_cves[cid]["cvss"] is None and en_cvss is not None:
                        master_cves[cid]["cvss"] = en_cvss
                    if en_ven and en_ven != "Unknown":
                        master_cves[cid]["vendors"].add(en_ven)
                    if en_prod and en_prod != "Unknown":
                        master_cves[cid]["products"].add(en_prod)
                except Exception as e:
                    logging.debug(f"Enrichment error: {e}")

        # Apply fallback description & update local cache
        for cid in enrich_targets:
            if not master_cves[cid]["description"] and master_cves[cid]["adv_fallback_desc"]:
                master_cves[cid]["description"] = master_cves[cid]["adv_fallback_desc"]

            v_list = sorted(list(master_cves[cid]["vendors"]))
            p_list = sorted(list(master_cves[cid]["products"]))
            local_cache[cid] = {
                "cvss": master_cves[cid]["cvss"],
                "description": master_cves[cid]["description"],
                "vendor": v_list[0] if v_list else "Unknown",
                "product": p_list[0] if p_list else "Unknown"
            }

        # 7. Text-Based Vendor Matching across enriched descriptions
        for cid, cve_obj in master_cves.items():
            search_blob = f"{' '.join(cve_obj['vendors'])} {' '.join(cve_obj['products'])} {cve_obj['description']}".lower()
            for v_name, aliases in vendor_rules.items():
                if any(a.lower() in search_blob for a in aliases):
                    cve_obj["vendors"].add(v_name)

        # 8. Finalize Master JSON Output
        final_master_list = []
        for cid, c in master_cves.items():
            c.pop("adv_fallback_desc", None)
            c["description"] = clean_html_text(c["description"])
            c["vendors"] = sorted(list(c["vendors"]))
            c["products"] = sorted(list(c["products"]))
            if not c["date_added"]:
                c["date_added"] = f"{cid.split('-')[1]}-01-01" if len(cid.split("-")) == 3 else "2026-01-01"
            final_master_list.append(c)

        final_master_list = sorted(final_master_list, key=lambda x: x.get("date_added", ""), reverse=True)

        # Save outputs strictly to docs/data/
        save_json(os.path.join(DATA_DIR, "cve_master.json"), final_master_list)
        save_json(os.path.join(DATA_DIR, "news.json"), news_articles)
        save_json(os.path.join(DATA_DIR, "sync_meta.json"), {
            "last_sync": get_ist_now_str(),
            "counts": {
                "master_cves": len(final_master_list),
                "news_articles": len(news_articles)
            }
        })
        save_json(CACHE_FILE, local_cache)

        # Mirror static reference configs into docs/data/
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
