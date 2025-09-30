#!/usr/bin/env python3
"""
VulnHound.py

Integrated legacy Windows vulnerability scanner:
- Enumerates installed software (Windows registry) OR accepts manual input.
- Filters software names by keywords in interesting_packages.json.
- Resolves CPEs via NVD, fetches up to 25 latest CVEs per CPE, deduplicates.
- Enriches CVEs asynchronously by scraping Wazuh CTI for CVSS score & severity.
- Prints results to console:
    CVE ID, description, published date, Wazuh CTI link, CVSS score(from wazuh cti), severity (from wazuh cti)

Requirements:
  pip install requests aiohttp beautifulsoup4
  (Optional for older scripts: pyppeteer if you plan to reuse older browser code)
Notes:
  - Set env var NVD_API_KEY to improve NVD rate limits (optional).
  - Run on Windows for automatic installed-software enumeration.
"""

import os
import sys
import time
import re
import json
import requests
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from wazuh_fallback import fetch_wazuh_cti_fallback

# Windows registry imports only when needed
try:
    import winreg
except Exception:
    winreg = None

# Config
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "").strip()
HEADERS = {"apiKey": API_KEY} if API_KEY else {}
REQUEST_DELAY = 0.6 if API_KEY else 6.0  # polite delay without key
INTERESTING_FILE = "interesting_packages.json"
PER_CPE_LIMIT = 25    # latest CVEs to fetch per CPE
TIMEOUT = 30

# -------------------- Utilities -------------------- #
def _tokenize(s):
    if not s: return set()
    s = s.lower()
    s = re.sub(r'[^a-z0-9]+', ' ', s)
    return set([t for t in s.split() if len(t) > 1])

def parse_date_to_dt(s):
    """Return timezone-aware datetime (UTC) from various ISO-like strings.
       Fallback to epoch (1970) on failure."""
    if not s:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        fmts = ["%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"]
        for f in fmts:
            try:
                dt = datetime.strptime(s, f)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)

# -------------------- NVD CPE resolver -------------------- #
def fetch_cpes_from_nvd(query, max_results=40):
    params = {"keywordSearch": query, "resultsPerPage": max_results}
    time.sleep(REQUEST_DELAY)
    r = requests.get(NVD_CPE_API, params=params, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def _score_candidate(keyword_tokens, version_token, title, cpe_name):
    score = 0
    title_tokens = _tokenize(title or "")
    cpe_tokens = _tokenize(cpe_name.replace("cpe:2.3:", ""))
    score += len(keyword_tokens & (title_tokens | cpe_tokens)) * 10
    if keyword_tokens & title_tokens:
        score += 5
    if version_token and (f":{version_token}:" in cpe_name or cpe_name.endswith(f":{version_token}:*")):
        score += 20
    if re.search(r':\*:?$', cpe_name):
        score += 2
    return score

def is_relevant_cpe(cpe):
    """Exclude obvious mobile-only target platforms (iphone_os, android, ios)."""
    parts = cpe.split(":")
    if len(parts) < 13:
        return False
    target_sw = parts[10]
    mobile_platforms = {"iphone_os", "android", "ios"}
    if target_sw and target_sw.lower() in mobile_platforms:
        return False
    return True

def resolve_cpes(keyword, version=None, max_candidates=8):
    """Return ranked list of candidate CPEs for the keyword+version."""
    keyword_str = keyword.strip()
    version_token = None
    if version:
        m = re.search(r'(\d+(?:\.\d+){0,3})', version)
        if m:
            version_token = m.group(1)
    keyword_tokens = _tokenize(keyword_str)
    q1 = f"{keyword_str} {version_token}" if version_token else keyword_str

    try:
        data = fetch_cpes_from_nvd(q1, max_results=40)
    except Exception as e:
        print(f"[WARN] fetch_cpes_from_nvd failed for query={q1}: {e}")
        data = {}

    candidates = []
    for item in data.get("products", []):
        c = item.get("cpe", {}) or {}
        cpe_name = c.get("cpeName")
        title = (c.get("titles") or [{}])[0].get("title", "") if c else ""
        if cpe_name and is_relevant_cpe(cpe_name):
            score = _score_candidate(keyword_tokens, version_token, title, cpe_name)
            candidates.append({"cpe": cpe_name, "title": title, "score": score})

    best = {}
    for c in candidates:
        key = c["cpe"]
        if key not in best or c["score"] > best[key]["score"]:
            best[key] = c
    ranked = sorted(best.values(), key=lambda x: x["score"], reverse=True)
    return ranked[:max_candidates]

# -------------------- NVD CVE fetcher -------------------- #
def get_cves_from_nvd(cpe, limit=PER_CPE_LIMIT):
    """Fetch CVEs for a CPE and return list of dicts containing cve, description, published, published_dt, wazuh_cti_link."""
    params = {"cpeName": cpe, "resultsPerPage": 2000}
    time.sleep(REQUEST_DELAY)
    try:
        r = requests.get(NVD_CVE_API, params=params, headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  [WARN] NVD CVE fetch failed for {cpe}: {e}")
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {}) or {}
        cve_id = cve.get("id")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        published_str = vuln.get("published") or vuln.get("publishedDate") or \
                        vuln.get("cve", {}).get("published") or vuln.get("cve", {}).get("publishedDate") or ""
        published_dt = parse_date_to_dt(published_str)

        cves.append({
            "cve": cve_id,
            "description": desc,
            "published": published_str,
            "published_dt": published_dt,
            "wazuh_cti_link": f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
        })

    # Sort newest first
    cves.sort(key=lambda x: x["published_dt"], reverse=True)
    # Return latest up to limit (or all if fewer)
    if limit and len(cves) > limit:
        return cves[:limit]
    return cves

# -------------------- Wazuh CTI async enrichment -------------------- #
async def fetch_html(session, url):
    async with session.get(url, ssl=False, timeout=TIMEOUT) as resp:
        return await resp.text()

async def get_cve_score(session, cve_id):
    url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
    try:
        html = await fetch_html(session, url)
        soup = BeautifulSoup(html, "html.parser")
        score, severity = None, None
        aside = soup.find("aside", class_="cve-score")
        if aside:
            dl = aside.find("dl")
            if dl:
                dd = dl.find("dd")
                dt = dl.find("dt")
                if dd:
                    score = dd.text.strip()
                if dt:
                    severity = dt.text.strip()
        return {"cve_id": cve_id, "cvss_score": score, "severity": severity}
    except Exception as e:
        # Swim gracefully on errors — return blanks
        print(f"  [WARN] Wazuh CTI fetch failed for {cve_id}: {e}")
        return {"cve_id": cve_id, "cvss_score": None, "severity": None}

async def enrich_cves_with_wazuh(cves):
    """Async scrape Wazuh CTI for multiple CVEs. Modifies and returns cves list in place."""
    async with aiohttp.ClientSession() as session:
        tasks = [get_cve_score(session, c["cve"]) for c in cves]
        results = await asyncio.gather(*tasks, return_exceptions=False)
    enrich_map = {r["cve_id"]: r for r in results}
    for cve in cves:
        info = enrich_map.get(cve["cve"], {})
        cve["cvss_score"] = info.get("cvss_score")
        cve["severity"] = info.get("severity")
    return cves

# -------------------- Windows installed software enumeration -------------------- #
UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", winreg.KEY_READ | getattr(winreg, "KEY_WOW64_32KEY", 0))
] if winreg else []

def get_installed_software():
    """Return list of dicts {'name': ..., 'version': ...} from Windows registry uninstall keys."""
    if not winreg:
        return []
    software = []
    for hive, path, access in UNINSTALL_KEYS:
        try:
            key = winreg.OpenKey(hive, path, 0, access)
        except FileNotFoundError:
            continue
        except Exception:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                sub = winreg.OpenKey(key, subkey_name, 0, access)
                try:
                    name = winreg.QueryValueEx(sub, "DisplayName")[0]
                    version = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                    if name:
                        software.append({"name": name, "version": version or ""})
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
            except OSError:
                break
    # deduplicate by name+version
    seen = {}
    for s in software:
        key = f"{s['name']}-{s['version']}"
        seen[key] = s
    return list(seen.values())

# -------------------- Interesting keywords loader -------------------- #
def load_interesting_packages(path=INTERESTING_FILE):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [p.lower() for p in data if isinstance(p, str)]
    except FileNotFoundError:
        print(f"[WARN] {path} not found — no automatic filtering will be applied.")
        return []
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
        return []

def is_interesting(name, keywords):
    nl = (name or "").lower()
    return any(kw in nl for kw in keywords)

# -------------------- Console output formatting -------------------- #
def print_package_report(pkg_name, pkg_version, cves):
    print("\n" + "="*70)
    print(f"Package: {pkg_name}    Version: {pkg_version}")
    print(f"Found CVEs: {len(cves)} (showing up to {len(cves)})")
    print("-"*70)
    if not cves:
        print("  No CVEs found (or fetch failed).")
        return
    # Sort by published_dt newest first (safety)
    cves_sorted = sorted(cves, key=lambda x: x.get("published_dt", datetime(1970,1,1, tzinfo=timezone.utc)), reverse=True)
    for c in cves_sorted:
        print(f"- {c.get('cve')} (published {c.get('published') or 'N/A'})")
        print(f"  Description: {c.get('description') or 'N/A'}")
        print(f"  Wazuh CTI: {c.get('wazuh_cti_link')}")
        print(f"  CVSS Score: {c.get('cvss_score') or 'N/A'}    Severity: {c.get('severity') or 'N/A'}")
        print()

# -------------------- Main flow -------------------- #
def run_for_package(name, version, search_keyword=None, interesting_keywords=None):
    """
    Process a package:
     - resolve CPEs -> fetch CVEs from NVD
     - dedupe and keep newest
     - if no CVEs from NVD, fallback to Wazuh CTI using `search_keyword` (from interesting_packages)
     - enrich missing CVEs with Wazuh CTI (async)
     - print package report
    """
    # ensure collected exists no matter what
    collected = {}

    print(f"\n[INFO] Processing package: {name} {version}")

    # quick filter (optional: keep for safety)
    if interesting_keywords and not is_interesting(name, interesting_keywords):
        print("  [SKIP] Not in interesting packages list.")
        return

    # 1) Resolve CPE candidates from NVD
    cpes = resolve_cpes(name, version, max_candidates=8)
    if not cpes:
        print("  [INFO] No relevant CPEs found for this package.")
        # try fallback immediately if no CPEs
        if search_keyword:
            print("  [INFO] No CPEs found. Trying Wazuh CTI fallback using keyword:", search_keyword)
            try:
                fallback_cves = asyncio.run(fetch_wazuh_cti_fallback(search_keyword, version))
                if fallback_cves:
                    print(f"  [INFO] Wazuh fallback found {len(fallback_cves)} CVEs.")
                    collected = {cv["cve"]: cv for cv in fallback_cves}
                else:
                    print("  [INFO] No CVEs found from Wazuh CTI fallback either.")
            except Exception as e:
                print(f"  [WARN] Wazuh CTI fallback failed: {e}")
                collected = {}
        else:
            print("  [WARN] No search_keyword provided for fallback; skipping fallback.")
    else:
        # We have CPEs: collect CVEs from them
        for c in cpes:
            cpe_name = c["cpe"]
            title = c.get("title", "")
            print(f"  [CPE] {cpe_name}  ({title})")
            try:
                cves = get_cves_from_nvd(cpe_name, limit=PER_CPE_LIMIT)
            except Exception as e:
                print(f"  [WARN] Failed to fetch CVEs for {cpe_name}: {e}")
                cves = []

            for cv in cves:
                cid = cv.get("cve")
                if not cid:
                    continue
                existing = collected.get(cid)
                # prefer the newest published_dt if duplicate
                if not existing or cv.get("published_dt", datetime(1970,1,1,tzinfo=timezone.utc)) > existing.get("published_dt", datetime(1970,1,1,tzinfo=timezone.utc)):
                    collected[cid] = cv

        # after querying CPEs, if still empty -> fallback using search_keyword
        if not collected and search_keyword:
            print("  [INFO] No CVEs found from NVD. Falling back to Wazuh CTI...")
            try:
                fallback_cves = asyncio.run(fetch_wazuh_cti_fallback(search_keyword, version))
                if fallback_cves:
                    print(f"  [INFO] Wazuh fallback found {len(fallback_cves)} CVEs.")
                    collected = {cv["cve"]: cv for cv in fallback_cves}
                else:
                    print("  [INFO] No CVEs found from Wazuh CTI fallback either.")
            except Exception as e:
                print(f"  [WARN] Wazuh CTI fallback failed: {e}")
                collected = {}

    # if still empty, nothing to do
    if not collected:
        print("  [INFO] No CVEs to report for this package.")
        return

    # Convert to list, sort newest first, limit overall to PER_CPE_LIMIT
    uniques = sorted(collected.values(), key=lambda x: x.get("published_dt", datetime(1970,1,1,tzinfo=timezone.utc)), reverse=True)
    if len(uniques) > PER_CPE_LIMIT:
        uniques = uniques[:PER_CPE_LIMIT]

    # Enrich CVEs that are missing cvss_score or severity (avoid re-scraping those fetched by fallback which already have them)
    to_enrich = [c for c in uniques if not c.get("cvss_score")]
    if to_enrich:
        print(f"  [INFO] Enriching {len(to_enrich)} CVEs with Wazuh CTI (async)...")
        try:
            enriched = asyncio.run(enrich_cves_with_wazuh(to_enrich))
            # map enriched results back into uniques (match by cve id)
            enrich_map = {e["cve"]: e for e in enriched}
            for i, c in enumerate(uniques):
                if c["cve"] in enrich_map:
                    # update only score/severity (keep other fields)
                    uniques[i]["cvss_score"] = enrich_map[c["cve"]].get("cvss_score")
                    uniques[i]["severity"] = enrich_map[c["cve"]].get("severity")
        except Exception as e:
            print(f"  [WARN] Wazuh CTI enrichment failed: {e}")
            # leave missing fields blank if enrichment fails

    # finally, print the report
    print_package_report(name, version, uniques)

def main():
    interesting_keywords = load_interesting_packages(INTERESTING_FILE)

    # Ask mode
    print("VulnHound - Legacy Windows vulnerability scanner")
    print("Choose mode:")
    print("  1) Auto (enumerate installed software and scan interesting packages)")
    print("  2) Manual (enter a software name + version)")
    mode = input("Select mode (1 or 2) [1]: ").strip() or "1"

    if mode not in {"1", "2"}:
        print("Invalid mode selected.")
        return

    if mode == "2":
        # Manual single package
        name = input("Enter software keyword (e.g. firefox): ").strip()
        version = input("Enter version (optional, e.g. 127.0): ").strip() or None
        run_for_package(name, version, search_keyword=name.lower(), interesting_keywords=[])
        return

    # Auto mode: need Windows registry
    if not winreg:
        print("[ERROR] Windows registry module not available. Auto mode requires running on Windows.")
        return

    print("[INFO] Enumerating installed software from registry...")
    all_sw = get_installed_software()
    if not all_sw:
        print("[INFO] No installed software found or registry access failed.")
        return

    # Filter by interesting keywords
    interesting = []
    for pkg in all_sw:
        name_lower = (pkg.get("name","") or "").lower()
        for kw in interesting_keywords:
            if kw in name_lower:
                interesting.append((pkg, kw))
                break
    print(f"[INFO] Found {len(all_sw)} installed entries, {len(interesting)} matched interesting keywords.")

    # Iterate filtered packages (dedup) — with keyword mapping
    processed = set()
    for idx, (pkg, matched_kw) in enumerate(interesting, start=1):
        name = pkg.get("name")
        version = pkg.get("version", "")
        dedup_key = f"{name.lower()}__{version}"
        if dedup_key in processed:
            continue
        processed.add(dedup_key)

        print(f"\n[{idx}/{len(interesting)}] Scanning {name} {version} ...")

        try:
            run_for_package(name, version, search_keyword=matched_kw, interesting_keywords=interesting_keywords)
        except Exception as e:
            print(f"  [ERROR] Failed scanning {name} {version}: {e}")
            
if __name__ == "__main__":
    main()
