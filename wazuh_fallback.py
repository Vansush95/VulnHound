#!/usr/bin/env python3
"""
wazuh_cti_fallback.py
----------------------------------
Async fallback CVE retriever for VulnHound.

Used only when NVD returns no CVEs.
Searches Wazuh CTI for <keyword> + <version> and parses CVE details.

Query strategy:
  1. exact:      keyword + version
  2. normalized: keyword + simplified version
  3. major:      keyword + major version (e.g. 'vlc+3')

Returns:
[
  {
    "cve": "CVE-2024-1234",
    "description": "...",
    "published": "2024-04-13",
    "cvss_score": "9.1",
    "severity": "Critical",
    "wazuh_cti_link": "https://cti.wazuh.com/vulnerabilities/cves/CVE-2024-1234"
  },
  ...
]
"""

import sys
import os
import asyncio
import re
import time
from bs4 import BeautifulSoup
from pyppeteer import launch

# ---------------- Configuration ---------------- #
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"  # adjust if needed
NAV_TIMEOUT = 60000  # ms
DETAIL_FETCH_DELAY = 3  # seconds between CVE detail fetches

# Fix Windows asyncio event loop
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass


# ---------------- Helper Functions ---------------- #
def simplify_version(version):
    """Return progressively simplified version (e.g. 1.2.10.6 → 1.2.10)."""
    if not version:
        return version
    v = version.strip()
    if '+' in v:
        v = v.split('+')[0]
    v = v.split('-')[0]  # strip suffix like -beta
    parts = v.split('.')
    # progressively shorter versions (without duplicates)
    versions = []
    for i in range(len(parts), 0, -1):
        simplified = '.'.join(parts[:i])
        if simplified not in versions:
            versions.append(simplified)
    return versions 

# ---------------- Browser Fetch ---------------- #
async def fetch_with_browser(url):
    """Fetch HTML content via headless browser."""
    browser = None
    try:
        launch_kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-setuid-sandbox"]}
        if CHROME_PATH and os.path.exists(CHROME_PATH):
            launch_kwargs["executablePath"] = CHROME_PATH

        browser = await launch(**launch_kwargs)
        page = await browser.newPage()
        await page.setUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/115 Safari/537.36"
        )
        await page.goto(url, {"waitUntil": "networkidle2", "timeout": NAV_TIMEOUT})
        await asyncio.sleep(1)
        content = await page.content()
        await browser.close()
        return content

    except Exception as e:
        print(f"[ERROR] Browser fetch failed for {url}: {e}")
        try:
            if browser:
                await browser.close()
        except Exception:
            pass
    return ""


# ---------------- Fetch CVE IDs ---------------- #
async def fetch_cve_ids(keyword, version):
    """Try multiple Wazuh CTI search variations and print each query clearly."""
    queries = []

    # 1️⃣ Build a list of queries using all simplified versions
    simplified_versions = simplify_version(version)
    for v in simplified_versions:
        q = f"{keyword}+{v}".replace(' ', '+')
        if q not in queries:
            queries.append(q)

    # ✳️ DEBUG: show all generated queries
    print(f"\n[DEBUG] Preparing Wazuh CTI queries for '{keyword} {version}':")
    # for i, q in enumerate(queries, 1):
        # print(f"  [{i}] -> {q}")

    found_ids = []

    # 🔍 Perform all queries in order until we find results
    for q in queries:
        url = f"https://cti.wazuh.com/vulnerabilities/cves?q={q}"
        print(f"\n[INFO] Querying Wazuh CTI search: {url}")

        html = await fetch_with_browser(url)
        if not html:
            print("  [WARN] No HTML returned for this query.")
            continue

        soup = BeautifulSoup(html, "html.parser")
        ids = []

        # Try CVE extraction from <dt> tags
        for dt in soup.find_all("dt"):
            txt = dt.get_text(strip=True)
            if txt.startswith("CVE-"):
                ids.append(txt)

        # Fallback to table layout
        if not ids:
            table = soup.find("table")
            if table:
                for row in table.find_all("tr")[1:]:
                    cols = row.find_all("td")
                    if not cols:
                        continue
                    a = cols[0].find("a")
                    if a and a.text.strip().startswith("CVE-"):
                        ids.append(a.text.strip())

        # If CVEs found — print and return
        if ids:
            ids = list(dict.fromkeys(ids))  # deduplicate
            found_ids.extend(ids)
            print(f"  [SUCCESS] Found {len(ids)} CVEs from query: {q}")
            print(f"  [DEBUG] Listing CVEs: {', '.join(ids[:5])}")
            return found_ids

        # else, try next simplified query
        print(f"  [INFO] No results found for query: {q}")

    # None of the simplified queries found results
    print(f"[INFO] No CVE IDs found from Wazuh CTI for '{keyword} {version}'.")
    return found_ids

# ---------------- Fetch CVE Details ---------------- #
async def fetch_cve_details(cve_id):
    """Fetch details (description, published date, score, severity)."""
    url = f"https://cti.wazuh.com/vulnerabilities/cves/{cve_id}"
    print(f"  [INFO] Fetching details for {cve_id} ...")

    html = await fetch_with_browser(url)
    if not html:
        print(f"  [WARN] No content for {cve_id}.")
        return None

    soup = BeautifulSoup(html, "html.parser")

    # Description
    desc_tag = soup.find("div", class_="show-more-content")
    description = desc_tag.get_text(strip=True) if desc_tag else ""

    # Published date
    published = ""
    pills = soup.find("ul", class_="cve-pills")
    if pills:
        date_tag = pills.find("li", {"title": "Published date"})
        if date_tag:
            published = date_tag.get_text(strip=True)

    # CVSS score & severity
    score, severity = None, None
    aside = soup.find("aside", class_="cve-score")
    if aside:
        dl = aside.find("dl")
        if dl:
            dt = dl.find("dt")
            dd = dl.find("dd")
            severity = dt.get_text(strip=True) if dt else None
            score = dd.get_text(strip=True) if dd else None

    await asyncio.sleep(DETAIL_FETCH_DELAY)  # polite delay

    return {
        "cve": cve_id,
        "description": description,
        "published": published,
        "cvss_score": score,
        "severity": severity,
        "wazuh_cti_link": url
    }


# ---------------- Main Entry ---------------- #
async def fetch_wazuh_cti_fallback(keyword, version):
    """Main entry point: orchestrates full Wazuh CTI fallback."""
    ids = await fetch_cve_ids(keyword, version)
    if not ids:
        return []

    results = []
    for cve_id in ids:
        details = await fetch_cve_details(cve_id)
        if details:
            results.append(details)
    return results


# ---------------- Standalone Test ---------------- #
if __name__ == "__main__":
    keyword = "vlc"
    version = "3.0.20"
    start = time.time()

    cves = asyncio.run(fetch_wazuh_cti_fallback(keyword, version))
    elapsed = time.time() - start

    print(f"\n[RESULT] Retrieved {len(cves)} CVEs in {elapsed:.1f}s.\n")
    for cve in cves:
        print(f"- {cve['cve']} (Published: {cve['published']})")
        print(f"  Severity: {cve['severity']}, Score: {cve['cvss_score']}")
        print(f"  Desc: {cve['description']}")
        print(f"  Link: {cve['wazuh_cti_link']}\n")

