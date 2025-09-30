# 🐾 VulnHound — Legacy Windows Vulnerability Scanner

VulnHound is a **dual-source vulnerability scanner** for **legacy Windows systems**, designed to detect known CVEs for installed software by leveraging both:

- **NVD (National Vulnerability Database)** — for accurate CPE-based CVE matching  
- **Wazuh CTI** — as a fallback intelligence source when NVD data is incomplete  

> 🎯 **Built for environments where upgrading isn’t always possible** — such as industrial control systems, public institutions, and healthcare networks still running on Windows 8.1 / Windows 10.

---

## ⚙️ Key Features

✅ **Automatic Software Enumeration**  
Reads all installed software and versions directly from the Windows Registry.  

✅ **Smart Filtering**  
Scans only *interesting* software defined in a configurable `interesting_packages.json`.  

✅ **Dual Vulnerability Intelligence**  
- **Primary:** Fetches CVEs using official NVD API via CPE resolution.  
- **Fallback:** Queries **Wazuh CTI** for CVEs when NVD results are missing.  

✅ **Comprehensive CVE Details**  
Each vulnerability is enriched with:  
- CVE ID  
- Description  
- Published date  
- CVSS score  
- Severity  

✅ **Async Data Fetching**  
Uses asynchronous requests for faster CVE enrichment from Wazuh CTI.  

✅ **Reliable Desktop Filtering**  
Ignores irrelevant mobile/iOS/Android CPEs (to focus only on desktop software).

---

## 🚀 Installation

### Requirements

- Python **3.9+**
- Windows (for registry software enumeration)
- Dependencies:  
  ```bash
  pip install requests aiohttp beautifulsoup4
  ```

> ⚠️ **Note:** The scanner uses the NVD API. For higher rate limits, you can set your API key:
> ```bash
> setx NVD_API_KEY "your_api_key_here"
> ```

---

## 🧩 Configuration

### `interesting_packages.json`

This file defines which software keywords are considered “interesting.”  
Example:

```json
["firefox", "vlc", "7-zip", "python", "notepad++", "chrome", "winrar"]
```

The scanner will only analyze installed software matching these names.

---

## 🧠 Usage

Run the scanner in **automatic** or **manual** mode:

### 1️⃣ Auto Mode — Scan Installed Software

```bash
python vulnhound.py
```

Then select:
```
1) Auto (enumerate installed software and scan interesting packages)
```

VulnHound will:
- Enumerate all installed software from the Windows registry  
- Filter using `interesting_packages.json`  
- Resolve CPEs via NVD  
- Fetch CVEs (latest 25) and enrich them with Wazuh CTI data  
- Fallback to Wazuh CTI when NVD returns no vulnerabilities

---

### 2️⃣ Manual Mode — Scan Specific Software

```bash
python vulnhound.py
```

Then select:
```
2) Manual (enter a software name + version)
```

You’ll be prompted to enter:
```
Enter software keyword: firefox
Enter version (optional): 127.0
```

---

## 🧾 Example Output

```text
[1/3] Scanning VLC media player 3.0.20 ...

[INFO] Resolving CPEs for vlc 3.0.20 (desktop/neutral platforms only)...
[INFO] CPE: cpe:2.3:a:videolan:vlc_media_player:3.0.20:*:*:*:*:*:*:*  (VideoLAN VLC Media Player 3.0.20)

[INFO] Enriching 12 CVEs with Wazuh CTI...

- CVE-2023-4735 (published 2023-11-12)
  Description: Buffer overflow vulnerability in VLC media demux module.
  CVSS Score: 7.8
  Severity: HIGH
  Wazuh CTI: https://cti.wazuh.com/vulnerabilities/cves/CVE-2023-4735
```

---

## 🧱 Architecture Overview

```
 ┌───────────────────────────────┐
 │ Installed Software (Registry) │
 └───────────────┬───────────────┘
                 │
                 ▼
      Filter “Interesting” Packages
                 │
                 ▼
   ┌─────────────────────────────────────┐
   │ 1️⃣ NVD Query via CPE Resolution     │
   └─────────────────────────────────────┘
                 │
         No CVEs found? ▼
   ┌─────────────────────────────────────┐
   │ 2️⃣ Wazuh CTI Fallback (keyword+ver) │
   └─────────────────────────────────────┘
                 │
                 ▼
        CVE Details Enrichment (async)
                 │
                 ▼
         Report to Console / Future JSON
```

---

## 🔍 Improvements over the Previous Version

| Feature | Old Script | VulnHound |
|----------|-------------|------------|
| CVE Source | Wazuh CTI only | NVD (primary) + Wazuh CTI (fallback) |
| CVSS / Severity | ❌ Not included | ✅ Scraped from Wazuh CTI CVE pages |
| Accuracy | Relied on text search | Uses CPE-mapped NVD results |
| Performance | Sequential pyppeteer (slow) | Async HTTP requests (fast, lightweight) |
| OS Target | Windows only | ✅ Windows-focused, ignoring mobile software |
| Reliability | Occasional false negatives | ✅ Broader and verified CVE coverage |

---

## 🔮 Planned Future Enhancements

- [ ] Export results to **JSON**, **CSV**, or **HTML report**
- [ ] Add optional **GUI interface** for easy use by non-technical users
- [ ] Filter vulnerabilities by **severity level (Critical, High, Medium)**
- [ ] Integration with **Wazuh Manager or Dashboard**
- [ ] Include **vulnerability trend analysis** over time
- [ ] Add support for **offline scanning** (air-gapped systems)
- [ ] Extend to **Linux and macOS** in future versions

---

## 🧑‍💻 Credits

Developed by **Lewis Rakotomalala**  
🇲🇬 **Wazuh Ambassador — Madagascar**

Special thanks to the **Wazuh Community** for the CTI platform and resources that made this project possible.

---

## 📜 License

MIT License
