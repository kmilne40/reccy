# The Reccy Toolkit: A Comprehensive Handbook  
**Written by Kev Milne**

---

## 1. Introduction to OSINT/Reconnaissance

Open Source Intelligence (OSINT) and reconnaissance refer to the process of collecting information about a target—such as a domain, IP address, organization, or individual—from publicly available sources. This data can include DNS records, WHOIS details, subdomains, web server headers, known vulnerabilities, public documents, social media content, and more. 

By using OSINT techniques, security professionals, penetration testers, and researchers gather intelligence without employing intrusive methods, making OSINT the **foundation** of the reconnaissance phase. The data you collect early in a penetration test can shape and guide all subsequent steps—helping you identify potential attack surfaces and vulnerabilities.

The Reccy Toolkit is designed to **streamline** the OSINT/recon process by consolidating multiple tasks—such as DNS lookups, WHOIS checks, subdomain brute forcing, email scraping, scanning, Shodan lookups, etc.—into a **single** Python-based tool. This way, you don’t have to juggle multiple separate utilities (or more advanced frameworks like `recon-ng`) to gather basic recon data.

---

## 2. Overview of The Reccy Toolkit

The Reccy Toolkit is an **all-in-one** reconnaissance script built in Python. It aims to be **simple**, **broad** in scope, and **modular** enough to extend. It uses well-known Python libraries (such as `requests`, `dns.resolver`, `bs4`, etc.) and optionally uses an API key for **Shodan** to unlock advanced search functionality.

Upon running the script, you’ll see a **menu** offering a variety of recon-related options—each of which is described in detail below.

---

## 3. Menu Options and Explanations

Below are all **18** options in The Reccy Toolkit. Each section explains:

- **Definition/Explanation** of what it is,
- **How it works** in this toolkit context,
- **Why** you might use it during the recon phase,
- **Any required API keys** or specialized libraries.

---

### 1. **Perform DNS Lookup (A)**

- **Definition/Explanation**: A DNS **A record** maps a domain to its IP address(es). “Perform DNS Lookup (A)” queries the DNS server to find all IPv4 addresses associated with a given domain. 
- **How It Works**: The tool uses `dns.resolver` to perform an A record lookup. If multiple A records exist (e.g., load balancing), you’ll see them all.
- **Why Use It**: During recon, you need to know the IP addresses that a domain resolves to—this can be your starting point for further scanning or exploitation. 
- **API Key**: **No** API key needed; it relies on DNS queries to the domain’s authoritative name servers.

---

### 2. **Perform MX Lookup**

- **Definition/Explanation**: MX records (Mail eXchanger) specify the mail servers responsible for receiving email on behalf of a domain.
- **How It Works**: The tool uses `dns.resolver` to query the domain’s MX records, returning the email server hostnames.
- **Why Use It**: In a pen test, knowing the mail servers can lead to potential social engineering targets (phishing) or checking for vulnerable mail servers (e.g., older SMTP services).
- **API Key**: **No** API key required; standard DNS queries.

---

### 3. **Perform NS Lookup**

- **Definition/Explanation**: NS records identify which name servers are authoritative for a domain. 
- **How It Works**: Using `dns.resolver`, the toolkit retrieves the NS records for the target domain.
- **Why Use It**: Identifying the name servers can help you check for misconfigurations—like whether a zone transfer is possible or if DNS-based vulnerabilities exist.
- **API Key**: **No**.

---

### 4. **Perform SOA Lookup**

- **Definition/Explanation**: The SOA (Start of Authority) record stores domain metadata, including the primary name server and the technical contact (in the form of an email-like address).
- **How It Works**: The tool queries the domain’s **SOA** record via `dns.resolver`.
- **Why Use It**: During recon, the SOA can reveal the domain’s main DNS server and an administrative contact. It sometimes discloses an email or subdomain you didn’t know existed.
- **API Key**: **No**.

---

### 5. **Perform Reverse DNS Lookup**

- **Definition/Explanation**: A reverse DNS lookup checks for a PTR record, mapping an IP address back to a domain name.
- **How It Works**: The toolkit uses `dns.reversename.from_address()` and queries the resulting PTR record. 
- **Why Use It**: In recon, if you discover a target IP, you can run a reverse DNS to see if it has a resolvable hostname—this might reveal naming conventions or additional subdomains.
- **API Key**: **No**.

---

### 6. **WHOIS Lookup (system whois)**

- **Definition/Explanation**: WHOIS is a protocol that provides registration details about a domain, such as registrant info, creation/expiration dates, and registrar details. 
- **How It Works**: The tool calls the **system’s** `whois` command via Python’s `subprocess` module. It prints the raw output and checks if the domain might be transfer-locked.
- **Why Use It**: WHOIS data can reveal the domain owner, contact info (or at least a registrar), and can confirm domain age (sometimes older domains are more likely to have legacy issues).
- **API Key**: **No**. This uses your system’s whois binary.

---

### 7. **Get All Information (DNS + WHOIS, raw output)**

- **Definition/Explanation**: This option is a convenience function that performs a **combination** of A, MX, NS, SOA lookups, a reverse DNS lookup on the first A record, and a WHOIS query—displaying everything in one go.
- **How It Works**: The script does sequential DNS queries for each record type, attempts a reverse DNS on the first IP, and finally runs the system whois on the domain. It outputs the results in raw text.
- **Why Use It**: For quick broad reconnaissance on a single domain, you can see all the main DNS details plus WHOIS in one consolidated output. 
- **API Key**: **No**.

---

### 8. **Perform Zone Transfer**

- **Definition/Explanation**: A **DNS zone transfer** (AXFR) is the process of copying the zone file from one DNS server to another. If misconfigured, external parties can request an AXFR and obtain **all** DNS records for the domain.
- **How It Works**: The toolkit tries to connect to each NS record and requests an AXFR via `dns.zone.from_xfr()`. 
- **Why Use It**: This can be a **major** find in a pen test—misconfigured name servers can expose every subdomain, mail server, and more, saving you a ton of time enumerating.
- **API Key**: **No**. Standard DNS queries.

---

### 9. **Email Scraper**

- **Definition/Explanation**: **Email scraping** is the process of crawling a website to find email addresses posted in the HTML or in text. 
- **How It Works**: The tool uses `requests` to fetch each page and `BeautifulSoup` to parse it, searching for strings that match an email regex (e.g., `user@domain.com`). It also follows internal links up to a user-specified depth.
- **Why Use It**: Gathering emails is crucial for the **social engineering** or **phishing** aspects of a pen test. Knowing valid email addresses can help you pivot or craft more realistic phishing attempts.
- **API Key**: **No**. This is purely HTML scraping.

---

### 10. **Brute Force Subdomains**

- **Definition/Explanation**: Subdomain brute forcing systematically appends potential subdomain strings (from a wordlist) to the base domain and checks if they resolve. 
- **How It Works**: For each subdomain guess, the tool tries a DNS A lookup. If it returns an IP, that subdomain **exists** (e.g., `dev.example.com`).
- **Why Use It**: In recon, subdomains often host admin panels, dev sites, or less hardened services. Finding them can significantly expand your attack surface.
- **API Key**: **No**. This uses local DNS queries.

---

### 11. **Port Scan & Banner Grab**

- **Definition/Explanation**: Port scanning checks if specific TCP ports are open on a target host. Banner grabbing attempts to retrieve a basic “banner” or initial server response to identify the running service.
- **How It Works**: After the user specifies a list of comma-delimited ports, the tool tries to connect using a TCP socket. If a connection succeeds, it sends a small HTTP request (like `HEAD / HTTP/1.0`) to see if any banner is returned.
- **Why Use It**: Port scanning is a **core** pen test activity—knowing which ports are open and which services are running helps you identify potential exploits. Banner grabbing can sometimes reveal service versions or other info.
- **API Key**: **No**. Pure Python sockets.

---

### 12. **HTTP Header Inspection**

- **Definition/Explanation**: HTTP headers can reveal important information about a web server—like server type (e.g., Apache, Nginx), possible security headers (HSTS, CSP), or cookies.
- **How It Works**: The tool sends a GET request using `requests` and prints the status code and all returned headers. 
- **Why Use It**: Analyzing response headers can inform you if the site enforces HTTPS, uses modern security headers, or inadvertently reveals internal software.
- **API Key**: **No**.

---

### 13. **robots.txt & sitemap.xml Parsing**

- **Definition/Explanation**: `robots.txt` instructs crawlers which URLs/paths are disallowed, while `sitemap.xml` often provides a site’s URL structure. 
- **How It Works**: The tool requests `domain.com/robots.txt` and `domain.com/sitemap.xml`. If found, it prints contents. 
- **Why Use It**: Some **disallowed** paths in robots.txt are exactly the interesting or sensitive areas you want to check. The sitemap can list all publicly available pages. Great for OSINT in a pen test.
- **API Key**: **No**.

---

### 14. **SSL/TLS Certificate Information**

- **Definition/Explanation**: SSL/TLS certificates provide secure communication (HTTPS). The certificate includes info like issuer (CA), expiration date, subject alternative names (SANs), and more.
- **How It Works**: The tool opens a socket on port 443, wraps it in SSL (`ssl.create_default_context()`), retrieves the certificate via `ssock.getpeercert()`.
- **Why Use It**: Checking if a domain has an **expired** or poorly managed certificate can be an immediate red flag. The SAN field might reveal additional subdomains as well.
- **API Key**: **No**.

---

### 15. **DNSSEC Validation (Basic)**

- **Definition/Explanation**: DNSSEC adds cryptographic signatures (like RRSIG, DNSKEY) to DNS records to prevent spoofing or tampering. 
- **How It Works**: The tool queries for RRSIG and DNSKEY records. Finding them means the domain has at least partially implemented DNSSEC.
- **Why Use It**: If DNSSEC is absent, an attacker may attempt DNS spoofing. If DNSSEC is present but misconfigured, that can be another vector of interest in a pen test.
- **API Key**: **No**.

---

### 16. **Parse Webpage Comments**

- **Definition/Explanation**: Developers sometimes leave **HTML comments** in the page source. These can contain leftover credentials, internal URLs, or debugging info.
- **How It Works**: The tool fetches a webpage (`requests`), uses a regex to match `<!-- ... -->` blocks, and prints the contents. 
- **Why Use It**: For pen testers, scanning HTML comments can quickly reveal unexpected secrets or references to test or staging environments.
- **API Key**: **No**.

---

### 17. **Google Dorks**

- **Definition/Explanation**: “Google Dorks” are specialized search queries that can find hidden or sensitive information (like `site:example.com inurl:admin`, `filetype:pdf`, etc.).
- **How It Works**: The toolkit prints a handful of typical dorks for your domain and optionally opens them in your web browser via `webbrowser.open()`.
- **Why Use It**: This is a **classic** OSINT trick—finding publicly exposed content or directories using Google’s indexing. 
- **API Key**: **No**. This relies on standard browser searches, but be mindful of Google’s TOS if you automate.

---

### 18. **Shodan Lookup (KISS Sub-Menu)**

- **Definition/Explanation**: Shodan is a search engine for internet-connected devices. It can reveal open ports, banners, vulnerabilities (CVE-based), or ICS/IoT systems. The “KISS” sub-menu helps you build complex queries, manage alerts, and filter results.
- **How It Works**: The script uses the **`shodan`** Python library along with a **hardcoded** or **user-provided** Shodan API key to execute advanced queries or manage Shodan alerts. The sub-menu allows you to choose a target type (domain, IP, org, net range), add filters (port, vulnerability, etc.), and then run the query in Shodan. 
- **Why Use It**: Shodan is extremely powerful for discovering hosts with known vulnerabilities, open ports, or specific software across the internet. This can quickly expand your recon scope far beyond a single domain or IP.
- **API Key**: **Yes**. You must have a Shodan account and provide a valid API key.

---

## 4. Libraries Used

The Reccy Toolkit relies on the following Python libraries:

1. **`dnspython`** (`dns.resolver`, `dns.reversename`, `dns.zone`, `dns.query`)  
2. **`subprocess`** (to call the system’s `whois` command).  
3. **`requests`** (for HTTP-based tasks, scraping, etc.).  
4. **`BeautifulSoup`** (from `bs4` for parsing HTML).  
5. **`re`** (Python’s regex, e.g., extracting emails or HTML comments).  
6. **`ipaddress`** (for IP validation).  
7. **`tabulate`** (for printing tables).  
8. **`socket`** and **`ssl`** (for custom TCP connections, banner grabbing, SSL certificate checks).  
9. **`webbrowser`** (for opening Google dork queries in a browser).  
10. **`shodan`** (needed for the Shodan-based sub-menu and searches).

---

## 5. Who May Find This Tool Useful?

- **Penetration Testers / Ethical Hackers**: Quickly gather OSINT (DNS, WHOIS, subdomain brute forcing, zone transfers, etc.) in one place.  
- **Bug Bounty Hunters**: Consolidate subdomain discovery, email scraping, Google dorks, Shodan queries, etc., to quickly find potential vulnerabilities.  
- **Blue Team / Security Researchers**: Monitor domain configurations, check DNSSEC, verify SSL certificates, or review email footprints.  
- **System Administrators / DevOps**: Quickly confirm DNS setup, retrieve certificate details, or see if unknown subdomains exist.

In short, **anyone** needing a **broad** recon tool—without learning separate utilities or advanced frameworks—can benefit from The Reccy Toolkit.

---

## 6. Why I Created the Reccy Toolkit

I developed The Reccy Toolkit because:

1. **I needed** a wide diversity of OSINT and recon options (DNS, WHOIS, subdomain brute forcing, etc.) but **didn’t** want to **juggle** multiple disjointed tools.  
2. I was short on time and found frameworks like `recon-ng` too **feature-heavy** for my immediate needs.  
3. I wanted to unify everything into **one** Python script with a **simple** menu, easy **API** integration for Shodan, and direct system calls for WHOIS.

Hence, The Reccy Toolkit is a user-friendly “all in one” script combining the most **common** tasks in reconnaissance.

---

## 7. Conclusion

Whether you’re a seasoned professional or just starting in security, The Reccy Toolkit provides a **unified** interface to perform OSINT and recon tasks:

- DNS queries (A, MX, NS, SOA, DNSSEC, zone transfers, etc.)  
- Basic scanning (port scanning & banner grabbing)  
- Web OSINT (HTTP headers, robots.txt, sitemap.xml, comment parsing)  
- WHOIS & subdomain enumerations  
- Email scraping  
- Google dorks  
- **Shodan** sub-menu for advanced searches (with an API key)

Everything is consolidated into **one** menu-based script, making your recon workflow more **efficient** and **streamlined**. Feel free to extend its functionality, add new checks, or integrate with other OSINT data sources, and enjoy the convenience of one single tool for all your recon needs!
