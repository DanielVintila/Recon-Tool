# Recon Tool: TCP Port Scanner and HTTP Prober
 
A Python reconnaissance tool that scans specified hosts and ports, grabs service banners, and gathers basic metadata from web services. Results are saved as structured JSON and CSV files. It is built with Python's standard networking libraries and does not use external scanners such as Nmap.
 
**Author:** Daniel Vintila
**Built with:** Python 3, requests
 
---
 
## Legal and Ethical Use
 
During development this tool was only run against:
- `nmap.scanme.org`, a host the Nmap Project provides for people to test scanners against (light use only)
- `example.com`, a reserved documentation domain
---
 
## Features
 
- **Command line interface** built with `argparse`
- **Target loading** from a text file, one host per line
- **Flexible port specification**: single ports (`80`), lists (`80,443`), and ranges (`8000-8010`)
- **TCP connect scanning** that classifies each port as open, closed (refused), or closed (timeout)
- **Concurrent scanning** using a thread pool, with a configurable number of workers
- **Banner grabbing** on open ports, storing the first 200 characters of the response (useful for services such as SSH)
- **HTTP and HTTPS probing** on open ports with `--http`, trying HTTP first and falling back to HTTPS. It collects:
  - Requested URL and final URL after redirects
  - Status code
  - Page title and meta description
  - `Server` header
  - Cookie names
  - First 4096 characters of the response body
- **JSON and CSV output** for reports and spreadsheets
- **Graceful error handling**: network errors and failed HTTP requests do not crash the scan
---
 
## Requirements
 
- Python 3.x
- requests
```bash
pip install requests
```
 
---
 
## Usage
 
```bash
python3 recon.py --targets targets.txt --ports 22,80,443,8000-8010 --workers 60 --http --output scan
```
 
| Option | Required | Description |
| --- | --- | --- |
| `--targets` | Yes | Path to a file with one hostname or IP address per line |
| `--ports` | Yes | Ports to scan, as a comma separated list or ranges (for example `80,443,8000-8010`) |
| `--workers` | No | Number of concurrent scan threads (default 20) |
| `--http` | No | Probe open ports for HTTP and HTTPS and extract metadata |
| `--timeout` | No | Per connection timeout in seconds (default 5.0) |
| `--output` | No | File prefix for results. Writes `PREFIX.results.json` and `PREFIX.results.csv` |
| `--tls` | No | Accepted, but currently has no effect. HTTPS fallback happens automatically with `--http` |
 
Example `targets.txt`:
 
```
example.com
nmap.scanme.org
```
 
---
 
## Example Output
 
Terminal output shows the status of each port as it is scanned:
 
```
nmap.scanme.org:22   OPEN
nmap.scanme.org:443   CLOSED (refused)
```
 
The JSON file groups results by host. An open SSH port with a banner:
 
```json
{
  "port": 22,
  "status": "open",
  "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
}
```
 
A closed port with the reason it failed:
 
```json
{
  "port": 443,
  "status": "closed",
  "banner": null,
  "reason": "refused"
}
```
 
An open web port with HTTP metadata (body sample shortened here):
 
```json
{
  "port": 80,
  "status": "open",
  "banner": null,
  "service_hint": "http",
  "http": {
    "url": "http://nmap.scanme.org:80/",
    "final_url": "http://nmap.scanme.org:80/",
    "status_code": 200,
    "title": "Go ahead and ScanMe!",
    "server_header": "Apache/2.4.7 (Ubuntu)",
    "cookies": []
  }
}
```
 
The CSV file has one row per host and port with these columns: host, port, status, reason, banner, service_hint, http_url, http_final_url, http_status_code, http_title, http_meta_description, http_server_header.
 
---
 
## Project Files
 
| File | Description |
| --- | --- |
| `recon.py` | The scanner |
| `targets.txt` | Example target list |
| `scan.results.json` | Example JSON results from a test scan |
| `scan.results.csv` | Example CSV results from the same scan |
 
---
 
## Limitations
 
- Only TCP connect scans over IPv4 are supported. There is no SYN scanning or UDP scanning.
- A timeout is reported as "closed", but it often means the port is filtered by a firewall.
- The banner grabber waits for the service to send data first, so web servers and other services that stay silent show no banner.
- Targets must be a hostname or IP address only. The `host:port` format is not supported.
- Title and meta description are extracted with regular expressions, so unusual HTML can be missed.
- TLS certificate analysis, service fingerprinting, and favicon hashing are not implemented.
---
 
## What I Learned
 
This project had a steep learning curve. I researched the socket, concurrent.futures, and requests libraries to understand how the provided code worked, and I spent a long time debugging the JSON and CSV output before the structure came out correctly. It taught me how port scanning works at the socket level, how to run network tasks concurrently, and how to turn raw scan data into structured reports.
 
---
 
## Acknowledgements
 
- The core scanning functions (`parse_port_spec`, `probe_tcp`, `grab_banner_tcp`, `scan_host`, and the `argparse` setup) were provided by my lecturer, Mark Cummins, in class labs at SETU.
- `load_targets`, `probe_http`, and the HTTP probing logic were written with help from ChatGPT. Integration, testing, and the JSON and CSV output were done by me.
Created as coursework for a Cybercrime and IT Security degree at South East Technological University (SETU).
