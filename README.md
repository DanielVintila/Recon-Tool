# Assignment-2 Recon Tool 

## Project overview:
Recon Tool is a Python network reconnaissance tool designed to perform automated scans on specified hosts and ports. It's main goal is to gather structured information about network services, such as HTTP/HTTPS without using external tools like Nmap.

This tool allows a user to:
- Perform TCP connect scans to detect open or closed ports.
- Grab banners from open ports to detect service software used.
- Probe HTTP and HTTPS services, and extract key metadata such as HTML title, server headers, and a sample of the body page.
- Output results to a structured JSON and CSV format for readability and for reports.
- Run concurrently using multiple workers, with custom timeouts.

This project is a learning and testing tool. Explicit permission has been given for all targets used while building and debugging this tool, as seen in Authorisation.txt inside the repository.
Targets were nmap.scanme.org and example.com

## Libraries used:
- argparse
(Handles command-line arguments).
- socket
(Provides network communications).
- concurrent.futures (Provides and interface for running tasks concurrently using threads or proccesses).
- json
- csv
- requests (High-level HTTP library for sending GET/POST requests).
- re (Regex, used for pattern matching).

## Running the code:
```python3 recon.py --targets targets.txt --ports 80,443,22,8000-8010 --workers 60 --http --output scan```
- --targets targets.txt (is to chose which targets file is to be used).
- --ports (specifies which ports should get scanned).
- --workers (specifies how many tasks to run at the same time).
- --output scan (saved results to a JSON and CSV file).
- --http (http probing on open ports)

## Features:
- Command-Line interface with argparse.

- Target file loading

- Port specification parsing (accepts single ports `80` or multiple ports `80,443` and ranges `8000-8010`)

- TCP Connect Port Scanning
uses TCP connect scans not SYN scanning for each host and port. Attempts a socket connection which detects `open` `closed (refused)` `closed (timeout)`

- Concurrency Scanning 
Uses ThreadPoolExecutor and respects `--workers` value. Scans multiple ports at the same time.

- HTTP/HTTPS Probing 
Recon tool will probe HTTP(S) when the `--http` argument is used. For each open port, it will detect a URL, a final URL after redirection, HTTP status code, HTML title, meta description, server header, and the first 4096 bytes of the body.

- Banner Grabbing
for open ports only, program attempts to read up to 1024 bytes. Works for services like ssh.

- JSON Output
Results are grouped by host, each host contains a list of scanned ports and each port contains status, banner, HTTP metadata.

- CSV Output
Program produces a csv file which can be opened with Excel or other spreadsheet applications. The file produced has one row per host and port, port status, banner, and HTTP metadata where availible.

- Failiure Handling
Network errors will not crash the prgram, closed ports are handles cleanly adnd HTTP failiures return none. 

## Features not implented
- TLS Certificate Alaysis 
- Fingerprint detection 
- Favicon hashing 
- Extras mentioned in the breif

## Project Reflection:
Upon completing this project to the best of my abilities, I found it very difficult as there was a steep learning curve. I struggled a lot with understanding the code provided as I had to research different functions and libraries. I had great difficulty with the JSON and CSV format and got stuck in a loop where my JSON file was outputting everything incorrectly. However, it was a tough but fun challenge and I learned a lot from it.

# References:
```python
def parse_port_spec(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)
```
```python
def probe_tcp(host, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return (port, True, None)
    except socket.timeout:
        return (port, False, "timeout")
    except ConnectionRefusedError:
        return (port, False, "refused")
    except Exception as e:
        return (port, False, str(e))
```
```python
def grab_banner_tcp(host, port, timeout=2.0, send_bytes=None, read_size=1024):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((host, port))
        if send_bytes:
            s.sendall(send_bytes)
        try:
            data = s.recv(read_size)
            banner += data.decode(errors='replace')
        except socket.timeout:
            pass
        s.close()
        return True, banner.strip()[:1000]
    except Exception as e:
        return False, str(e)
```
```python
def scan_host(host, ports, workers, timeout):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda x: x[0])
```
```python
def parse_args():
    parser = argparse.ArgumentParser(
        description ="Example argparse parser for network scanning flags"
    )
...
```
## The code above was provided to me by Mark Cummins and was given to me in the labs that we done in class. 

```python
def load_targets(path):
    targets = []
    try:
        with open(path, "r") as f: #Open targets file as read 
            for line in f:
                lines = line.strip() 
                if lines:
                    targets.append(lines)
        return targets #return the list of targets
    except Exception as e:
        print(f"Error reading targets file: {e}")
    return []
```
```python
def probe_http(host, port, timeout=5.0, use_tls=False):
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects = True
        )
        body = r.text or ""

        #extracting title from HTML with regex
        title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE| re.DOTALL)
        title = title_match.group(1).strip() if title_match else None
        
        #extracting description 
        meta_match = re.search(
            r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']',
            body,
            re.IGNORECASE
        )
```
```python
            if args.http: #checking if you use --http
                http_data = None
                scheme = None
                http_data = probe_http(host, port, timeout=args.timeout, use_tls=False)
                if http_data: #first try with http
                    scheme = "http"
                else: #if http failes try https 
                    http_data = probe_http(host, port, timeout=args.timeout, use_tls=True)
                    if http_data:
                        scheme = "https"
         
                if http_data: #if http data found then save it in result_entry
                    result_entry["service_hint"] = "http"
                    result_entry["http"] = http_data
            host_results.append(result_entry) #append the port's result to the host result
        all_results[host] = host_results
```
## The code above was written with help from ChatGPT, integration and testing was done independently.