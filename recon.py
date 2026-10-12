import argparse
import socket 
import concurrent.futures
import json
import csv
import requests 
import re

#function for reading targets file
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

#function for parsing ports
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

#probes specifed ports to check status
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

#banner grabber 
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
    
#http banner grabber
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
            
        
        meta_desciption = meta_match.group(1).strip() if meta_match else None
        #returning structured dictionary for relevent information
        return{
            "url": url,
            "final_url": r.url,
            "status_code": r.status_code,
            "title": title,
            "meta_description": meta_desciption,
            "server_header": r.headers.get("Server"),
            "cookies": list(r.cookies.keys()),
            "body_sample": body[:4096]                                                           
        }
    except Exception:
        return None


#multithread scanner 
#uses a thread pool to scan multiple ports at the same time
def scan_host(host, ports, workers, timeout):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futures = {exe.submit(probe_tcp, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda x: x[0]) #return the results sorted by port number 

#function for adding arguments when running the program 
def parse_args():
    parser = argparse.ArgumentParser(
        description ="Example argparse parser for network scanning flags"
    )

    parser.add_argument(
        "--targets",
        required=True,
        help="Path to file (one host per line; allow host or host:port)",
    )

    parser.add_argument(
        "--ports",
        required=True,
        help="Comma list or ranges (e.g., 80,443,8000-8010)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Concurrent TCP workers (default 20)",
    )

    parser.add_argument(
        "--http",
        action="store_true",
        help="Probe HTTP(s) services and extract title, meta description, Server header",
    )

    parser.add_argument(
        "--tls",
        action="store_true",
        help="Attempt TLS retreival for ports that speak TLS",
    )

    parser.add_argument(
        "--output",
        help="Path prefix for results; tool writes PREFIX.results.json and PREFIX.results.csv",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-connection timeout in seconds (float OK)",
    )
    
    return parser.parse_args()


def main():
    #printing out formatted lines inside the terminal
    args = parse_args() #parse the command line arguments
    print("Arguments Received:")
    print(f"    targets : {args.targets}")

    ports = parse_port_spec(args.ports) #parse the ports string
    print(f"    ports   : {ports}")
    print(f"    workers : {args.workers}")
    print(f"    http    : {args.http}")
    print(f"    tls     : {args.tls}")
    print(f"    output  : {args.output}")
    print(f"    timeout : {args.timeout}")

    targets = load_targets(args.targets)
    print("\nLoaded targets:")
    for t in targets:
        print(" -", t)
        print()

    final_result = {}
    all_results = {}

#iterate over each host
    for host in targets:
        print(f"Scanning {host} ...")
        print()
        results = scan_host(host, ports, args.workers, args.timeout)
        host_results = []

        for port, is_open, reason in results:
            result_entry = {
                "port": port,
                "status": "open" if is_open else "closed",
                "banner": None
            }
        
            if not is_open:
                result_entry["reason"] = reason
                host_results.append(result_entry)
                print(f"{host}:{port}   CLOSED ({reason})")
                continue

            print(f"{host}:{port}   OPEN")
            success, banner = grab_banner_tcp(host, port, timeout=args.timeout)
            if success and banner:
                result_entry["banner"] = banner[:200]
                '''
                checks if a banner was taken, if yes, the program stores the first 200 characters
                inside of result_entry
                '''
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

    #opening and saving results to a json file
    if args.output: #if --output is used then save the data to a json file 
        json_file = f"{args.output}.results.json"
        with open (json_file, "w") as f:
            json.dump(all_results, f, indent=2)
            print(f"Results saved to {json_file}")

    #opening and saving results to a csv file 
    csv_file = f"{args.output}.results.csv"
    with open(csv_file, "w") as f:
        writer = csv.writer(f)
        #adding rows to the csv file
        writer.writerow(["host", "port", "status", "reason", "banner",
        "service_hint", "http_url", "http_final_url",
        "http_status_code", "http_title", "http_meta_description",
        "http_server_header"
        ])

        for host, host_results in all_results.items():
            for entry in host_results:
                http_info = entry.get("http", {})
                writer.writerow([
                    #adding entries to the rows
                    host,
                    entry.get("port"),
                    entry.get("status"),
                    entry.get("reason", ""),
                    entry.get("banner", ""),
                    entry.get("service_hint", ""),
                    http_info.get("url", ""),
                    http_info.get("final_url", ""),
                    http_info.get("status_code", ""),
                    http_info.get("title", ""),
                    http_info.get("meta_description", ""),
                    http_info.get("server_header", "")
                ])
    print(f"Results saved to {csv_file}")


if __name__ == "__main__":
    main()
