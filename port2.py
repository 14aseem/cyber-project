

import argparse
import socket
import sys
import csv
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

def parse_ports(spec: str) -> List[int]:
    """Parse port spec like '22,80,1000-1010' into sorted unique list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a_i, b_i = int(a), int(b)
                if a_i > b_i:
                    a_i, b_i = b_i, a_i
                for p in range(max(1, a_i), min(65535, b_i) + 1):
                    ports.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def grab_banner(sock: socket.socket, timeout: float = 0.6) -> str:
    """Try to provoke a short banner and return decoded text."""
    try:
        sock.settimeout(timeout)
        try:
            sock.sendall(b"\r\n")
        except Exception:
            pass
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""

def scan_one(target: str, port: int, timeout: float = 1.0, do_banner: bool = True) -> Dict:
    """Attempt TCP connect. Return result dict for CSV/printing."""
    t0 = time.time()
    status = "closed"
    banner = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((target, port))
        if rc == 0:
            status = "open"
            if do_banner:
                banner = grab_banner(s)
        s.close()
    except socket.gaierror:
        status = "host_error"
    except Exception:
        status = "error"
    return {
        "timestamp": now_iso(),
        "host": target,
        "port": port,
        "status": status,
        "banner": banner.replace("\n", " ").replace("\r", " "),
        "duration_s": round(time.time() - t0, 3)
    }

def run_scan(target: str, ports: List[int], threads: int, timeout: float, do_banner: bool, quiet: bool) -> List[Dict]:
    results = []
    if not ports:
        return results
    total = len(ports)
    start = time.time()
    workers = min(threads, total)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = { ex.submit(scan_one, target, p, timeout, do_banner): p for p in ports }
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                res = fut.result()
            except Exception:
                port = futures.get(fut)
                res = {"timestamp": now_iso(), "host": target, "port": port, "status":"error", "banner":"", "duration_s":0.0}
            results.append(res)
            if not quiet and (done % max(1, total//20) == 0 or done == total):
                elapsed = time.time() - start
                print(f"Progress: {done}/{total} ports — elapsed {int(elapsed)}s")
    if not quiet:
        print(f"Scan finished in {int(time.time()-start)}s")
    return results

def save_csv(results: List[Dict], filename: str):
    keys = ["timestamp","host","port","status","banner","duration_s"]
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in keys})
        print(f"Saved CSV: {filename}")
    except Exception as e:
        print("Failed to save CSV:", e)

def print_summary(results: List[Dict]):
    total = len(results)
    open_ports = [r for r in results if r.get("status") == "open"]
    print("---- Summary ----")
    print(f"Scanned: {total} ports, Open: {len(open_ports)}")
    for r in sorted(open_ports, key=lambda x: x["port"]):
        b = r.get("banner","")
        bshort = (b[:60] + "...") if len(b) > 60 else b
        print(f" - {r['host']}:{r['port']}  banner='{bshort}'")

def build_parser():
    p = argparse.ArgumentParser(description="Compact concurrent TCP port scanner")
    p.add_argument("--target","-t", required=True, help="Hostname or IP to scan")
    p.add_argument("--ports","-p", default="22,80,443", help="Ports spec, e.g. '1-100,443,8080'")
    p.add_argument("--threads","-T", type=int, default=50, help="Max concurrent workers")
    p.add_argument("--timeout","-o", type=float, default=1.0, help="Socket timeout seconds")
    p.add_argument("--no-banner", action="store_true", help="Disable banner reading")
    p.add_argument("--csv","-c", default="compact_scan.csv", help="CSV output filename")
    p.add_argument("--quiet","-q", action="store_true", help="Less progress output")
    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        resolved = socket.gethostbyname(args.target)
        print(f"Target {args.target} -> {resolved}")
    except Exception:
        print("Failed to resolve target. Try an IP or check DNS.")
        sys.exit(1)
    ports = parse_ports(args.ports)
    if not ports:
        print("No valid ports parsed. Exiting.")
        sys.exit(1)
    print(f"Scanning {args.target} on {len(ports)} ports (threads={args.threads})")
    results = run_scan(args.target, ports, args.threads, args.timeout, not args.no_banner, args.quiet)
    save_csv(results, args.csv)
    print_summary(results)

if __name__ == "__main__":
    print("Reminder: scan only hosts you own or have permission to test (e.g., localhost or scanme.nmap.org).")
    main()
