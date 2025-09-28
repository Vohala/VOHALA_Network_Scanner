#!/usr/bin/env python3
# Vohala Network Scanner v1.7

import subprocess
import socket
import concurrent.futures
import ipaddress
import shutil
import os
import json


BRAND = "VOHALA"
PRODUCT = "Network Scanner"
VERSION = "v1.7"
ORG = "Vohala Cybersecurity Labs"

PREDEFINED_NETWORKS = [
    "192.168.1.0/24",
    "192.168.0.0/24",
    "192.168.100.0/24"
]

PORTS = [
    21,22,23,25,53,80,110,135,139,143,443,445,
    3389,5357,8080,8443
]
MAX_WORKERS = 120

OUI_LOCAL_FILE = "oui_prefixes.json"
OUI_FALLBACK = {
    "0001C0": "Hewlett-Packard",
    "0003F8": "Hewlett-Packard",
    "00085D": "Dell",
    "001A2B": "Dfell",
    "F0D5BF": "Dell",
    "00265E": "Lenovo",
    "EC8EAD": "Lenovo",
    "3C5A37": "ASUSTek",
    "B4A9FC": "ASUSTek",
    "84A134": "Samsung",
    "F8E61A": "Samsung",
    "B827EB": "Raspberry Pi",
    "D85D4C": "Xiaomi",
    "A4B197": "Apple",
    "F0D1A9": "Apple",
    "BC929B": "OnePlus",
    "18C04D": "HP Inc.",
    "A0A36E": "Realtek",
}

RESET  = "\033[0m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
WHITE  = "\033[97m"

def term_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def center(text):
    w = term_width()
    return "\n".join(line.center(w) for line in text.splitlines())

def try_pyfiglet(text):
    try:
        from pyfiglet import Figlet
        f = Figlet(font="ANSI Shadow")
        return f.renderText(text)
    except Exception:
        return None

def try_figlet_bin(text):
    try:
        out = subprocess.check_output(["figlet", "-f", "standard", text])
        return out.decode("utf-8", "ignore")
    except Exception:
        return None

def banner():
    os.system("clear")
    art = try_pyfiglet(BRAND) or try_figlet_bin(BRAND)
    if art:
        print(CYAN + center(art) + RESET)
    else:
        
        box = f" {BRAND} "
        line = "═" * (len(box))
        print(CYAN + center(f"╔{line}╗\n║{box}║\n╚{line}╝") + RESET)
    print(center(f"{BOLD}{WHITE}{BRAND} {PRODUCT} {VERSION}{RESET}"))
    print(center(f"{DIM}{ORG}{RESET}\n"))

def udp_nudge(ip, port=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.05)
        s.sendto(b"x", (ip, port))
        s.close()
    except:
        pass

def read_arp_table():
    """Return dict {ip: mac} from /proc/net/arp"""
    table = {}
    try:
        with open("/proc/net/arp", "r") as f:
            next(f)  
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip, mac = parts[0], parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        table[ip] = mac
    except:
        pass
    return table

def mac_for_ip(ip):
    return read_arp_table().get(ip)

def ping(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except:
        return False

def tcp_check(ip, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except:
        return False

def nmb_has_name(ip):
    try:
        out = subprocess.check_output(["nmblookup", "-A", ip],
                                      stderr=subprocess.DEVNULL, text=True)
        return "<00>" in out
    except:
        return False

def resolve_hostname(ip):
    
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
   
    try:
        out = subprocess.check_output(["nmblookup", "-A", ip],
                                      stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            L = line.strip()
            if "<00>" in L and "group" not in L.lower():
                name = L.split()[0]
                if name and name != "name_query":
                    return name
    except:
        pass
    return "-"

def is_alive(ip):
    
    udp_nudge(ip)
    if mac_for_ip(ip):
        return True
    
    if ping(ip):
        return True
    
    for p in PORTS:
        if tcp_check(ip, p):
            return True
    
    if nmb_has_name(ip):
        return True
    
    if mac_for_ip(ip):
        return True
    return False

def load_oui_map():
    m = OUI_FALLBACK.copy()
    try:
        if os.path.isfile(OUI_LOCAL_FILE):
            with open(OUI_LOCAL_FILE, "r") as f:
                data = json.load(f)
                
                for k, v in data.items():
                    m[k.upper().replace(":", "").replace("-", "")[:6]] = v
    except Exception:
        pass
    return m

OUI_MAP = load_oui_map()

def vendor_from_mac(mac):
    if not mac:
        return "-"
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return OUI_MAP.get(prefix, "Unknown")


def menu():
    print(center(f"{YELLOW}Select a network to scan:{RESET}"))
    for i, net in enumerate(PREDEFINED_NETWORKS, 1):
        print(center(f"{CYAN}{i}. {net}{RESET}"))
    print(center(f"{CYAN}{len(PREDEFINED_NETWORKS)+1}. Enter custom network{RESET}"))
    print()
    choice = input(f"{GREEN}Enter choice: {RESET}").strip()
    try:
        n = int(choice)
        if 1 <= n <= len(PREDEFINED_NETWORKS):
            return PREDEFINED_NETWORKS[n-1]
        elif n == len(PREDEFINED_NETWORKS)+1:
            return input(f"{GREEN}Enter custom (e.g. 192.168.1.0/24): {RESET}").strip()
    except:
        pass
    print(f"{YELLOW}Using default: {PREDEFINED_NETWORKS[0]}{RESET}")
    return PREDEFINED_NETWORKS[0]

def header():
    print()
    cols = f"{'IP':<16}{'Hostname / Windows Name':<32}{'MAC':<18}{'Vendor':<16}{'Open Ports'}"
    print(CYAN + cols + RESET)
    print("-" * min(term_width(), 100))


def main():
    banner()
    network = menu()
    try:
        net = ipaddress.ip_network(network, strict=False)
    except:
        print(f"{YELLOW}Invalid network, defaulting to 192.168.1.0/24{RESET}")
        net = ipaddress.ip_network("192.168.1.0/24", strict=False)

    header()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(is_alive, str(ip)): str(ip) for ip in net.hosts()}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            if fut.result():
                mac = mac_for_ip(ip)  
                vend = vendor_from_mac(mac) if mac else "-"
                name = resolve_hostname(ip)
                
                open_ports = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex2:
                    for port, ok in zip(PORTS, ex2.map(lambda p: tcp_check(ip, p), PORTS)):
                        if ok: open_ports.append(port)
                ports_s = ",".join(map(str, open_ports)) if open_ports else "-"
                print(f"{GREEN}{ip:<16}{RESET}{name:<32}{(mac or '-'):<18}{vend:<16}{ports_s}")

if __name__ == "__main__":
    main()
