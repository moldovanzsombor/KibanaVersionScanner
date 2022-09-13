#!/usr/bin/python3

# Basically stolen from:
# https://github.com/LandGrey/CVE-2019-7609

# Tested on targets found on shodan.io
# Tested with versions 4.X.X -> 8.4.1
# Do not exploit targets you are not allowed to test!
# Shodan Dork:
# port:5601 kibana

# Search for kibana vulnerabilities:
# https://www.cvedetails.com/google-search-results.php?q=kibana&sa=Search


import os
import socket
import sys
import requests
import re
requests.packages.urllib3.disable_warnings()

cg = "\033[92m" # green
cr = "\033[91m" # red
nc = "\033[0m"  # nocolor

def usage():
    print("scanner.py *[target/targetfile] (-t TIMEOUT) (-h/--help)")
    print("target (positional) must be an IP address or HOST ")
    sys.exit()


def get_version(host, timeout):

    url = f"http://{host}:5601/app/kibana"

    headers = {
        "Referer": url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    }

    try:
        r = requests.get(url, verify=False, headers=headers, timeout=timeout, allow_redirects=True)

        if version := re.findall("&quot;version&quot;:&quot;(.*?)&quot;,", r.content.decode("utf-8")):
            return f"Target: {url}\nVersion: {cg}{version[0]}{nc}\n"
        elif version := re.findall('"version":"(.*?)",', r.content.decode("utf-8")):
            return f"Target: {url}\nVersion: {cg}{version[0]}{nc}\n"
        elif version := r.headers['kbn-version']:
            return f"Target: {url}\nVersion: {cg}{version}{nc}\n"

    except KeyError: # Except version detection from response headers
        return f"Target: {url}\nVersion: {cr}unknown{nc}\n"

    except KeyboardInterrupt:
        print("\nKeyboardInterrupt, Exiting")
        sys.exit()

    except Exception as e:
        print(f"Exception with {url}:\n" + str(e))
        return ""


if __name__ == "__main__":
    if len(sys.argv) <= 1 or "-h" in sys.argv or "--help" in sys.argv:
        usage()

    try:
        target = sys.argv[1]
        timeout = 5 if "-t" not in sys.argv else int(sys.argv[sys.argv.index("-t") + 1])
    except:
        usage()

    if os.system("ping -c 1 " + target + " >/dev/null 2>&1") == 0:
        print(get_version(target, timeout))

    else:
        targets = open(target, "r")

        for i in targets.readlines():
            i = i.replace("\n", "")

            print(get_version(i, timeout))

