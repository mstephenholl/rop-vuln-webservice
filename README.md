# ROP-Vulnerable Webservice for BeagleBone Black Rev C

An educational C++ webservice targeting the BeagleBone Black Rev C (ARM Cortex-A8, Ubuntu 16.04) that:

- Exposes processor temperature via HTTP
- Computes Pi digits under sustained CPU load (Rabinowitz-Wagon spigot algorithm)
- Controls the 4 user LEDs based on thermal thresholds
- Contains **intentionally vulnerable** POST endpoints for demonstrating ARM32 ROP chain attacks

> **WARNING:** This software is intentionally vulnerable and must only be used in isolated educational environments. Never expose it to untrusted networks.

## Required Tools

### Linux (x86_64 / Debian-based)

```bash
# Build tools and cross-compiler
sudo apt update
sudo apt install build-essential gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# GDB with ARM support
sudo apt install gdb-multiarch

# checksec (verify binary protections)
sudo apt install checksec

# ROPgadget (find ROP gadgets in binaries)
pip install ROPgadget

# pwntools (exploit development framework)
pip install pwntools

# curl (send HTTP requests / deliver payloads)
sudo apt install curl
```

### macOS

```bash
# Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# ARM cross-compiler toolchain
brew install arm-linux-gnueabihf-binutils
brew install osx-cross/arm/arm-linux-gnueabihf-gcc

# checksec
brew install checksec

# ROPgadget
pip install ROPgadget

# pwntools
pip install pwntools

# GDB (note: lldb is the default macOS debugger; GDB requires code-signing)
brew install gdb

# curl (pre-installed on macOS, but can be updated)
brew install curl
```

### Tool Summary

| Tool | Purpose |
|------|---------|
| `gcc` / `g++` (ARM cross-compiler) | Compile the vulnerable binary for ARM32 |
| `gdb` / `gdb-multiarch` | Debug the service, catch crashes, inspect registers and stack |
| `checksec` | Verify binary protections are disabled (no RELRO, no canary, NX off, no PIE) |
| `ROPgadget` | Scan the binary for usable ROP gadgets (`pop {r0, pc}`, etc.) |
| `pwntools` | Generate cyclic patterns, find crash offsets, craft exploit payloads |
| `curl` | Interact with HTTP endpoints and deliver overflow payloads |

## Building

### Native Build (on BBB)

```bash
make
```

### Cross-Compile (from x86 host)

```bash
sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
make CROSS_COMPILE=arm-linux-gnueabihf-
```

### Safe Build (protections enabled, for comparison)

```bash
make safe
```

## Verifying Binary Properties

```bash
checksec --file=rop-webservice
```

Expected output for the vulnerable build:
```
RELRO           STACK CANARY      NX            PIE
No RELRO        No canary found   NX disabled   No PIE
```

Compare with the safe build:
```bash
checksec --file=rop-webservice-safe
```

## Running

The service requires root for LED sysfs access:

```bash
sudo ./rop-webservice
```

### Disable ASLR (required for reliable ROP exploitation)

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Re-enable after lab:
```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

## HTTP Endpoints

### GET /temperature

Returns processor temperature in Celsius.

```bash
curl http://localhost:8080/temperature
# {"temperature_c": 45.0, "max_safe_c": 105.0}
```

### POST /pi/start

Starts Pi digit computation (CPU-intensive).

```bash
curl -X POST http://localhost:8080/pi/start
# {"status": "started"}
```

**Vulnerable:** Body is `strcpy`'d into a 64-byte stack buffer.

### POST /pi/stop

Stops Pi computation, returns last computed digit and place.

```bash
curl -X POST http://localhost:8080/pi/stop
# {"status": "stopped", "digit": 5, "place": 4231}
```

**Vulnerable:** Body is `sprintf`'d into a 48-byte stack buffer.

### GET /pi/status

Returns current computation progress.

```bash
curl http://localhost:8080/pi/status
# {"running": true, "digit": 3, "place": 1}
```

## LED Behavior

| LED | Function | Behavior |
|-----|----------|----------|
| USR0 | Heartbeat | 500ms on / 500ms off (1 Hz blink) |
| USR1 | Temp low | ON when T > 0°C (always on during operation) |
| USR2 | Temp med | ON when T > 35°C |
| USR3 | Temp high | ON when T > 70°C |

When temperature reaches 98% of max safe (102.9°C), LEDs 1-3 flash in unison at ~3 Hz.

## ROP Educational Notes

### ARM32 Function Prologue/Epilogue

ARM32 functions typically begin and end with:

```asm
; Prologue — saves frame pointer and link register
PUSH    {fp, lr}         ; sp -= 8; [sp] = fp; [sp+4] = lr
ADD     fp, sp, #4       ; fp points to saved lr
SUB     sp, sp, #<size>  ; allocate local variables

; Epilogue — restores and returns
SUB     sp, fp, #4       ; deallocate locals
POP     {fp, pc}         ; restore fp; pop saved lr into pc (return)
```

The saved LR (link register) on the stack is the return address. Overwriting it redirects execution.

### Finding the Offset to Saved LR

1. Start the service under GDB:
   ```bash
   sudo gdb ./rop-webservice
   (gdb) run
   ```

2. In another terminal, send an overflow pattern:
   ```bash
   # Generate a cyclic pattern (install: pip install pwntools)
   python3 -c "from pwn import *; print(cyclic(200))" | \
     curl -X POST -d @- http://localhost:8080/pi/start
   ```

3. GDB will catch the crash. Examine the PC value:
   ```
   (gdb) info registers pc
   (gdb) x/8wx $sp-16
   ```

4. Find the offset:
   ```python
   from pwn import *
   cyclic_find(0x<pc_value>)  # returns offset to saved LR
   ```

### Finding ROP Gadgets

```bash
ROPgadget --binary rop-webservice --thumb
ROPgadget --binary rop-webservice | grep "pop.*pc"
```

Common useful gadgets for ARM32:
- `pop {r0, pc}` — set first argument and jump
- `pop {r0, r1, pc}` — set two arguments and jump
- Address of `system()` in libc for ret2libc

### Buffer Sizes and Expected Offsets

| Endpoint | Function | Buffer | Size | Overflow via |
|----------|----------|--------|------|-------------|
| `/pi/start` | `handle_pi_start` | `config_buf` | 64 bytes | `strcpy` |
| `/pi/stop` | `handle_pi_stop` | `reason_buf` | 48 bytes | `sprintf` |

Exact offsets depend on compiler stack frame layout — use GDB to determine them for your build.

### Proving the Overflow

```bash
# Send 200 bytes to the 64-byte buffer — should crash the server
python3 -c "print('A' * 200)" | curl -X POST -d @- http://localhost:8080/pi/start

# Check server — it should have segfaulted
```

## Development Notes

- On non-BBB hardware, LED operations silently no-op and temperature returns a mock 42.5°C
- The service listens on port 8080 by default
- Ctrl+C (SIGINT) triggers clean shutdown: threads join, Pi stops, LEDs turn off
