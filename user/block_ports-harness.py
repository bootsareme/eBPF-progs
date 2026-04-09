# Usage: sudo python3 block_ports-harness.py [interface] <list> <of> <ports> <to> <block>
from bcc import BPF
import sys
import ctypes

bpf = BPF(src_file="../kern/block_ports.bpf.c")
func = bpf.load_func("fw_block_ports", BPF.XDP)

iface = sys.argv[1]
bpf.attach_xdp(iface, func, 0)

table = bpf.get_table("blocked_ports")
for port in sys.argv[2:]:
    key = ctypes.c_ushort(int(port))
    table[key] = ctypes.c_ubyte(1) # map lookup will see the port should be blocked

print(f"[+] Port blocker attached to {iface}")
print(f"[+] Blocking ports: {sys.argv[2:]}")

try:
    bpf.trace_print()
except KeyboardInterrupt:
    print("\n[-] Detaching...")
    bpf.remove_xdp(iface, 0)
