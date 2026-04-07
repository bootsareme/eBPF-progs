# Usage: sudo python3 firewall_demo-harness.py [interface you want to filter]
# Run this in the background or a concurrent shell to test that it actually works

from bcc import BPF
import sys

# load function from corresponding BPF file
bpf = BPF(src_file="../kern/firewall_demo.bpf.c")
fw_block_ipaddr = bpf.load_func("fw_block_ipaddr", BPF.XDP)

# attach to network interface the function that will be monitoring it
bpf.attach_xdp(sys.argv[1], fw_block_ipaddr)
print(f"XDP firewall attached to {sys.argv[1]}")

try:
    while True:
        bpf.trace_print() 
except KeyboardInterrupt:
    bpf.remove_xdp(sys.argv[1], 0)
    print(f"\nXDP firewall detached from {sys.argv[1]}")
