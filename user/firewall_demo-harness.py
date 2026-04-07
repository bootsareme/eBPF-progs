# Usage: sudo python3 firewall_demo-harness.py [interface you want to block]
# Run this in the background or a concurrent shell to test that it actually works

from bcc import BPF
import socket
import sys

# load function from corresponding BPF file
bpf = BPF(src_file="../kern/firewall_demo.bpf.c")
func = bpf.load_func("fw_block_ip", BPF.XDP)

idx = socket.if_nametoindex(sys.argv[1])
bpf.attach_xdp(idx, fn)
print(f"XDP firewall attached to {sys.argv[1]}")

try:
    while True:
        pass
except KeyboardInterrupt:
    bpf.remove_xdp(idx, 0)
    print(f"XDP detached from {sys.argv[1]}")