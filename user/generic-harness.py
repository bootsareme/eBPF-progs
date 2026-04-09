from bcc import BPF
import sys

bpf = BPF(src_file=sys.argv[1])
print(f"eBPF program passed verification, now successfully running in kernel space...")
bpf.trace_print()
