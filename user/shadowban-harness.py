from bcc import BPF

# attach to syscall entry
bpf = BPF(src_file="../kern/shadowban.bpf.c")
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="shadowban")
print("[*] Blocking all access to /etc/shadow (including root)...")
print("[*] Watching /sys/kernel/debug/tracing/trace_pipe...")

try:
    while True:
        bpf.trace_print()
except KeyboardInterrupt:
    print("\n[+] Detached")
