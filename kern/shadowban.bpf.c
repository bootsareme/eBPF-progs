/*
   This program will block any user (including root) from accessing /etc/shadow.
   Just replace the path to block any other file you want.

   Use the command "sudo python3 user/generic-harness.py kern/shadowban.bpf.c" to run it.
*/

#include <linux/signal.h>

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    char filename[256]; // kernel buffer since filename comes from userspace
    bpf_probe_read_user_str(filename, sizeof(filename), args->filename /* comes from userspace */);
    const char protected[] = "/etc/shadow";

#pragma unroll
    for (unsigned i = 0; i < sizeof(protected); i++)
        if (filename[i] != protected[i])
            goto _not_protected_file; // mismatching character, file path could not possibly be target

    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // deny access regardless of UID (even root)
    bpf_send_signal(SIGKILL);
    bpf_trace_printk("Blocked UID=%d from accessing '%s' by killing PID=%d\n", uid, protected, pid);

_not_protected_file:
    return 0;
}
