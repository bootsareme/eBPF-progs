/*
   This program will block any user (including root) from accessing /etc/shadow.
   Just replace the path to block any other file you want.
*/

#include <linux/signal.h>

int shadowban(struct tracepoint__syscalls__sys_enter_openat *ctx)
{
    char filepath[16];
    bpf_probe_read_user_str(filepath, sizeof(filepath), (const char *)ctx->filename);

    const char target[] = "/etc/shadow";
    bool match = true;

#pragma unroll
    for (unsigned i = 0; i < sizeof(target); i++) {
        if (filepath[i] != target[i]) {
            match = false; // mismatching character, file path could not possibly be target
            break;
        }
    }

    if (match) {
        u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        // deny access regardless of UID (even root)
        bpf_send_signal(SIGKILL);
        bpf_trace_printk("blocked UID=%d from accessing '%s' by killing PID=%d\n", uid, target, pid);
    }

    return 0;
}
