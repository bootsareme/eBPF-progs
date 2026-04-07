# eBPF-progs
A collection of eBPF programs that occasionally do what you want. To get started:

1. Read and understand the [purpose](https://ebpf.io/what-is-ebpf/) of eBPF.
2. Make sure your environment meets the system requirements listed below.
3. https://github.com/iovisor/bcc/blob/master/INSTALL.md
4. `sudo python3 user/specific_prog_harness.py`
5. Should there be any additional instructions, they will be spelled out in the harness script comments.
6. Explanations of the eBPF code itself will live in the source (not harness) comments.

## System Requirements

- Linux (Debian, Fedora, Arch, Ubuntu, Kali, ...*any modern kernel would suffice, userspace should not matter except in rare cases*...)
- Python 3 (popular distros should have by default)

## Suggested Use Case
These standalone eBPF programs are quick utilities and not ready for production. Do not use it on any system that you care. The recommended approach is to create a Linux virtual machine with the correct kernel version and test all of it there. 

## Contributing
Please submit issues on what type of eBPF programs you would like to see get added. Feel free to add a written program yourself. You should put your `progname.bpf.c` in `kern/` and `progname_harness.py` in `user/`. This will keep the format consistent for the entire repository.