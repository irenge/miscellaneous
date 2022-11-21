#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Copyright 2022
# Licensed under the Apache License, Version 2.0 (the "License")

#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import argparse
import signal
from time import strftime

#arguments
examples = """examples:
    ./madvsnoop           # trace all madvise() signals
    ./madvsnoop -p 4086    # only trace PID 4086
"""
parser = argparse.ArgumentParser(
    description="Trace signals issued by the madvise() syscall",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-x", "--failed", action="store_true",
    help="only show failed madvise syscalls")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
#parser.add_argument("-s", "--signal",
 #   help="trace this signal only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0


# define BPF program
bpf_text = """

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct val_t {
        u64 pid;
        int start;
        int length;
        int behaviour;
        char comm[TASK_COMM_LEN];
        };
struct data_t {
        u64 pid;
        int start;
        int length;
        int behaviour;
        char comm[TASK_COMM_LEN];
        int ret;
        };
BPF_HASH(infotmp, u32, struct val_t);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_madvise) {
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;
u32 tid = (u32) pid_tgid;

PID_FILTER

struct val_t val = {.pid = pid};

if(bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.start = args->start;
        val.length = args->len_in;
        val.behaviour = args->behavior;

        infotmp.update(&tid, &val);
        }
        return 0;
        }
TRACEPOINT_PROBE(syscalls, sys_exit_madvise) {
struct data_t data = {};
struct val_t *valp;
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid >> 32;
u32 tid = (u32) pid_tgid;

valp = infotmp.lookup(&tid);
if(valp == 0) {
//missed entry
return 0;
}
bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
data.pid = pid;
data.start = valp->start;
data.length = valp->length;
data.behaviour = valp->behaviour;
data.ret =  args->ret;
void *ctx = args;

events.perf_submit(ctx, &data, sizeof(data));

return 0;

        }
"""

if args.pid:
    bpf_text = bpf_text.replace('PID_FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('PID_FILTER', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


# initialize BPF
b = BPF(text=bpf_text)

print("%-9s %-6s %-16s %-16s %-9s %-9s %3s" % (
    "TIME", "PID", "COMM", "START", "LENGTH", "BEHAVIOUR", "RESULT"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    if (args.failed and (event.ret >= 0)):
        return

    printb(b"%-9s %-6d %-16s %-16d %-9d %-9d %3d" % (strftime("%H:%M:%S").encode('ascii'),
        event.pid, event.comm, event.start, event.length, event.behaviour, event.ret))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()


