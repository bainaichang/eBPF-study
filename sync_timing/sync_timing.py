# 检测系统的sync调用功能，如果两次调用间隔少于1秒就输出
from bcc import BPF
b = BPF(src_file='sync_timing.c')
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    delta:float = event.delta / 1_000_000_000
    print(f"触发2次sync间隔小于1秒, 间隔: {delta:.2f}ms")


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print('程序已退出！')
        exit()