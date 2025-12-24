# 
from bcc import BPF
b = BPF(src_file='disksnoop.c')

def print_event(cpu, data, size):
    # data是一个int， 感觉跟fd很像
    event = b["events"].event(data)
    print()
    print('-'*32)
    print('进程id:', event.pid)
    print('字节数:', event.bytes)
    print('读写标志:', event.rwbs)
    print('进程名称:', event.prog_name)
    time = (event.ok_time - event.begin_time) / 1000
    print('耗费时间(微秒):', time)
    print('-'*32)
    print()

# 从管道events中获取数据，注册回调函数
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print('程序已退出！')
        exit()