#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// 自定义往用户态传输数据的结构体
struct data_t
{
    u32 pid; // 进程id
    u32 bytes; // 请求操作的字节数
    char rwbs[8]; // 读写标志
    char prog_name[TASK_COMM_LEN]; // 调用磁盘的进程名
    u64 begin_time; // 请求开始的时间
    u64 ok_time; // 完成请求的时间
};

BPF_PERF_OUTPUT(events); // 感觉很像管道
BPF_HASH(hashmap, u32, struct data_t);

TRACEPOINT_PROBE(block, block_rq_issue) { // 磁盘请求开始入点
    struct data_t data = {};
    u32 key_dev = args->dev; // 获取 key, 我这里拿设备号当key，并不是很完美
    data.begin_time = bpf_ktime_get_ns();
    data.bytes = args->bytes; // args的字段可以通过sudo cat /sys/kernel/debug/tracing/events/block/block_rq_issue/format查看
    hashmap.update(&key_dev, &data);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) { // 磁盘请求完成入点
    struct data_t data = {};
    struct data_t *last = 0;
    u32 key_dev = args->dev;
    last = hashmap.lookup(&key_dev);
    if (last != 0) {
        data.pid = bpf_get_current_pid_tgid();
        data.bytes = last->bytes;
        bpf_probe_read_kernel_str(data.rwbs, sizeof(data.rwbs), args->rwbs);
        bpf_get_current_comm(&data.prog_name, sizeof(data.prog_name)); // 获取进程名
        data.begin_time = last->begin_time;
        data.ok_time = bpf_ktime_get_ns();
        events.perf_submit(args, &data, sizeof(data));
        hashmap.delete(&key_dev);
    }
    return 0;
}