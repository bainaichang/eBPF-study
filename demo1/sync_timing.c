#include <linux/sched.h>
#include <uapi/linux/ptrace.h>


struct data_t {
    u64 delta;
};

BPF_HASH(last);
BPF_PERF_OUTPUT(events);

int do_trace(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 key = 0; // 用来获取调用时间戳的key值
    u64 *last_time = 0; // 用来获取调用的value
    last_time = last.lookup(&key); // *u64 lookup(*u64 key);
    if (last_time != NULL) {
        u64 now_time = bpf_ktime_get_ns(); // 获取的时间戳是内核启动到现在的纳秒数
        u64 delta = now_time - *last_time;
        if (delta < 1000000000) { // 小于1秒的情况
            data.delta = delta;
            events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    u64 ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}