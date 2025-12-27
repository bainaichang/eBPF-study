from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep

# 监听用户态 strlen() 函数的调用。

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
""")

"""
不能直接监听strlen
查看libc中strlen的符号信息: nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep strlen
out: 00000000000a86a0 i strlen@@GLIBC_2.2.5
     虚拟地址        i代表间接符号 本质是 “符号别名 / 跳转入口”，无实际执行代码
i 类型的 strlen 是 “符号转发器” —— 它不对应任何可执行的机器码，只是告诉链接器：
“当程序调用 strlen 时，实际跳转到另一个真实函数”（比如 __strlen_avx2/__strlen_sse2）。

# 反汇编libc的.text段（执行代码段），查找strlen地址的指令
objdump -d /lib/x86_64-linux-gnu/libc.so.6 -j .text | grep -A 10 "a86a0 <strlen>"

通过查看反汇编的代码得知挂载函数名
"""
b.attach_uprobe(name="/lib/x86_64-linux-gnu/libc.so.6", sym="__strlen_avx2", fn_name="count")
# b.attach_uprobe(name="c", sym="strlen", fn_name="count")

# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b"%10d \"%s\"" % (v.value, k.c))