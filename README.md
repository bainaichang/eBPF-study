sync_timing 是检测sync调用间隔时间，用内核探针实现 {入口探针（kprobe）」和「返回探针（kretprobe）}
disksnoop 是监控磁盘请求，用TRACEPOINT实现



获取一个hash表: BPF_HASH(哈希表名, key的类型(默认u64), value的类型(默认u64))
获取一个直方图: BPF_HISTOGRAM(dist);



我是跟着https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md 逐步学习的

感谢大佬