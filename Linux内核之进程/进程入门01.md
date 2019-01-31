# 进程
一个进程就是一个**正在执行程序**的实例。从概念上说，进程是处于执行期的程序以及相关的资源的总称。进程不仅局限于一段可执行程序代码，通常还包含其它资源：内核数据对象、打开的文件、挂起的信号、处理器状态、内存地址空间、一个或多个执行线程等。

程序本身并不是进程，程序可以认为是磁盘上二进制代码的集合。当操作系统加载运行程序的那一时刻，即创建了新的进程。操作系统可以加载运行同一个程序多次，另一层意思是两个或多个进程可以共享同一程序代码。

在Linux中，通常调用`fork()`系统调用来创建一个新的进程。调用`fork()`的进程称为**父进程**，生成的新进程为**子进程**。`fork()`系统调用从内核返回两次:一次回到父进程，另一次回到子进程。

程序通过`exit()`系统调用退出执行。该函数会终结进程并将其占用的资源释放掉。父进程可以通过`wait4()`系统调用用来等待和获取子进程的退出状态。进程退出后被设置为僵死状态，直到它的父进程调用`wait()`或`waitpid()`为止。

# 进程状态
每个进程都有生命周期，从创建到终止。进程通过状态来体现生命周期的变化。进程状态可分为三大类：
- 运行态：该时刻进程占用cpu
- 就绪态：进程已经就绪，暂时未被cpu执行
- 阻塞态：等待某种外部事件发生

在Linux中，进程状态分为五种：
- `TASK_RUNNING`:进程待执行(就绪态,在运行队列中待执行)或正在执行(运行态)
- `TASK_INTERRUPTIBLE`:进程处于等待状态(阻塞态),等待某个条件达成后被内核唤醒，也可能因接收到信号而提前被唤醒
- `TASK_UNINTERRUPTIBLE`:进程处于等待状态(阻塞态),不可中断，不接收任何信号，必须等待某事件发生才会被唤醒
- `TASK_TRACED`:被其它进程跟踪,如被ptrace调试
- `TASK_STOPPED`:进程停止执行，当进程接收到`SIGSTOP`、`SIGTSTP`、`SIGTTIN`或`SIGTTOU`信号后会进入此状态

# 进程的层次结构
当进程创建子进程后，父子进程会以某种形式保持关联，而子进程又可以创建更多的子进程，这样就组成一个进程的层次结构。

每个进程有且仅有一个父进程，但可以拥有0个或多个子进程。拥有同一个父进程的所有进程称为**兄弟**。

Linux中所有的进程都是PID为1的进程的后代。

# 进程描述符
内核把运行态的进程信息存放在由双向循环链表构成的任务队列中。队列中的每一项类型为`struct task_struct`,称为进程描述符结构，
该结构定义在`<linux/sched.h>`文件中。进程描述符中包含一个具体进程的所有信息。

进程描述符的信息可以大致划分为以下几大类：
- 调度参数：进程优先级，最近消耗cpu的时间，最近睡眠的时间等。
- 内存映射：指向代码、数据、堆栈段或页表的指针。
- 信号：通过信号掩码显示哪些信号被忽略、哪些需要被捕捉、哪些暂时阻塞、哪些信号传递当中。
- 机器寄存器：当上下文切换时，机器寄存器的内容会被保存。
- 系统调用状态：当前系统调用的信息，包括参数和返回值。
- 文件描述符表：当某个文件被打开时，文件描述作为索引在文件描述表中定位相关文件的i节点数据结构。
- 统计数据：指向记录用户、系统执行时间。
- 内核堆栈：进程的内核部分可使用的固定堆栈。
- 其他：进程状态、PID、父子进程关系、用户和组标识等。

`struct task_struct`结构体比较大，完整的结构如下(`linux-4.9.44`):
```C
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info thread_info;
#endif
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	void *stack;
	atomic_t usage;
	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;

#ifdef CONFIG_SMP
	struct llist_node wake_entry;
	int on_cpu;
#ifdef CONFIG_THREAD_INFO_IN_TASK
	unsigned int cpu;	/* current CPU */
#endif
	unsigned int wakee_flips;
	unsigned long wakee_flip_decay_ts;
	struct task_struct *last_wakee;

	int wake_cpu;
#endif
	int on_rq;

    /*与调度相关的信息*/
	int prio, static_prio, normal_prio;
	unsigned int rt_priority;
	const struct sched_class *sched_class;
	struct sched_entity se;
	struct sched_rt_entity rt;
#ifdef CONFIG_CGROUP_SCHED
	struct task_group *sched_task_group;
#endif
	struct sched_dl_entity dl;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* list of struct preempt_notifier: */
	struct hlist_head preempt_notifiers;
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif

	unsigned int policy;
	int nr_cpus_allowed;
	cpumask_t cpus_allowed;

#ifdef CONFIG_PREEMPT_RCU
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
	unsigned long rcu_tasks_nvcsw;
	bool rcu_tasks_holdout;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_idle_cpu;
#endif /* #ifdef CONFIG_TASKS_RCU */

#ifdef CONFIG_SCHED_INFO
	struct sched_info sched_info;
#endif
    /*task链表*/
	struct list_head tasks;
#ifdef CONFIG_SMP
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
#endif
    /*虚拟内存空间*/
	struct mm_struct *mm, *active_mm;
	/* per-thread vma caching */
	u32 vmacache_seqnum;
	struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
	struct task_rss_stat	rss_stat;
#endif
/* task state */
	int exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	unsigned long jobctl;	/* JOBCTL_*, siglock protected */

	/* Used for emulating ABI behavior of previous Linux versions */
	unsigned int personality;

	/* scheduler bits, serialized by scheduler locks */
	unsigned sched_reset_on_fork:1;
	unsigned sched_contributes_to_load:1;
	unsigned sched_migrated:1;
	unsigned sched_remote_wakeup:1;
	unsigned :0; /* force alignment to the next boundary */

	/* unserialized, strictly 'current' */
	unsigned in_execve:1; /* bit to tell LSMs we're in execve */
	unsigned in_iowait:1;
#if !defined(TIF_RESTORE_SIGMASK)
	unsigned restore_sigmask:1;
#endif
#ifdef CONFIG_MEMCG
	unsigned memcg_may_oom:1;
#ifndef CONFIG_SLOB
	unsigned memcg_kmem_skip_account:1;
#endif
#endif
#ifdef CONFIG_COMPAT_BRK
	unsigned brk_randomized:1;
#endif
#ifdef CONFIG_CGROUPS
	/* disallow userland-initiated cgroup migration */
	unsigned no_cgroup_migration:1;
#endif

	unsigned long atomic_flags; /* Flags needing atomic access. */

	struct restart_block restart_block;
    /*进程标识*/
	pid_t pid;
	pid_t tgid;

#ifdef CONFIG_CC_STACKPROTECTOR
	/* Canary value for the -fstack-protector gcc feature */
	unsigned long stack_canary;
#endif
	/*
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with
	 * p->real_parent->pid)
	 */
	struct task_struct __rcu *real_parent; /* real parent process */
	struct task_struct __rcu *parent; /* recipient of SIGCHLD, wait4() reports */
	/*
	 * children/sibling forms the list of my natural children
	 */
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
	struct task_struct *group_leader;	/* threadgroup leader */

	/*
	 * ptraced is the list of tasks this task is using ptrace on.
	 * This includes both natural children and PTRACE_ATTACH targets.
	 * p->ptrace_entry is p's link on the p->parent->ptraced list.
	 */
	struct list_head ptraced;
	struct list_head ptrace_entry;

	/* PID/PID hash table linkage. */
	struct pid_link pids[PIDTYPE_MAX];
	struct list_head thread_group;
	struct list_head thread_node;

	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */

	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;
	struct prev_cputime prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqcount_t vtime_seqcount;
	unsigned long long vtime_snap;
	enum {
		/* Task is sleeping or running in a CPU with VTIME inactive */
		VTIME_INACTIVE = 0,
		/* Task runs in userspace in a CPU with VTIME active */
		VTIME_USER,
		/* Task runs in kernelspace in a CPU with VTIME active */
		VTIME_SYS,
	} vtime_snap_whence;
#endif

#ifdef CONFIG_NO_HZ_FULL
	atomic_t tick_dep_mask;
#endif
	unsigned long nvcsw, nivcsw; /* context switch counts */
	u64 start_time;		/* monotonic time in nsec */
	u64 real_start_time;	/* boot based time in nsec */
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;

	struct task_cputime cputime_expires;
	struct list_head cpu_timers[3];

/* process credentials */
	const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
	const struct cred __rcu *real_cred; /* objective and real subjective task
					 * credentials (COW) */
	const struct cred __rcu *cred;	/* effective (overridable) subjective task
					 * credentials (COW) */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */
/* file system info */
	struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
/* hung task detection */
	unsigned long last_switch_count;
#endif
/* filesystem information */
	struct fs_struct *fs;
/* open file information */
	struct files_struct *files;
/* namespaces */
	struct nsproxy *nsproxy;
/* signal handlers */
	struct signal_struct *signal;
	struct sighand_struct *sighand;

	sigset_t blocked, real_blocked;
	sigset_t saved_sigmask;	/* restored if set_restore_sigmask() was used */
	struct sigpending pending;

	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	unsigned sas_ss_flags;

	struct callback_head *task_works;

	struct audit_context *audit_context;
#ifdef CONFIG_AUDITSYSCALL
	kuid_t loginuid;
	unsigned int sessionid;
#endif
	struct seccomp seccomp;

/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed,
 * mempolicy */
	spinlock_t alloc_lock;

	/* Protection of the PI data structures: */
	raw_spinlock_t pi_lock;

	struct wake_q_node wake_q;

#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task */
	struct rb_root pi_waiters;
	struct rb_node *pi_waiters_leftmost;
	/* Deadlock detection and priority inheritance handling */
	struct rt_mutex_waiter *pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
	/* mutex deadlock detection */
	struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	unsigned long hardirq_enable_ip;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	int hardirqs_enabled;
	int hardirq_context;
	unsigned long softirq_disable_ip;
	unsigned long softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
	int softirqs_enabled;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	struct held_lock held_locks[MAX_LOCK_DEPTH];
	gfp_t lockdep_reclaim_gfp;
#endif
#ifdef CONFIG_UBSAN
	unsigned int in_ubsan;
#endif

/* journalling filesystem info */
	void *journal_info;

/* stacked block device info */
	struct bio_list *bio_list;

#ifdef CONFIG_BLOCK
/* stack plugging */
	struct blk_plug *plug;
#endif

/* VM state */
	struct reclaim_state *reclaim_state;

	struct backing_dev_info *backing_dev_info;

	struct io_context *io_context;

	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
	struct task_io_accounting ioac;
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	cputime_t acct_timexpd;	/* stime + utime since last update */
#endif
#ifdef CONFIG_CPUSETS
	nodemask_t mems_allowed;	/* Protected by alloc_lock */
	seqcount_t mems_allowed_seq;	/* Seqence no to catch updates */
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
	/* Control Group info protected by css_set_lock */
	struct css_set __rcu *cgroups;
	/* cg_list protected by css_set_lock and tsk->alloc_lock */
	struct list_head cg_list;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
#endif
#ifdef CONFIG_PERF_EVENTS
	struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
	unsigned long preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *mempolicy;	/* Protected by alloc_lock */
	short il_next;
	short pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	unsigned long numa_migrate_retry;
	u64 node_stamp;			/* migration stamp  */
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;

	struct list_head numa_entry;
	struct numa_group *numa_group;

	/*
	 * numa_faults is an array split into four regions:
	 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
	 * in this precise order.
	 *
	 * faults_memory: Exponential decaying average of faults on a per-node
	 * basis. Scheduling placement decisions are made based on these
	 * counts. The values remain static for the duration of a PTE scan.
	 * faults_cpu: Track the nodes the process was running on when a NUMA
	 * hinting fault was incurred.
	 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
	 * during the current scan window. When the scan completes, the counts
	 * in faults_memory and faults_cpu decay and these values are copied.
	 */
	unsigned long *numa_faults;
	unsigned long total_numa_faults;

	/*
	 * numa_faults_locality tracks if faults recorded during the last
	 * scan window were remote/local or failed to migrate. The task scan
	 * period is adapted based on the locality of the faults with different
	 * weights depending on whether they were shared or private faults
	 */
	unsigned long numa_faults_locality[3];

	unsigned long numa_pages_migrated;
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	struct tlbflush_unmap_batch tlb_ubc;
#endif

	struct rcu_head rcu;

	/*
	 * cache last used pipe for splice
	 */
	struct pipe_inode_info *splice_pipe;

	struct page_frag task_frag;

#ifdef	CONFIG_TASK_DELAY_ACCT
	struct task_delay_info *delays;
#endif
#ifdef CONFIG_FAULT_INJECTION
	int make_it_fail;
#endif
	/*
	 * when (nr_dirtied >= nr_dirtied_pause), it's time to call
	 * balance_dirty_pages() for some dirty throttling pause
	 */
	int nr_dirtied;
	int nr_dirtied_pause;
	unsigned long dirty_paused_when; /* start of a write-and-pause period */

#ifdef CONFIG_LATENCYTOP
	int latency_record_count;
	struct latency_record latency_record[LT_SAVECOUNT];
#endif
	/*
	 * time slack values; these are used to round up poll() and
	 * select() etc timeout values. These are in nanoseconds.
	 */
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;

#ifdef CONFIG_KASAN
	unsigned int kasan_depth;
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Index of current stored address in ret_stack */
	int curr_ret_stack;
	/* Stack of return addresses for return function tracing */
	struct ftrace_ret_stack	*ret_stack;
	/* time stamp for last schedule */
	unsigned long long ftrace_timestamp;
	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun.
	 */
	atomic_t trace_overrun;
	/* Pause for the tracing */
	atomic_t tracing_graph_pause;
#endif
#ifdef CONFIG_TRACING
	/* state flags for use by tracers */
	unsigned long trace;
	/* bitmask and counter of trace recursion */
	unsigned long trace_recursion;
#endif /* CONFIG_TRACING */
#ifdef CONFIG_KCOV
	/* Coverage collection mode enabled for this task (0 if disabled). */
	enum kcov_mode kcov_mode;
	/* Size of the kcov_area. */
	unsigned	kcov_size;
	/* Buffer for coverage collection. */
	void		*kcov_area;
	/* kcov desciptor wired with this task or NULL. */
	struct kcov	*kcov;
#endif
#ifdef CONFIG_MEMCG
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;

	/* number of pages to reclaim on returning to userland */
	unsigned int memcg_nr_pages_over_high;
#endif
#ifdef CONFIG_UPROBES
	struct uprobe_task *utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
	unsigned int	sequential_io;
	unsigned int	sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	unsigned long	task_state_change;
#endif
	int pagefault_disabled;
#ifdef CONFIG_MMU
	struct task_struct *oom_reaper_list;
#endif
#ifdef CONFIG_VMAP_STACK
	struct vm_struct *stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* A live task holds one reference. */
	atomic_t stack_refcount;
#endif
/* CPU-specific state of this task */
	struct thread_struct thread;
/*
 * WARNING: on x86, 'thread_struct' contains a variable-sized
 * structure.  It *MUST* be at the end of 'task_struct'.
 *
 * Do not put anything below here!
 */
};
```

## 进程标识
内核通过一个唯一的进程标识值(PID)来标识每个进程，PID的类型为`pid_t`，实际是一个`int`类型。通过`/proc/sys/kernel/pid_max `文件查看或修改内核对PID最大值的限制，在某些机器该文件内容为`4194304`。

在分配或回收PID值，内核通过维护`pidmap[PIDMAP_ENTRIES]`位图数组来标识哪些PID被分配，哪些为空闲。

## `struct thread_info`结构
内核为每个进程在内核栈底(假设内核栈是向下增长)创建一个`struct thread_info`的结构对象，该对象主要作用就是让内核能够快速的获取当前进程描述符。`struct thread_info`是一个与cpu硬件相关的结构，在文件`<asm/thread_info.h>`定义。

`struct thread_info`结构如下：
```C
/*
 * On IA-64, we want to keep the task structure and kernel stack together, so they can be
 * mapped by a single TLB entry and so they can be addressed by the "current" pointer
 * without having to do pointer masking.
 */
struct thread_info {
        struct task_struct *task;       /* XXX not really needed, except for dup_task_struct() */
        __u32 flags;                    /* thread_info flags (see TIF_*) */
        __u32 cpu;                      /* current CPU */
        __u32 last_cpu;                 /* Last CPU thread ran on */
        __u32 status;                   /* Thread synchronous flags */
        mm_segment_t addr_limit;        /* user-level address space limit */
        int preempt_count;              /* 0=premptable, <0=BUG; will also serve as bh-counter */
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE
        __u64 ac_stamp;
        __u64 ac_leave;
        __u64 ac_stime;
        __u64 ac_utime;
#endif
};
```
在X86上，内核栈的大小和位置是固定的。所以很容易获取栈底指针，即`struct thread_info`结构对象的位置。再通过该对象就可以获取task的地址。
```
current_thread_info()->task
```
不同的CPU体系结构，获取task的方式有所有不同，有些cpu会将当前的`task_struct`保存在固定的寄存器中。

注：关于`struct thread_info`结构的描述对于现在linux内核可能不适用了，因为有可能内核会将整个task_struct对象直接放置在栈底。说白了，`thread_info`的存在是一种优化方式，这种优化方式可能被其它更好的方式所取代。

# 进程的创建
Linux调用`fork()`通过复制当前进程来创建新的子进程，Linux为了加快创建过程，并未复制整个进程地址空间。Linux创建进程是出了名的快，主要使用了写时复制(copy on write)技术，一种推迟或免除数据复制的技术。

## 写时复制
`fork()`主要开销是复制父进程的页表以及给子进程创建新的进程描述符。父进程与子进程通过页表共享数据页,并将数据页的属性设置为只读。当数据页写入数据时，因为只读将引发页错误，内核捕获该错误并复制数据页，更新进程的页表项。

# 进程管理命令
## ps：显示当前进程状态
```shell
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps aux 
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 225712  9132 ?        Ss   1月15   2:24 /sbin/init splash
root         2  0.0  0.0      0     0 ?        S    1月15   0:00 [kthreadd]
root         4  0.0  0.0      0     0 ?        I<   1月15   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        I<   1月15   0:00 [mm_percpu_wq]
root         7  0.0  0.0      0     0 ?        S    1月15   1:21 [ksoftirqd/0]
root         8  0.0  0.0      0     0 ?        I    1月15   6:34 [rcu_sched]
root         9  0.0  0.0      0     0 ?        I    1月15   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    1月15   0:00 [migration/0]
root        11  0.0  0.0      0     0 ?        S    1月15   0:08 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    1月15   0:00 [cpuhp/0]
...
```
显示的列信息：
- USER: 用户名
- PID：进程ID
- PPID: 父进程ID
- %CPU: CPU占用率
- %MEM: 内存占用率
- VSZ: 虚拟内存大小(单位KB)
- RSS：实际使用内存大小
- TTY: 控制终端(?表示守护进程)
- STAT: 状态(S-可中断睡眠,D-不可中断睡眠,R-正在运行,Z-僵尸状态)
- START：启动时间
- TIME: 累积CPU时间
- COMMAND: 执行的命令

常用选项：
- `-e`: 显示所有进程，与`-A`相同
- `-l`: 按长格式显示
- `-f`: 按全格式显示
- `-u <userlist>`：显示指定用户的进程，默认显示所有用户
- `--sort spec` : 指定排序的方式
- `-C cmdlist`: 显示指定进程名的进程
- `-L`：显示线程信息

示例：
* 只显示指定用户ice的进程
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps -f -u ice
UID        PID  PPID  C STIME TTY          TIME CMD
ice       1290 17950  0 10:17 pts/1    00:01:13 emacs sched.h
ice       2007     1  0 1月15 ?       00:00:00 /lib/systemd/systemd --user
ice       2015  2007  0 1月15 ?       00:00:00 (sd-pam)
ice       2031  2003  0 1月15 ?       00:00:00 /bin/sh /etc/xdg/xfce4/xinitrc -- /etc/X11/xinit/xserverrc
ice       2045  2007  0 1月15 ?       00:00:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activat
ice       2119     1  0 1月15 ?       00:00:00 /usr/bin/VBoxClient --clipboard
ice       2120  2119  0 1月15 ?       00:00:12 /usr/bin/VBoxClient --clipboard
ice       2129     1  0 1月15 ?       00:00:00 /usr/bin/VBoxClient --display
...
```
* 按cpu使用率排序显示
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps -aux --sort -pcpu
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
ice       1290  0.7 14.3 610100 292848 pts/1   Tl   10:17   1:13 emacs sched.h
root      5919  0.7  4.7 210340 97760 ?        SLsl 1月25  69:16 /usr/sbin/corosync -f
root     19477  0.3  2.8 718880 58496 ?        Ssl  1月26  28:05 /usr/bin/dockerd -H fd://
root     19498  0.3  1.6 663636 32848 ?        Ssl  1月26  24:35 docker-containerd --config /var/run/docker/containerd/containerd.toml
ice       2142  0.2  0.0 126232  1608 ?        Sl   1月15  68:23 /usr/bin/VBoxClient --draganddrop
root      1283  0.1  1.7 248092 35304 ?        S<Lsl 1月15  36:24 ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslo
root         1  0.0  0.4 225712  9144 ?        Ss   1月15   2:25 /sbin/init splash
...
```
* 按内存使用率排序显示
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps -aux --sort -pmem
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
ice       1290  0.6 14.3 610100 292848 pts/1   Tl   10:17   1:13 emacs sched.h
root      5919  0.7  4.7 210340 97760 ?        SLsl 1月25  69:17 /usr/sbin/corosync -f
ice       4609  0.0  4.6 761340 95344 ?        SNl  1月27   0:17 /usr/bin/python3 /usr/bin/update-manager --no-update --no-focus-on-map
root       254  0.0  3.6 194960 73980 ?        S<s  1月15   2:47 /lib/systemd/systemd-journald
root     19477  0.3  2.8 718880 58496 ?        Ssl  1月26  28:05 /usr/bin/dockerd -H fd://
ice       2992  0.0  2.2 921676 45764 ?        Sl   1月15   2:49 /usr/bin/xfce4-terminal
root      1645  0.0  2.1 363052 44760 tty7     Rsl+ 1月15   5:47 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0
root      1283  0.1  1.7 248092 35304 ?        S<Lsl 1月15  36:24 ovs-vswitchd unix:/var/run/openvswitch/db.sock -vconsole:emer -vsyslo
root     19498  0.3  1.6 663636 32848 ?        Ssl  1月26  24:35 docker-containerd --config /var/run/docker/containerd/containerd.toml
ice       2175  0.0  1.1 436592 23904 ?        Sl   1月15   0:38 xfwm4 --replace
...
```
* 查看sshd进程
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps -f -C sshd
UID        PID  PPID  C STIME TTY          TIME CMD
root      1431     1  0 1月15 ?       00:00:00 /usr/sbin/sshd -D
```
* 查看某个进程的线程信息
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ ps -L 19498
  PID   LWP TTY      STAT   TIME COMMAND
19498 19498 ?        Ssl    0:00 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19516 ?        Ssl    6:28 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19517 ?        Ssl    0:00 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19518 ?        Ssl    4:28 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19519 ?        Ssl    0:00 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19520 ?        Ssl    0:00 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19521 ?        Ssl    1:48 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19530 ?        Ssl    4:07 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 19532 ?        Ssl    4:48 docker-containerd --config /var/run/docker/containerd/containerd.toml
19498 16227 ?        Ssl    2:53 docker-containerd --config /var/run/docker/containerd/containerd.toml
```
* 与watch命令结合达到实时查询进程状态的效果
```
watch -n 1 'ps -aux --sort -pmem'
```
## top: 动态实时显示系统和进程的信息
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ top
top - 13:35:42 up 16 days, 13:11,  1 user,  load average: 0.07, 0.02, 0.00
Tasks: 181 total,   1 running, 129 sleeping,   1 stopped,   1 zombie
%Cpu(s): 11.6 us,  5.3 sy,  0.3 ni, 82.5 id,  0.0 wa,  0.0 hi,  0.3 si,  0.0 st
KiB Mem :  2041304 total,   177336 free,   781632 used,  1082336 buff/cache
KiB Swap:  2097148 total,  2063908 free,    33240 used.  1000428 avail Mem 

  PID USER      PR  NI    VIRT    RES    SHR S %CPU %MEM     TIME+ COMMAND                                                              
 1645 root      20   0  363052  44760  12216 S  7.9  2.2   5:56.07 Xorg                                                                 
 2992 ice       20   0  922068  45764  23984 S  4.6  2.2   2:54.71 xfce4-terminal                                                       
 2175 ice       20   0  436592  23904  15824 S  1.0  1.2   0:39.85 xfwm4                                                                
 3804 ice       20   0   49348   4048   3392 R  1.0  0.2   0:00.25 top                                                                  
 2411 ice       20   0  220776   5096   4384 S  0.7  0.2   0:02.69 at-spi2-registr                                                      
 5919 root      rt   0  210340  97760  74932 S  0.7  4.8  69:27.79 corosync                                                             
 2142 ice       20   0  126232   1608   1532 S  0.3  0.1  68:25.90 VBoxClient                                                           
 2200 ice       20   0  588228  19912  10488 S  0.3  1.0   0:04.20 polkit-gnome-au                                                      
 2223 ice       20   0  535352  16180   7944 S  0.3  0.8   0:01.17 light-locker                                                         
 2393 ice       20   0   49928   4180   3720 S  0.3  0.2   0:00.44 dbus-daemon
...
```
* 系统运行时间和平均负载
```
top - 13:35:42 up 16 days, 13:11,  1 user,  load average: 0.07, 0.02, 0.00
```

* 任务统计
```
Tasks: 181 total,   1 running, 129 sleeping,   1 stopped,   1 zombie
```
* CPU统计
```
%Cpu(s): 11.6 us,  5.3 sy,  0.3 ni, 82.5 id,  0.0 wa,  0.0 hi,  0.3 si,  0.0 st
```
* 内存统计
```
KiB Mem :  2041304 total,   177336 free,   781632 used,  1082336 buff/cache
KiB Swap:  2097148 total,  2063908 free,    33240 used.  1000428 avail Mem 
```
## kill：给进程发送信号
发送和接收信号是一种进程之间通信的机制。Linux内置一些固定的信号以及信号处理方式。
命令格式：
```
 kill [options] <pid> [...]
```
常用 选项：
- `-<signal>`或`-s <signal>`：指定要发送的信号
- `-l`或`-L`：显示信号列表

示例：
* 查看信号列表
```
ice@ice-VirtualBox:~/linux/linux-4.9.44$ kill -l
 1) SIGHUP	 2) SIGINT	 3) SIGQUIT	 4) SIGILL	 5) SIGTRAP
 2) SIGABRT	 7) SIGBUS	 8) SIGFPE	 9) SIGKILL	10) SIGUSR1
1)  SIGSEGV	12) SIGUSR2	13) SIGPIPE	14) SIGALRM	15) SIGTERM
2)  SIGSTKFLT	17) SIGCHLD	18) SIGCONT	19) SIGSTOP	20) SIGTSTP
3)  SIGTTIN	22) SIGTTOU	23) SIGURG	24) SIGXCPU	25) SIGXFSZ
4)  SIGVTALRM	27) SIGPROF	28) SIGWINCH	29) SIGIO	30) SIGPWR
5)  SIGSYS	34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
6)  SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
7)  SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
8)  SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
9)  SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
10) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
11) SIGRTMAX-1	64) SIGRTMAX		
```
* 终止进程
```
kill <pid> [...]    #优雅地终止进程，默认发送SIGTERM信号(15)
kill -9 <pid> [...] #强制终止进程
```