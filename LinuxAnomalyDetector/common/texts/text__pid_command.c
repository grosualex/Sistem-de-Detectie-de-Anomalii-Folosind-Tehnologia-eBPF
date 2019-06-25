#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/fs.h>
#include <linux/sched.h>


struct return_data {
	int 	pid;
	char 	comm[TASK_COMM_LEN];
};

BPF_HASH(infotmp, u64, struct return_data);
BPF_PERF_OUTPUT(events);


int trace_pid_command(struct pt_regs *ctx) {
	struct return_data data = {};

	u64 pid = bpf_get_current_pid_tgid() >> 32;
	data.pid = pid;

	if (pid == 0) {
		return 0;
	}

	if (bpf_get_current_comm(&data.comm, TASK_COMM_LEN) == 0) {
		infotmp.update(&pid, &data);
	}

	return 0;
}

int trace_return(struct pt_regs *ctx) {
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	struct return_data* stored_data;
	struct return_data 	to_return = {};

	if (pid == 0) {
		return 0;
	}

    stored_data = infotmp.lookup(&pid);

    if (stored_data == 0) {
    	return 0;
    }

	bpf_probe_read(
		&to_return.comm,
		TASK_COMM_LEN,
		stored_data->comm);

	to_return.pid = stored_data->pid;

	events.perf_submit(ctx, &to_return, sizeof(to_return));
    infotmp.delete(&pid);

	return 0;
}