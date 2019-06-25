from bcc import BPF

from common import texts

__MODULE_TYPE__ = "TEXT__PID_COMMAND"


class FileOpenAnomalies():
    def __init__(self):
        pass

    def detect(self, event):
        return False


def generate(**kargv):
    b = BPF(text=texts.TEXT__PID_COMMAND)
    b.attach_kprobe(event="do_sys_open", fn_name="trace_pid_command")
    b.attach_kretprobe(event="do_sys_open", fn_name="trace_return")

    anomaly_detector = FileOpenAnomalies()

    return (b, anomaly_detector)
