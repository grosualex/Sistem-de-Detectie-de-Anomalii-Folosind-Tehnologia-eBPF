from bcc import BPF

from common import texts

__MODULE_TYPE__ = "TEXT__PID_COMMAND"


class NetRecvFromAnomalies():
    def __init__(self):
        pass

    def detect(self, data):
        return False


def generate(**kargv):
    b = BPF(text=texts.TEXT__PID_COMMAND)
    b.attach_kprobe(event="sys_recvfrom", fn_name="trace_pid_command")
    b.attach_kretprobe(event="sys_recvfrom", fn_name="trace_return")

    anomaly_detector = NetRecvFromAnomalies()

    return (b, anomaly_detector)
