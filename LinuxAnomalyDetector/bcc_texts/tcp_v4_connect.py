from bcc import BPF

from common import texts

__MODULE_TYPE__ = "TEXT__PID_COMMAND"


class TCPV4ConnectAnomalies():
    def __init__(self):
        pass

    def detect(self, data):
        return False


def generate(**kargv):
    b = BPF(text=texts.TEXT__PID_COMMAND)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_pid_command")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_return")

    anomaly_detector = TCPV4ConnectAnomalies()

    return (b, anomaly_detector)
