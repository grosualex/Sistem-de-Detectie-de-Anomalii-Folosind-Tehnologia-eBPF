from bcc import BPF

from common import texts

__MODULE_TYPE__ = "TEXT__PID_COMMAND"


class ProcessCreateAnomalies():
    def __init__(self):
        self.known_processes = [
            "systemd-journal",
            "ibus-engine-sim",
            "nm-dhcp-helper",
            "pulseaudio",
            "ibus-ui-gtk3",
            "upstart-dbus-br",
            "thermald",
            "compiz",
            "gnome-software",
            "gmain",
            "evolution-calen",
            "bash",
            "systemd",
            "upstart-file-br",
            "rtkit-daemon",
            "lpstat",
            "evolution-addre",
            "upowerd",
            "deja-dup-monito",
            "gpg-agent",
            "Xorg",
            "avahi-daemon",
            "NetworkManager",
            "fwupd",
            "upstart",
            "bamfdaemon",
            "(spatcher)",
            "prlsga",
            "python",
            "ibus-daemon",
            "whoopsie",
            "nm-dispatcher",
            "hud-service",
            "prlshprof",
            "prlcc",
            "unity-panel-ser",
            "xkbcomp",
            "gnome-terminal-",
            "prltimesync",
            "pool",
            "InputThread",
            "dhclient",
            "gdbus",
            "mc",
            "unity-settings-",
            "systemd-udevd",
            "upstart-udev-br",
            "cups-browsed",
            "cat",
            "sed",
            "window-stack-br",
            "indicator-datet",
            "cupsd",
            "sh"]

    def detect(self, event):
        for key in event:
            if key == "total_count":
                continue

            cmd = event[key]["comm"]

            if cmd not in self.known_processes:
                return True


def generate(**kargv):
    b = BPF(text=texts.TEXT__PID_COMMAND)
    b.attach_kprobe(event="sys_execve", fn_name="trace_pid_command")
    b.attach_kretprobe(event="sys_execve", fn_name="trace_return")

    anomalies = ProcessCreateAnomalies()

    return (b, anomalies)
