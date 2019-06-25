import os
import re
import sys
import json
import importlib
import logging
import sqlite3
import anomaly_detector
import copy

from datetime import datetime
from common import constants
from multiprocessing import Process


class BPFContainer():
    MAXIM_COUNT = 3600
    container_in_use = None
    learning = True
    containers = list()

    seconds = "seconds"
    minutes = "minutes"
    hours = "hours"

    anomaly_second = ""
    anomaly_minute = ""

    FIELDS = list()

    comm_pattern = re.compile("^(.*?)([0-9]{1,5})$")
    scripts_list = [
        "python", "perl", "ruby", "php"
    ]

    def __init__(self, module_name):
        # DATA
        self.module_data = None
        self.bpf_data = None
        self.custom_event_anomaly = None

        self.__last_second = ""
        self.__last_minute = ""
        self.__last_hour = ""

        # DATABASE
        self.seconds_dict = dict()
        self.minutes_dict = dict()
        self.hours_dict = dict()

        self.seconds_command_info = self.template_info_databases()
        self.minutes_command_info = self.template_info_databases()
        self.hours_command_info = self.template_info_databases()

        # REAL INITIALISATION
        self.load_module(module_name)

        self.load_knowledge()
        self.generate_bpf_data()

        self.database_events = self.init_database_events()
        self.database_info = self.init_database_info()

    # ###################### INITIALISATION METHODS
    def load_knowledge(self):
        seconds_path = os.path.join(
            'knowledge', self.module_data["name"] + '_seconds.json')
        minutes_path = os.path.join(
            'knowledge', self.module_data["name"] + '_minutes.json')
        hours_path = os.path.join(
            'knowledge', self.module_data["name"] + '_hour.json')

        if os.path.exists(seconds_path):
            with open(seconds_path) as fhandle:
                self.seconds_command_info = json.load(fhandle)

        if os.path.exists(minutes_path):
            with open(minutes_path) as fhandle:
                self.minutes_command_info = json.load(fhandle)

        if os.path.exists(hours_path):
            with open(hours_path) as fhandle:
                self.hours_command_info = json.load(fhandle)

    def init_database_events(self):
        return {
            BPFContainer.seconds: self.seconds_dict,
            BPFContainer.minutes: self.minutes_dict,
            BPFContainer.hours: self.hours_dict
        }

    def init_database_info(self):
        return {
            BPFContainer.seconds: self.seconds_command_info,
            BPFContainer.minutes: self.minutes_command_info,
            BPFContainer.hours: self.hours_command_info
        }

    def template_info_databases(self):
        return {
            "max": dict(),
            "average": dict()
        }

    def load_module(self, module_name):
        self.module_data = {
            "name": module_name,
            "module": importlib.import_module("bcc_texts." + module_name)
        }

    def generate_bpf_data(self):
        self.bpf_data = self.module_data["module"].generate()
        self.custom_event_anomaly = self.bpf_data[1]

        self.bpf_data = self.bpf_data[0]
        self.bpf_data["events"].open_perf_buffer(
            BPFContainer.event_callback,
            page_cnt=256)

    # ###################### PUBLIC METHODS

    def detect_anomaly(self, dict_type):
        if dict_type == BPFContainer.seconds:
            _last = self.__last_second

        if dict_type == BPFContainer.minutes:
            _last = self.__last_minute

        if dict_type == BPFContainer.hours:
            _last = self.__last_hour

        if _last == "":
            return

        detected = self.custom_event_anomaly.detect(
            self.database_events[dict_type][_last])

        return detected

    def update_database_info(self, dict_type):
        if dict_type == BPFContainer.seconds:
            _last = self.__last_second

        if dict_type == BPFContainer.minutes:
            _last = self.__last_minute

        if dict_type == BPFContainer.hours:
            _last = self.__last_hour

        if _last == "":
            return

        database_info = self.database_info[dict_type]
        dictionary = self.database_events[dict_type][_last]

        _aux = dict()

        for key in dictionary:
            if key == "total_count":
                continue

            cmd = dictionary[key]["comm"]
            count = dictionary[key]["count"]

            if cmd not in _aux:
                _aux[cmd] = 0

            _aux[cmd] += count

        for key in _aux:
            if key not in database_info["max"]:
                database_info["max"][key] = count
                database_info["average"][key] = dict()
                database_info["average"][key]["avg"] = count
                database_info["average"][key]["count"] = 0

            database_info["average"][key]["avg"] = \
                ((database_info["average"][key]["avg"] *
                  database_info["average"][key]["count"] + _aux[key]) /
                 (database_info["average"][key]["count"] + 1))

            database_info["average"][key]["count"] += 1

            if database_info["max"][key] < _aux[key]:
                database_info["max"][key] = _aux[key]

    def trace(self):
        self.bpf_data.perf_buffer_poll()

    def get_module_name(self):
        return self.module_data["name"]

    def save_knowledge(self):
        for key in self.database_info:
            database_info = self.database_info[key]

            fhandle = open(os.path.join(
                'knowledge', self.module_data["name"] + "_" + key + '.json'), "w")
            json.dump(database_info, fhandle, indent=4)
            fhandle.close()

    # ###################### STATIC METHODS

    @staticmethod
    def add_new_field(field_name):
        field_name = copy.deepcopy(field_name)
        BPFContainer.FIELDS.append(field_name)
        sql_conn = sqlite3.connect('databases/anomalies.db')
        c = sql_conn.cursor()
        c.execute("INSERT into fields(field_name) values(?)", (field_name,))
        sql_conn.commit()
        sql_conn.close()

    @staticmethod
    def load_fields():
        sql_conn = sqlite3.connect('databases/anomalies.db')
        c = sql_conn.cursor()
        c.execute("""
            SELECT field_name from fields order by id
        """)

        data = c.fetchall()
        sql_conn.close()

        BPFContainer.FIELDS = [x[0] for x in data]

    # time key formatter
    @staticmethod
    def get_seconds_time(_datetime):
        return _datetime.strftime('%Y-%m-%d_%H:%M:%S')

    @staticmethod
    def get_minutes_time(_datetime):
        return _datetime.strftime('%Y-%m-%d_%H:%M')

    @staticmethod
    def get_hour_time(_datetime):
        return _datetime.strftime('%Y-%m-%d_%H')

    # ###################### DATABASE
    @staticmethod
    def __database_filter(dictionary):
        keys = sorted(dictionary.keys(), reverse=True)
        if len(keys) <= BPFContainer.MAXIM_COUNT:
            return

        to_remove = keys[BPFContainer.MAXIM_COUNT:]
        for removable in to_remove:
            dictionary.pop(removable, None)

    @staticmethod
    def __normalize_process_command(command):
        m = BPFContainer.comm_pattern.match(command)

        if m is not None:
            command = m.groups()[0]

        command.strip()
        return command

    @staticmethod
    def __is_script(command_line):
        for script in BPFContainer.scripts_list:
            if script in command_line.split(' ')[0]:
                return True

        return False

    @staticmethod
    def __remove_empty_string(lista):
        return [x for x in lista if x != '']

    @staticmethod
    def __extract_script_name(command_line):
        splited = command_line.split(' ')
        splited = BPFContainer.__remove_empty_string(splited)

        if len(splited) > 1:
            return splited[1]

        return None

    @staticmethod
    def __database_update(event, dict_type, time_key):
        dictionary = BPFContainer.container_in_use.database_events[dict_type]

        cmdline = BPFContainer.read_process_cmdline(event.pid)
        if time_key not in dictionary:
            dictionary[time_key] = dict()
            dictionary[time_key]["total_count"] = 0

        dictionary[time_key]["total_count"] += 1
        if event.pid not in dictionary[time_key]:
            dictionary[time_key][event.pid] = dict()
            dictionary[time_key][event.pid]["count"] = 0
            dictionary[time_key][event.pid]["comm"] = event.process_command
            dictionary[time_key][event.pid]["cmdline"] = cmdline

            if dictionary[time_key][event.pid]["cmdline"] == '':
                dictionary[time_key][event.pid]["cmdline"] = \
                    event.process_command

        dictionary[time_key][event.pid]["count"] += 1

        BPFContainer.__database_filter(dictionary)

    @staticmethod
    def scan_scripts(time_range):
        for container in BPFContainer.containers:
            dictionary = container.database_events[time_range]

            for timestamp in dictionary:
                for pid in dictionary[timestamp]:
                    cmdline = dictionary[timestamp][pid]['cmdline']
                    comm = dictionary[timestamp][pid]['comm']

                    comm = BPFContainer.__normalize_process_command(comm)
                    if BPFContainer.__is_script(cmdline):
                        script_name = BPFContainer.__extract_script_name(cmdline)
                        if script_name is not None:
                            comm = script_name

                    dictionary[timestamp][pid]['comm'] = comm

                    if comm not in BPFContainer.FIELDS:
                        BPFContainer.add_new_field(comm)

    @staticmethod
    def start_anomaly_detector(time_range):
        print "ANOMALY DETECTOR STARTED", time_range
        BPFContainer.scan_scripts(BPFContainer.seconds)

        p = Process(target=anomaly_detector.detect,
                    args=(
                        BPFContainer.containers,
                        BPFContainer.FIELDS,
                        time_range,
                        BPFContainer.learning,
                        sys.stdout))
        p.start()

    @staticmethod
    def save_learned_clusters():
        print ""
        print "SAVING CLUSTERS"
        BPFContainer.scan_scripts(BPFContainer.seconds)

        p = Process(target=anomaly_detector.cluster_learned,
                    args=(BPFContainer.seconds,))
        p.start()

        # for container in BPFContainer.containers:
        #     container.save_knowledge()

        # anomaly_detector.detect(
        #     BPFContainer.containers,
        #     BPFContainer.FIELDS,
        #     time_range,
        #     BPFContainer.learning
        # )

    @staticmethod
    def read_process_cmdline(pid):
        try:
            fhandle = open("/proc/" + str(pid) + '/cmdline', 'rb')
            cmdline = fhandle.read().replace('\0', ' ')
            fhandle.close()
        except IOError:
            return ''

        return cmdline

    @staticmethod
    def event_callback(cpu, data, size):
        event = BPFContainer.container_in_use.bpf_data["events"].event(data)

        _datetime = datetime.now()
        seconds_time = BPFContainer.get_seconds_time(_datetime)
        # minutes_time = BPFContainer.get_minutes_time(_datetime)
        # hours_time = BPFContainer.get_hour_time(_datetime)

        if seconds_time != BPFContainer.container_in_use.__last_second:
            print seconds_time
            if BPFContainer.learning:
                BPFContainer.container_in_use.update_database_info(
                    BPFContainer.seconds)

            detected = BPFContainer.container_in_use.detect_anomaly(
                BPFContainer.seconds)

            BPFContainer.container_in_use.__last_second = seconds_time

        # if hours_time != BPFContainer.container_in_use.__last_hour:
        #     if BPFContainer.learning:
        #         BPFContainer.container_in_use.update_database_info(
        #             BPFContainer.hours)

        #     BPFContainer.container_in_use.__last_hour = hours_time

        # if minutes_time != BPFContainer.container_in_use.__last_minute:
        #     print minutes_time
        #     if BPFContainer.learning:
        #         BPFContainer.container_in_use.update_database_info(
        #             BPFContainer.minutes)

        #     if BPFContainer.learning is not False:
        #         BPFContainer.container_in_use.save_knowledge()

        #     logging.debug("#" * 100)
        #     logging.debug("MODULE NAME: %s\n\n",
        #                   BPFContainer.container_in_use.get_module_name())
        #     logging.debug("SECONDS\n%s", json.dumps(
        #         BPFContainer.container_in_use.seconds_dict, indent=4))
        #     logging.debug("MINUTES\n%s", json.dumps(
        #         BPFContainer.container_in_use.minutes_dict, indent=4))
        #     logging.debug("HOURS\n%s", json.dumps(
        #         BPFContainer.container_in_use.hours_dict, indent=4))

        #     BPFContainer.container_in_use.__last_minute = minutes_time

        BPFContainer.__database_update(
            event, BPFContainer.seconds, seconds_time)
        # BPFContainer.__database_update(
        #     event, BPFContainer.minutes, minutes_time)
        # BPFContainer.__database_update(
        #     event, BPFContainer.hours, hours_time)


def main():
    constants.PROJECT_ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

    with open(sys.argv[1]) as fhandle:
        config = json.load(fhandle)

    logging.basicConfig(
        filename=config["log_path"],
        format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=logging.DEBUG)

    BPFContainer.load_fields()

    BPFContainer.containers = list()
    for module in config["modules"]:
        container = BPFContainer(module)
        BPFContainer.containers.append(container)

    # Jucaus ;)
    while True and not False:
        for container in BPFContainer.containers:
            BPFContainer.container_in_use = container
            container.trace()

        anomaly_second = BPFContainer.get_seconds_time(datetime.now())
        if anomaly_second != BPFContainer.anomaly_second and \
           anomaly_second.endswith("0"):
            BPFContainer.start_anomaly_detector(
                BPFContainer.seconds,
            )

            BPFContainer.anomaly_second = anomaly_second

        # anomaly_minute = BPFContainer.get_minutes_time(datetime.now())

        # if BPFContainer.anomaly_minute == "":
        #     BPFContainer.anomaly_minute = anomaly_minute[-2:]

        # if len(BPFContainer.anomaly_minute) == 2 and \
        #    not anomaly_minute.endswith(BPFContainer.anomaly_minute):
        #     BPFContainer.anomaly_minute = anomaly_minute

        # if anomaly_minute != BPFContainer.anomaly_minute and \
        #    len(BPFContainer.anomaly_minute) != 2:
        #     BPFContainer.start_anomaly_detector(
        #         BPFContainer.minutes
        #     )

        #     BPFContainer.anomaly_minute = anomaly_minute


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        if BPFContainer.learning:
            BPFContainer.save_learned_clusters()
            exit(0)
