from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

import os
import re
import json
import sqlite3
import shutil
import time
import random


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.routes = {
            r'^/decision$': {
                'PUT': self.handle_decision
            },
            r'^/entries': {
                'POST': self.get_entries,
                'media_type': 'application/json'
            },
            r'^/switch_learning': {
                'PUT': self.switch_learning,
                'media_type': 'application/json'
            }
        }

        return BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_HEAD(self):
        self.handle_request("HEAD")

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_PUT(self):
        self.handle_request("PUT")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def accept_type(self, request_type):
        if request_type == 'PUT' or request_type == 'POST':
            return True

        return False

    def __not_found(self):
        self.send_response(404)
        self.end_headers()
        self.wfile.write('Page not found.\n')

    def switch_learning(self):
        sql_conn = sqlite3.connect('../databases/anomalies.db')
        c = sql_conn.cursor()

        c.execute("""
            SELECT * FROM tracer_config
        """)

        data = c.fetchall()[0]
        learning = data[2]
        if learning == 0:
            learning = 1
        else:
            learning = 0

        c.execute("""
            UPDATE tracer_config set learning = ?
        """, (learning, ))

        sql_conn.commit()
        sql_conn.close()

    def load_usual_data(self, time_range, iteration=30):
        if iteration == 0:
            return None

        if not os.path.exists("../knowledge/usual_" + time_range + ".json"):
            usual = {
                "fields": [],
                "data": [],
                "events": []
            }
        else:
            try:
                usual_handle = open("../knowledge/usual_" + time_range + ".json")
                usual = json.load(usual_handle)
                usual_handle.close()
            except ValueError:
                time.sleep(1)
                usual = self.load_usual_data(time_range, iteration - 1)

        return usual

    def save_usual_events_json(self, data):
        time_range = 'seconds'
        file_path = "../knowledge/usual_" + time_range + ".json"

        if os.path.exists(file_path):
            shutil.copy(file_path, file_path + 'bkp')

        random_number = random.randint(1, 999999999)

        tmp_path = file_path + '.' + str(random_number) + '.tmp'
        fhandle = open(tmp_path, 'wb')
        json.dump(data, fhandle)
        fhandle.close()

        shutil.copy(tmp_path, file_path)
        os.remove(tmp_path)

    def __load_knowledge(self, event_name, time_range):
        file_path = "../knowledge/" + event_name + \
            '_' + time_range + '.json'

        fhandle = open(file_path)
        data = json.load(fhandle)
        fhandle.close()

        return data

    def merge_knowledge(self, aux_knowledge, database_info):
        for field in aux_knowledge['max']:
            if field not in database_info['max']:
                database_info['max'][field] = aux_knowledge['max'][field]
            elif aux_knowledge['max'][field] > database_info['max'][field]:
                database_info['max'][field] = aux_knowledge['max'][field]

        for field in aux_knowledge['average']:
            if field not in database_info['average']:
                database_info['average'][field] = \
                    aux_knowledge['average'][field]
            elif aux_knowledge['average'][field]['count'] > database_info['average'][field]['count']:
                database_info['average'][field] = \
                    aux_knowledge['average'][field]

    def save_knowledge(self, anomaly_state, usual):
        knowledge = dict()

        events = usual['events']
        fields = usual['fields']

        for i in range(len(anomaly_state)):
            if anomaly_state[i] == 0:
                continue

            field_index = i / len(events)
            event_index = i % len(events)

            event_name = events[event_index]
            field_name = fields[field_index]

            if event_name not in knowledge:
                knowledge[event_name] = dict()

            knowledge[event_name][field_name] = anomaly_state[i]

        for event_name in knowledge:
            data = self.__load_knowledge(
                event_name, "seconds")

            for field_name in knowledge[event_name]:
                if field_name not in data['max']:
                    data['max'][field_name] = \
                        knowledge[event_name][field_name]

                elif data['max'][field_name] < knowledge[event_name][field_name]:
                    data['max'][field_name] = \
                        knowledge[event_name][field_name]

                if field_name not in data['average']:
                    data['average'][field_name] = dict()
                    data['average'][field_name]["avg"] = \
                        knowledge[event_name][field_name]
                    data['average'][field_name]["count"] = 1
                else:
                    data['average'][field_name]["avg"] = \
                        (data['average'][field_name]["avg"] *
                         data['average'][field_name]["count"] +
                         knowledge[event_name][field_name]) / \
                        data['average'][field_name]["count"] + 1

                    data['average'][field_name]["count"] += 1

            file_path = "../knowledge/" + event_name + \
                '_seconds.json'

            # fhandle = open(file_path)
            # aux_knowledge = json.load(fhandle)
            # fhandle.close()

            # self.merge_knowledge(aux_knowledge, data)

            fhandle = open(file_path, 'w')
            fhandle.write(json.dumps(data, indent=4))
            fhandle.flush()
            fhandle.close()

    def handle_decision(self):
        decision_data = json.loads(
            self.rfile.read(int(self.headers['Content-Length']))
        )

        decision = decision_data['decision']
        anomaly_id = int(decision_data['anomaly_id'])
        kill_pids = decision_data['kill_pids']
        is_anomaly = decision_data['is_anomaly']

        sql_conn = sqlite3.connect('../databases/anomalies.db')
        c = sql_conn.cursor()

        print decision, anomaly_id

        c.execute("""
            SELECT pids_stopped, anomaly_state from anomalies WHERE id = ?
        """, (anomaly_id,))

        anomalies_entry = c.fetchall()[0]
        pids_stopped = anomalies_entry[0].split("<|>")
        anomaly_state = anomalies_entry[1]
        anomaly_state = json.loads(anomaly_state)

        print decision_data

        if decision == 'done':
            print '-' * 40
            print "DECISION IS DONE"
            p = re.compile(r'^(PID:\ {1,5})([0-9]{1,5})')
            remaining_pids = list(set(pids_stopped) - set(kill_pids))

            print is_anomaly

            if not is_anomaly:
                # fhandle = open("../knowledge/anomalies/%d.json" %
                #                (anomaly_id))
                # anomaly_usual = json.load(fhandle)
                # fhandle.close()

                usual = self.load_usual_data('seconds')
                usual['data'].append(anomaly_state)
                self.save_usual_events_json(usual)
                self.save_knowledge(anomaly_state, usual)
                print "No anomaly detected. Saving new data."

            for pid_str in kill_pids:
                m = p.match(pid_str)

                if m is not None:
                    pid = m.groups()[1]
                    os.system("sudo kill -9 %s" % (pid))

            for pid_str in remaining_pids:
                m = p.match(pid_str)
                print pid_str

                if m is not None:
                    pid = m.groups()[1]
                    print 'PID----', pid, len(pid)
                    os.system("sudo kill -CONT %s" % (pid))
            print "Done "
            print '-' * 50
        else:
            print os.system("sudo init 1")

        c.execute("""
            UPDATE anomalies SET solved = 1 WHERE id = ?
        """, (anomaly_id,))
        sql_conn.commit()

        c.execute("""
            SELECT * from anomalies where solved = 0
        """)

        data = c.fetchall()
        print "LEFT DATA", len(data)
        if len(data) == 0:
            c.execute("""
                UPDATE tracer_config SET detect = 1
            """)

            sql_conn.commit()

        sql_conn.close()

    def get_entries(self):
        print 'here'
        entries_data = json.loads(
            self.rfile.read(int(self.headers['Content-Length']))
        )
        entries_number = entries_data['entries_number']
        to_exclude = [str(x) for x in entries_data['to_exclude']]

        for ids in entries_data['to_exclude']:
            try:
                aux = int(ids)
            except ValueError:
                print "NOT INT. POSSIBLE SQL INJ. RETURNING"
                self.wfile.write(json.dumps({"error": "invalid api call"}))

        print to_exclude

        sql_conn = sqlite3.connect('../databases/anomalies.db')
        c = sql_conn.cursor()
        c.execute("""
            SELECT * FROM anomalies WHERE
                solved = 0 and
                id not in ({seq})
            ORDER BY timestamp desc limit ?
        """.format(seq=",".join(to_exclude)), (entries_number,))

        results = c.fetchall()

        c = sql_conn.cursor()
        c.execute("""
            SELECT learning from tracer_config
        """)

        learning = bool(c.fetchall()[0][0])
        sql_conn.close()

        response = dict()
        response['learning'] = learning
        response['anomalies'] = []
        for result in results:
            response['anomalies'].append(
                {
                    "anomaly_id": result[0],
                    "anomaly_title": result[1],
                    "anomaly_text": result[2],
                    "stopped_pids": list(result[3].split("<|>"))
                }
            )

        response_string = json.dumps(response)
        # self.send_header('Content-Length', len(response_string))
        # self.send_header('Content-type', 'application/json')

        self.wfile.write(response_string)

    def handle_request(self, request_type):
        route = self.get_route()
        print request_type
        print route

        if route is None or not self.accept_type(request_type):
            self.__not_found()
            return

        if request_type == 'POST':
            if request_type not in route:
                self.__not_found()
                return

            self.send_response(200)
            if 'media_type' in route:
                self.send_header('Content-type', route['media_type'])

            self.end_headers()
            route[request_type]()

            return

        if request_type == 'PUT':
            if request_type not in route:
                self.__not_found()
                return

            self.send_response(200)
            if 'media_type' in route:
                self.send_header('Content-type', route['media_type'])

            self.end_headers()
            route[request_type]()

            return

    def get_route(self):
        for path, route in self.routes.iteritems():
            if re.match(path, self.path):
                return route
        return None


def main():
    PORT = 6578

    http_server = HTTPServer(('', PORT), RequestHandler)
    print 'Starting HTTP server at port %d' % PORT

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass

    print 'Stopping HTTP server'
    http_server.server_close()


if __name__ == '__main__':
    main()
