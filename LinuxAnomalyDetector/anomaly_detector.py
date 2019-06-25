import os
import re
import sys
import math
import numpy as np
import copy
import json
import time
import random
import psutil
import sqlite3
import shutil
import collections


from sklearn.neighbors import DistanceMetric, RadiusNeighborsClassifier
from sklearn.cluster import DBSCAN
from scipy import sparse


euclidian_metric = DistanceMetric.get_metric('euclidean')
ANOMALY_RADIUS = 20


def make_chunks(l, n):
    data = []
    for i in range(0, len(l), n):
        data.append(l[i:i + n])

    return data


def compare_lists(x, y):
    return collections.Counter(x) == collections.Counter(y)


def normalize(now, fields, usual):
    if set(now.keys()) == set(usual["events"]) and \
       set(fields) == set(usual['fields']):
        return usual, False

    new_fields = list(set(fields) - set(usual['fields']))

    if len(new_fields) > 0:
        events_number = len(usual['events'])
        remaining_fields = len(new_fields)

        for data in usual['data']:
            data += [0] * (remaining_fields * events_number)

        usual['fields'] += new_fields

    new_events = list(set(now.keys()) - set(usual['events']))
    if len(new_events) > 0:
        for data in usual['data']:
            chunks = make_chunks(data, len(usual['events']))
            for chunk in chunks:
                chunk += [0] * len(new_events)

            data = [item for sublist in chunks for item in sublist]

        usual['events'] += new_events

    return usual, True


def save_usual_events_json(data, time_range):
    try:
        file_path = "knowledge/usual_" + time_range + ".json"

        if os.path.exists(file_path):
            shutil.copy(file_path, file_path + 'bkp')

        random_number = random.randint(1, 999999999)

        tmp_path = file_path + '.' + str(random_number) + '.tmp'
        fhandle = open(tmp_path, 'wb')
        json.dump(data, fhandle)
        fhandle.close()

        shutil.copy(tmp_path, file_path)
        os.remove(tmp_path)
    except KeyboardInterrupt:
        fhandle = open(file_path, 'wb')
        json.dump(data, fhandle)
        fhandle.close()
        print "EXITING ANOMALY DETECTION"
        exit()


def eventdata_to_timestamps(new, usual):
    timestamps_data = dict()

    for event in new:
        for timestamp in new[event]:
            for key in new[event][timestamp]:
                if key == "total_count":
                    continue

                field = new[event][timestamp][key]["comm"]
                count = new[event][timestamp][key]["count"]

                index_event = usual['events'].index(event)
                index_field = usual['fields'].index(field)

                if timestamp not in timestamps_data:
                    timestamps_data[timestamp] = dict()
                    timestamps_data[timestamp]['pid_cmdline'] = []
                    timestamps_data[timestamp]['data'] = [0] * \
                        (len(usual['events']) * len(usual['fields']))

                timestamps_data[timestamp]['data'][len(
                    usual['events']) * index_field + index_event] += count

                timestamps_data[timestamp]['pid_cmdline'].append({
                    'comm': new[event][timestamp][key]["comm"],
                    'pid': key,
                    'cmdline': new[event][timestamp][key]["cmdline"],
                    'event': event
                })

    return timestamps_data


def from_timestamps_to_data(timestamps_data_format):
    return [timestamps_data_format[x]['data']
            for x in timestamps_data_format]


def filter_diplicates(x):
    to_delete = []
    for i in range(len(x)):
        for j in range(i + 1, len(x)):
            dist = euclidian_metric.pairwise([x[i]], [x[j]])[0][0]
            if dist < 2:
                if j not in to_delete:
                    to_delete.append(j)

    to_delete = list(set(to_delete))
    to_delete.sort()

    for i in range(len(to_delete) - 1, -1, -1):
        x.pop(to_delete[i])


maxim_distances = []


def similarity(x, y):
    global maxim_distances
    x = [x]
    y = [y]
    d = euclidian_metric.pairwise(x, y)
    maxim_distances.append(d[0][0])
    return d[0][0]

    # length = len(x)
    # sum = 0
    # for i in range(length):
    #     if min(x[i], y[i]) == 0 and (abs(x[i] - y[i]) > 0.5):
    #         ratio = 0.5
    #     elif x[i] == y[i] and x[i] == 0:
    #         ratio = 0
    #         length -= 1
    #     else:
    #         ratio = 1 - (float(min(x[i], y[i])) / max(x[i], y[i]))

    #     sum += ratio

    # return sum / length


def append_without_dublicates(usual, y, knowledge):
    if len(usual['data']) == 0:
        usual['data'] += y
        return

    maxims, averages = get_maxims_and_averages(knowledge)
    usual_to_fit = normalize_fit_input(
        usual['data'],
        usual['events'],
        usual['fields'],
        averages,
        maxims)

    new_data_to_fit = normalize_fit_input(
        y,
        usual['events'],
        usual['fields'],
        averages,
        maxims)

    classifier = RadiusNeighborsClassifier(
        radius=2,
        metric='euclidean',
        outlier_label=-1)

    classifier.fit(
        sparse.csr_matrix(usual_to_fit),
        [0] * len(usual_to_fit))

    labels = classifier.predict(
        sparse.csr_matrix(new_data_to_fit))

    for i in range(len(labels) - 1, -1, -1):
        if labels[i] != -1:
            y.pop(i)

    usual['data'] += y


def add_new_data_to_cluster(data, usual, knowledge):
    print "ADDING NEW DATA TO CLUSTER"
    t = time.time()
    new_data = eventdata_to_timestamps(data, usual)
    new_data = from_timestamps_to_data(new_data)
    print len(usual['data']), len(new_data)
    full_len = len(new_data) + len(usual['data'])

    filter_diplicates(new_data)
    append_without_dublicates(usual, new_data, knowledge)
    print "DONE ADDING NEW DATA TO CLUSTER", time.time() - t, 'seconds'
    print "REMOVED:", full_len - len(usual['data'])


def get_maxims_and_averages(knowledge):
    maxims = dict()
    averages = dict()

    for event in knowledge:
        maxims[event] = knowledge[event]['max']
        averages[event] = knowledge[event]['average']

    return maxims, averages


def excepted(string, exceptions):
    for exception in exceptions:
        if exception['re_compiled'].search(string) is not None:
            return True

    return False


def suspend_pid(pid):
    try:
        p = psutil.Process(pid)
        p.suspend()
    except psutil.NoSuchProcess:
        return False

    return True


def do_detection(list_to_detect, new_event_timestamps, maxims, to_fit, events, fields, usual, exceptions):
    for timestamp in new_event_timestamps:
        if compare_lists(list_to_detect, new_event_timestamps[timestamp]['data']):
            data = new_event_timestamps[timestamp]['data']
            top_anomaly_score = []

            dump_data = dict()
            for i in range(len(data)):
                field_index = i / len(events)
                event_index = i % len(events)

                if events[event_index] not in dump_data:
                    dump_data[events[event_index]] = dict()

                if data[i] != 0:
                    dump_data[events[event_index]
                              ][fields[field_index]] = data[i]

                if to_fit[i] > 1:
                    top_anomaly_score.append({
                        'score': to_fit[i],
                        'comm': fields[field_index],
                        'event': events[event_index],
                        'no_operations': data[i]
                    })

            top_anomaly_score.sort(key=lambda x: x['score'])

            minim = 99999999999
            for element in usual['data']:
                dist = euclidian_metric.pairwise([element], [to_fit])
                if dist < minim:
                    minim = dist

            # --------------------------------------------
            #           AQUIRE DB DATA
            # --------------------------------------------

            text_to_send = ""
            pids_stopped = []

            text_to_send += '#' * 40 + '\n'
            text_to_send += 'Anomaly detected at:\n'
            text_to_send += '    ' + timestamp + '\n'
            text_to_send += 'Minimum distance from normal data: \n'
            text_to_send += '    ' + str(minim[0][0]) + '\n'
            text_to_send += 'Anomaly event score: \n'
            text_to_send += '    ' + str(sum(to_fit)) + '\n'
            text_to_send += "List of guessed anomaly cause:\n"
            text_to_send += '-' * 40 + '\n'

            title = ""
            for anomaly in top_anomaly_score:
                limit = 0

                if anomaly['event'] == 'file_open':
                    limit = 4
                if anomaly['event'] == 'file_write':
                    limit = 3
                if anomaly['event'] == 'process_create':
                    limit = 3

                if anomaly['score'] >= limit:
                    text_to_send += "process comm:  "
                    text_to_send += anomaly['comm'] + '\n'
                    text_to_send += "process score: "
                    text_to_send += str(anomaly['score']) + '\n'
                    text_to_send += "no operations: "
                    text_to_send += str(anomaly['no_operations']) \
                                    + ' of type ' + anomaly['event'] + '\n'
                    text_to_send += '\n'
                    text_to_send += "Possible processes which caused anomaly:\n"

                    aux_texts = []
                    for pid_cmdline in new_event_timestamps[timestamp]['pid_cmdline']:
                        if pid_cmdline['comm'] == anomaly['comm'] and \
                           pid_cmdline['event'] == anomaly['event']:
                            aux_text = "    "

                            if excepted(pid_cmdline['cmdline'], exceptions):
                                aux_text = "[e] "
                            elif suspend_pid(pid_cmdline['pid']):
                                pids_stopped.append(
                                    "PID: " +
                                    str(pid_cmdline['pid']).ljust(5) +
                                    "\n" +
                                    "cmdline: " +
                                    pid_cmdline['cmdline'])

                                aux_text = "[s] "

                            aux_text += "PID "
                            aux_text += str(pid_cmdline['pid']).rjust(5)
                            aux_text += ": "
                            aux_text += pid_cmdline['cmdline'] + '\n'
                            title = pid_cmdline['cmdline']
                            aux_texts.append(aux_text)

                    aux_texts.sort()
                    for text in aux_texts:
                        text_to_send += text

                    text_to_send += '\n'
                    text_to_send += '-' * 40 + '\n'

            text_to_send += 'All operations json: \n'
            text_to_send += json.dumps(dump_data, indent=4)

            text_to_send += '\n'
            text_to_send += '-' * 40 + '\n'
            text_to_send += '-' * 40 + '\n'
            text_to_send += '#' * 40 + '\n'

            print text_to_send
            print len(text_to_send)

            # --------------------------------------------
            #               ADD ANOMALY TO DB
            # --------------------------------------------

            sql_conn = sqlite3.connect('databases/anomalies.db')

            c = sql_conn.cursor()
            if title == '':
                c.execute("""
                    SELECT max(id) from anomalies
                """)
                entry = c.fetchall()
                if len(entry) > 0:
                    maxid = int(entry[0][0])
                else:
                    maxid = 0

                title = "Anomaly " + str(maxid)

            anomaly_state = json.dumps(list_to_detect)
            c.execute("""
                INSERT INTO anomalies(
                    message, solved,
                    timestamp, priority,
                    alerted, pids_stopped,
                    title, anomaly_state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                text_to_send, 0,
                timestamp.replace('_', ' '),
                sum(to_fit), 0,
                "<|>".join(pids_stopped),
                title, anomaly_state)
            )

            c.execute("""
                UPDATE tracer_config set detect = 0
            """)

            sql_conn.commit()

            # c.execute("""
            #     SELECT * from anomalies order by id desc limit 1
            # """)
            # last_id = int(c.fetchall()[0][0])

            # fhandle = open("knowledge/anomalies/%d.json" % (last_id))
            # json.dump(usual)
            # fhandle.close()

            sql_conn.close()
            return True

    return False


def normalize_fit_input(data, events, fields, averages, maximums):
    normalized = []

    for entry in data:
        new_entry = []
        for i in range(len(entry)):
            field_index = i / len(events)
            event_index = i % len(events)

            if fields[field_index] not in averages[events[event_index]]:
                new_entry.append(entry[i])
                continue

            avg = averages[events[event_index]][fields[field_index]]['avg']
            maxim = maximums[events[event_index]][fields[field_index]]

            avg = (float(maxim) + avg) / 2

            if avg != 0:
                new_entry.append(float(entry[i]) / avg)
            else:
                new_entry.append(entry[i])

        normalized.append(new_entry)

    return normalized


def load_exceptions():
    exceptions_handle = open("configs/exceptions.json")
    exceptions = json.load(exceptions_handle)
    exceptions_handle.close()

    for exception in exceptions:
        exception['re_compiled'] = re.compile(exception['re_string'])

    return exceptions


def load_knowledge_from_file(usual, time_range):
    knowledge = dict()

    for event in usual['events']:
        try:
            knowledge_handle = open("knowledge/" + event +
                                    '_' + time_range + ".json")
        except IOError:
            print "NO knowledge for", event
            knowledge[event] = {
                "max": dict(),
                "average": dict()
            }
            continue

        event_knowledge = json.load(knowledge_handle)
        knowledge_handle.close()

        knowledge[event] = event_knowledge

    return knowledge


def cluster_data(usual, to_fit):
    print 'STARTING CLUSTERING'
    t = time.time()
    print len(to_fit[0])
    dbscan = DBSCAN(eps=ANOMALY_RADIUS,
                    min_samples=2,
                    metric='euclidean')
    dbscan.fit(sparse.csr_matrix(to_fit))
    print 'ENDING CLUSTERING'
    print '------ TOOK', time.time() - t, 'seconds'

    print 'NORMAL DATA MEAN SCORE', \
        float(sum([sum(x) for x in to_fit])) / len(to_fit)

    labels = []
    last = max(dbscan.labels_) + 1
    for label in dbscan.labels_:
        if label == -1:
            labels.append(last)
            last += 1
        else:
            labels.append(label)

    usual['labels'] = labels

    print "DIFFERENT LABELS", set(labels)
    print "DIFFERENT LABELS", len(labels)


def cluster_learned(time_range):
    usual = load_usual_data(time_range)

    knowledge = load_knowledge_from_file(usual, time_range)

    maxims, averages = get_maxims_and_averages(knowledge)
    to_fit = normalize_fit_input(
        usual['data'], usual['events'], usual['fields'],
        averages, maxims)

    # -----------------------------------
    # CLUSTERING OLD EVENTS
    # -----------------------------------

    cluster_data(usual, to_fit)
    save_usual_events_json(usual, time_range)

    print "DONE SAVING"
    print "EXITING"
    exit(0)


def load_usual_data(time_range, iteration=30):
    if iteration == 0:
        return None

    if not os.path.exists("knowledge/usual_" + time_range + ".json"):
        usual = {
            "fields": [],
            "data": [],
            "events": []
        }
    else:
        try:
            usual_handle = open("knowledge/usual_" + time_range + ".json")
            usual = json.load(usual_handle)
            usual_handle.close()
        except ValueError:
            time.sleep(1)
            usual = load_usual_data(time_range, iteration - 1)

    return usual


def detect(containers, fields, time_range, learning=True, usual_file=None, stdout=None):
    global maxim_distances

    if stdout is not None:
        sys.stdout = stdout

    data = dict()
    knowledge = dict()

    exceptions = load_exceptions()

    if time_range == 'seconds':
        print '-' * 50
        print "SECONDS"
        print '-' * 50

    for container in containers:
        data[container.module_data['name']] = copy.deepcopy(
            container.database_events[time_range])

        knowledge[container.module_data['name']] = copy.deepcopy(
            container.database_info[time_range])

    usual = load_usual_data(time_range)
    usual, changed = normalize(
        data, fields, usual)

    if changed and not learning:
        save_usual_events_json(usual, time_range)

    if learning:
        add_new_data_to_cluster(data, usual, knowledge)
        save_usual_events_json(usual, time_range)
        return

    # -----------------------------------
    # NOT LEARNING ---> PREDICT
    # -----------------------------------

    maxims, averages = get_maxims_and_averages(knowledge)
    usual_to_fit = normalize_fit_input(
        usual['data'],
        usual['events'],
        usual['fields'],
        averages,
        maxims)
    # -----------------------------------
    # PREPARING TO PREDICTs
    # -----------------------------------

    new_timestamps = eventdata_to_timestamps(data, usual)
    new_data = from_timestamps_to_data(new_timestamps)
    new_data_to_fit = normalize_fit_input(
        new_data,
        usual['events'],
        usual['fields'],
        averages,
        maxims)

    classifier = RadiusNeighborsClassifier(
        radius=ANOMALY_RADIUS,
        metric=similarity,
        outlier_label=-1)

    print "PREDICTING"
    t = time.time()

    if len(usual['labels']) < len(usual_to_fit):
        cluster_data(usual, usual_to_fit)
        save_usual_events_json(usual, time_range)

    classifier.fit(usual_to_fit, usual['labels'])
    labels = classifier.predict(new_data_to_fit)
    print "PREDICTION TOOK", time.time() - t, "seconds"

    print 'maxim distances:', sorted(maxim_distances, reverse=True)[:10]
    print 'NEW SAMPLES LABELS: ', labels

    # -----------------------------------
    # DONE PREDICTION
    # -----------------------------------

    events = usual['events']
    fields = usual['fields']

    for i in range(len(new_data) - 1, -1, -1):
        if labels[i] == -1:
            detected = do_detection(
                new_data[i],
                new_timestamps,
                maxims,
                new_data_to_fit[i],
                events,
                fields,
                usual,
                exceptions)

            # if detected and not learning:
            #     del new_data[i]
            #     change_occured = True

    # if change_occured:
    #     save_usual_events_json(usual,
    #                            "knowledge/usual_" + time_range + ".json")
