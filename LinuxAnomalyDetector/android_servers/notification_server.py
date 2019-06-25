import socket
import sqlite3
import errno
import time
import sys

HOST = '0.0.0.0'
PORT = 6579


def new_anomalies(addr):
    sql_conn = sqlite3.connect('../databases/anomalies.db')
    c = sql_conn.cursor()

    c.execute("""
        SELECT id, alerted from anomalies where solved = 0
    """)

    result = [str(x[0]) for x in c.fetchall()
              if addr[0] not in x[1]]

    if len(result) > 0:
        return True, result

    sql_conn.close()
    return False, None


def set_alerted(ids, addr):
    sql_conn = sqlite3.connect('../databases/anomalies.db')
    c = sql_conn.cursor()

    c.execute("""
        SELECT id, alerted from anomalies where id in (%s)
    """ % (','.join(ids)))

    data = c.fetchall()

    print data

    for entry in data:
        id = entry[0]
        alerted = entry[1]
        address = addr[0]

        if address not in alerted:
            c.execute("""
                UPDATE anomalies set alerted = ? where id = ?
            """, (alerted + '<|>' + address, id))

    sql_conn.commit()
    sql_conn.close()


def main():
    print "STARTING NOTIFICATION SERVER"
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        conn, addr = s.accept()

        try:
            print('Connected by', addr)
            while True:
                exists_new, result = new_anomalies(addr)
                if exists_new:
                    print 'sending anomalies'
                    conn.sendall("alert\n")
                    set_alerted(result, addr)
                else:
                    conn.sendall("n\n")

                data = conn.recv(1024)
                time.sleep(3)
        except IOError, e:
            if e.errno == errno.EPIPE:
                sys.stdout.write("CONNECTION CLOSED\n")
        except Exception as e:
            s.close()
            print e


if __name__ == '__main__':
    main()
