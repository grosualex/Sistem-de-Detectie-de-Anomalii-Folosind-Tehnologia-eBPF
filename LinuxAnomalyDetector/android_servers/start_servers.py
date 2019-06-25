import decision_server
import notification_server

from multiprocessing import Process


def main():
    decision = Process(target=decision_server.main, args=tuple())
    notification = Process(target=notification_server.main, args=tuple())

    decision.start()
    notification.start()


if __name__ == '__main__':
    main()
