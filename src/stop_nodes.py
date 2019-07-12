import sys
import os
import signal
import time

from config import Config
from logger import get_logger
from utils import get_running_instances, check_pid

def main():
    logger = get_logger()

    if len(sys.argv) != 2:
        print "Usage: python stop_nodes.py <all|port>"
        return

    port_to_stop = sys.argv[1]
    if port_to_stop == "all":
        port_to_stop = 0
    else:
        port_to_stop = int(port_to_stop)

    instances = get_running_instances()
    if len(instances) == 0:
        logger.info("no running instances")
        return

    # stop instances
    to_kill = []
    for instance in instances:
        pid = instance['pid']
        port = instance['port']
        remove_pid_file = False
        if port_to_stop == 0 or port == port_to_stop:
            to_kill.append(pid)
            logger.debug("stop: port=%r pid=%r", port, pid)
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as e:
                if e.args[0] == 3 and e.args[1] == 'No such process':
                    remove_pid_file = True
                    logger.error("missing node process: port=%r pid=%r", port, pid)
            except Exception as e:
                logger.exception("error: %r", e.args)

        if remove_pid_file:
            logger.info("remove pid file: %s", instance['pid_file_path'])
            os.remove(instance['pid_file_path'])

    #wait until all processes are stopped
    while True:
        try:
            has_running = False
            for pid in to_kill:
                if check_pid(pid, "acestreamengine"):
                    logger.info("still running, wait: pid=%r", pid)
                    has_running = True
                    break

            if has_running:
                time.sleep(1.0)
            else:
                break

        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()