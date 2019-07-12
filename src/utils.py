import os
import sys
import re
import psutil
import requests

from config import Config
from logger import get_logger

logger = get_logger("utils")

def ensure_dir_exists(path):
    if not os.path.isdir(path):
        os.makedirs(path)
    return True

def get_node_data(port):
    config = Config()
    token = config.get("node_access_token")

    if token:
        url = "http://127.0.0.1:%d/app/%s/monitor" % (port,token)
    else:
        url = "http://127.0.0.1:%d/app/monitor" % (port,)

    r = requests.get(url)
    r.raise_for_status()
    return r.json()

def get_running_instances(with_data=False):
    """
    Return list of dicts {pid: X, port: Y}
    """
    config = Config()

    pid_dir = config.get_dir("pid")
    if not os.path.isdir(pid_dir):
        logger.info("missing pid dir: %r", pid_dir)
        return

    # get all files in pid dir
    files = []
    for (dirpath, dirnames, filenames) in os.walk(pid_dir):
        files.extend(filenames)
        break

    # filter files
    pid_files = []
    for f in files:
        if f.endswith(".pid"):
            pid_files.append(f)

    if len(pid_files) == 0:
        return []

    # get pids, parse ports from filename
    result = []
    for filename in pid_files:
        path = os.path.join(pid_dir, filename)
        with open(path, "rb") as f:
            pid = f.read()

        pid = pid.strip()
        pid = int(pid)

        m = re.match('^acestreamengine-(\\d+)\\.pid$', filename, re.I)
        if not m:
            raise Exception("malformed pid file: %r" % (path,))

        port = int(m.group(1))
        instance = {
            'pid': pid,
            'port': port,
            'pid_file_path': path,
            }

        if with_data:
            try:
                instance['data'] = get_node_data(port)
            except Exception as e:
                instance['error'] = e

        result.append(instance)

    return result

def check_pid(pid, process_name=None):
    """
    Check For the existence of a unix pid.
    If `process_name` is given then ensure that pid and process name match

    Sending signal 0 to a pid will raise an OSError exception if the pid is not running, and do nothing otherwise.
    @see http://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
    """
    try:
        os.kill(pid, 0)

        if process_name:
            p = psutil.Process(pid)
            return p.name() == process_name

        return True
    except OSError:
        return False

def ensure_utf8(s):
    if isinstance(s, str):
        return s
    elif isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return ""

def encode_fs(s):
    if isinstance(s, str):
        return s.decode("utf-8").encode(sys.getfilesystemencoding())
    elif isinstance(s, unicode):
        return s.encode(sys.getfilesystemencoding())
    else:
        return ""

def get_m3u_tag(item, tagname):
    if item.tags and tagname in item.tags:
        value = item.tags[tagname]
    else:
        value = None
    return value

