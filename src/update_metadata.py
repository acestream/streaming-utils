import sys
import os
import time
import requests
import logging

from config import Config
from logger import get_logger

logging.getLogger("urllib3").setLevel(logging.WARNING)

logger = get_logger()

def send_metadata(endpoint_url, config, data):
    r = requests.post(endpoint_url, json=data)
    r.raise_for_status()
    return r.json()

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def main():
    config = Config()

    endpoint_url = config.get_controller("metadata_receiver", required=False)
    if endpoint_url is None:
        logger.error("metadata receiver endpoint is not set (check your config)")
        return

    metadata = {}
    metadata_dir = config.get_dir("metadata")
    for filename in os.listdir(metadata_dir):
        path = os.path.join(metadata_dir, filename)
        (stream_name, ext) = os.path.splitext(filename)

        if not ext in [".restart", ".sauth"]:
            continue

        if not stream_name in metadata:
            metadata[stream_name] = {
                'last_seq': None,
                'private_key': None,
            }
        if ext == ".restart":
            metadata[stream_name]['last_seq'] = int(read_file(path))
        elif ext == ".sauth":
            metadata[stream_name]['private_key'] = read_file(path)

    # verify
    for stream_name, data in metadata.iteritems():
        keys = ['last_seq', 'private_key']
        for key in keys:
            if data[key] is None:
                print "missing %r for stream %s" % (key, stream_name)
                return

    ret = send_metadata(endpoint_url, config, metadata)
    print ret

if __name__ == "__main__":
    main()
