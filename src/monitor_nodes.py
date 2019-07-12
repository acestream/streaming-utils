import sys
import os
import json
import requests
import logging
import argparse

from utils import get_running_instances, get_node_data
from logger import get_logger
from config import Config

logger = get_logger("monitor-nodes")

# suppress 'urllib3' logging
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

def send_instance_data(endpoint_url, config, data):
    try:
        payload = json.dumps(data)
        r = requests.post(endpoint_url, data=payload)
        return True
    except:
        logger.exception("failed to send data")
        return False

def parse_args():
    params = sys.argv[1:]
    parser = argparse.ArgumentParser(prog="app")

    parser.add_argument("--node-type", help="node type", choices=["source", "support"], required=True)

    return parser.parse_args(params)

def main():
    cli_args = parse_args()
    config = Config()

    endpoint_url = config.get_controller("monitor", required=False)
    if endpoint_url is None:
        logger.error("monitor endpoint is not set (check your config)")
        return

    instances = get_running_instances(with_data=True)

    for instance in instances:
        if instance.get('data') is not None:
            data = instance['data']
            port = int(instance['port'])
            data['port'] = port

            # Set node type from CLI because HLS sources have type 'support'
            data['type'] = cli_args.node_type

            send_instance_data(endpoint_url, config, data)

        else:
            logger.error("instance with no data: pid=%r port=%r", instance['pid'], instance['port'])

if __name__ == "__main__":
    main()