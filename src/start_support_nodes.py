"""
Start support nodes for this host.
List of sources is retrieved from http://<controller>/support_node/get_config.php which detects this host by ip.
"""
import json
import os
import sys
import subprocess
import urllib2
import requests
import signal
import argparse
import psutil
import logging

from logger import get_logger
from config import Config
from utils import get_running_instances, get_node_data
from errors import UserError

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

logger = get_logger("start_support_nodes")

DETACHED_PROCESS = 0x00000008
MIN_CACHE_SIZE = 50*1024*1024
MAX_CACHE_SIZE = 1024*1024*1024
RESERVE_PER_PROCESS_MEMORY = 50*1024*1024
USE_PERCENT_FROM_TOTAL_MEMORY = 0.8

COMMON_ARGS = [
    '--stream-support-node',
    '--close-connections-from-same-peer', '1',
    '--max-peers', '10',
    '--core-sandbox-max-peers', '1',
    '--core-max-fast-peers', '1',
    '--stats-report-interval', '4',
    '--stats-report-peers',
    '--service-remote-access',
    '--live-cache-type', 'memory',
    '--log-backup-count', '1',
]

COMMON_DEBUG_ARGS = [
    '--log-debug', '1',
    '--log-modules', 'root:D',
    '--log-max-size', '100000000',
    '--debug-multicast-pex',
    '--debug-encoder',
    '--debug-encoder-connection',
    '--debug-download-live',
    '--debug-connecter',
    '--debug-connecter-connection',
    '--debug-downloader',
    '--debug-single-download',
    '--debug-picker-client',
    '--debug-client-transporter',
    '--debug-memory-usage',
    '--debug-pieces',
    '--debug-storage',
    '--debug-rerequester',
    '--debug-rerequester-dht',
    '--debug-dht',
    '--debug-magnet',
]

def start_single_stream(port, config, stream_data, cli_args):
    port = int(port)

    required_keys = [
        'cache_size',
        'extended_logging',
        'engine_version',
    ]
    for k in required_keys:
        if not k in stream_data:
            raise UserError("Missing %r in stream data" % (k,))

    try:
        cache_size = int(stream_data['cache_size'])
    except:
        raise UserError("Malformed cache_size: %r" % (stream_data['cache_size'],))

    if cache_size < MIN_CACHE_SIZE:
        raise UserError("Too low: cache_size=%r min=%r" % (cache_size, MIN_CACHE_SIZE))

    logger.info(
        "%s: port=%d engine=%s debug=%r cache=%r source=%s",
        "DRY-RUN" if cli_args.dry_run else "start",
        port,
        stream_data['engine_version'],
        stream_data['extended_logging'],
        stream_data['cache_size'],
        stream_data['download_from']
        )

    stream_data['extended_logging'] = int(stream_data['extended_logging'])

    token = config.get("node_access_token", required=False)
    log_path = os.path.join(config.get_dir("log"), "support_node_%d.log" % (port,))
    cache_path = os.path.join(config.get_dir("cache"), "support_node_%d_cache" % (port,))
    state_path = os.path.join(config.get_dir("state"), "support_node_%d_state" % (port,))
    engine_path = config.get_engine_path(stream_data['engine_version'])

    if cli_args.clear_logs_on_start and os.path.isfile(log_path):
        os.remove(log_path)

    if token:
        transport_file_url = "http://%s/app/%s/get_transport_file?format=raw" % (stream_data['download_from'], token)
    else:
        transport_file_url = "http://%s/app/get_transport_file?format=raw" % (stream_data['download_from'],)

    args = [
        engine_path,
        '--log-file', str(log_path),
        '--port', str(port),
        '--url', transport_file_url,
        '--download-from', stream_data['download_from'],
        '--cache-dir', str(cache_path),
        '--state-dir', str(state_path),
        '--pid-file-dir', str(config.get_dir("pid")),
        '--live-mem-cache-size', str(cache_size),
    ]

    if token:
        args.extend(['--service-access-token', str(token)])

    args.extend(COMMON_ARGS)

    if stream_data['extended_logging'] == 1:
        args.extend(COMMON_DEBUG_ARGS)

    if cli_args.dry_run:
        logger.info('DRY-RUN: start engine: args=%r', args)
    else:
        if sys.platform == "win32":
            subprocess.Popen(args, creationflags=DETACHED_PROCESS, stdin=None, stderr=subprocess.STDOUT, stdout=open(log_path, "a"))
        else:
            # need "nohup" otherwise engine process will stop on shell logout
            args.insert(0, 'nohup')
            subprocess.Popen(args, close_fds=True, stdin=None, stderr=subprocess.STDOUT, stdout=open(log_path, "a"))

    return True

def get_config(config, args):
    controller_path = config.get_controller("support_node")

    if controller_path.startswith("http:") or controller_path.startswith("https:"):
        streams = get_remote_config(controller_path, config, args)
    else:
        streams = get_local_config(controller_path, config, args)

    for node_config in streams:
        # add "download_from" field
        node_config['source_port'] = int(node_config['source_port'])
        node_config['download_from'] = "%s:%d" % (node_config['source_ip'], node_config['source_port'])

    return streams

def get_remote_config(url, config, cli_args):
    r = requests.get(url)
    r.raise_for_status()
    data = r.json()

    if 'error' in data:
        raise UserError('get_remote_config: server returned error: %s' % (data['error'],))
    elif not 'result' in data:
        raise UserError('get_remote_config: missing "result" in response')

    return data['result']

def get_local_config(path, config, args):
    path = config.get_abs_path(path)
    with open(path, 'rb') as f:
        return json.load(f)

def parse_args():
    params = sys.argv[1:]
    parser = argparse.ArgumentParser(prog="monitor")

    parser.add_argument("--port", help="port of node to start", type=int)
    parser.add_argument("--dry-run", help="dry run", action="store_true")
    parser.add_argument("--clear-logs-on-start", help="clear logs on start", action="store_true")

    return parser.parse_args(params)

def main():
    args = parse_args()

    try:
        config = Config()

        streams = get_config(config, args)
        instances = get_running_instances(with_data=True)

        logger.info("%d running instances, loaded %d sources", len(instances), len(streams))

        instances_by_port = {}
        busy_ports = set()
        running_sources = {}

        for instance in instances:
            if instance.get('data') is not None:
                busy_ports.add(instance['port'])
                download_from_list = instance['data'].get('download_from')
                if not download_from_list:
                    logger.error("instance with no 'download_from' info: pid=%r port=%r", instance['pid'], instance['port'])
                elif len(download_from_list) != 1:
                    logger.error("only one 'download_from' is supported: pid=%r port=%r count=%r", instance['pid'], instance['port'], len(download_from_list))
                else:
                    download_from = download_from_list[0]
                    # |download_from| is a tuple (ip, port)
                    source_addr = "%s:%s" % (download_from[0], download_from[1])
                    running_sources[source_addr] = instance['port']
                    instances_by_port[instance['port']] = instance
            else:
                logger.error("instance with no data: pid=%r port=%r", instance['pid'], instance['port'])

        if len(streams) > 0:
            mem = psutil.virtual_memory()
            cache_size = int(mem.total * USE_PERCENT_FROM_TOTAL_MEMORY / len(streams))
            cache_size -= RESERVE_PER_PROCESS_MEMORY

            if cache_size < MIN_CACHE_SIZE:
                cache_size = MIN_CACHE_SIZE
            elif cache_size > MAX_CACHE_SIZE:
                cache_size = MAX_CACHE_SIZE

        for node_config in streams:
            node_config['port'] = int(node_config['port'])
            node_config['cache_size'] = cache_size

            if args.port and int(node_config['port']) != int(args.port):
                continue

            download_from = node_config['download_from']

            if download_from in running_sources:
                port = running_sources[download_from]
                logger.debug("already running: source_addr=%s port=%r", download_from, port)
                instances_by_port[port]['_exists'] = True
            else:
                port = node_config['port']
                if port in busy_ports:
                    raise UserError("port is busy: %r" % (port,))

                try:
                    if start_single_stream(port, config, node_config, args):
                        busy_ports.add(port)
                        running_sources[download_from] = port
                except UserError as e:
                    logger.error("failed to start node: port=%r err=%s", port, str(e))

        # check running instances which are not in the playlist
        if not args.port:
            for instance in instances:
                exists = instance.get('_exists')
                if not exists:
                    url = None
                    download_from_list = None
                    if instance.get('data') is not None:
                        download_from_list = instance['data'].get('download_from')

                    if args.dry_run:
                        logger.info("DRY-RUN: instance not exists in the playlist, stop: pid=%r port=%r download_from_list=%s\r", instance['pid'], instance['port'], download_from_list)
                    else:
                        logger.info("instance not exists in the playlist, stop: pid=%r port=%r download_from_list=%s\r", instance['pid'], instance['port'], download_from_list)
                        try:
                            os.kill(instance['pid'], signal.SIGTERM)
                        except:
                            logger.info("failed to stop instance: pid=%r port=%r", instance['pid'], instance['port'])

    except UserError as e:
        print str(e)

if __name__ == "__main__":
    main()
