import argparse
import json
import os
import sys
import subprocess
import urllib2
import urlparse
import re
import hashlib
import signal
import requests
import logging
import psutil

from logger import get_logger
from config import Config
from utils import (
    get_running_instances,
    encode_fs,
    get_m3u_tag
    )
from common import ALLOWED_CATEGORIES
from errors import UserError

logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

logger = get_logger("start")

DETACHED_PROCESS = 0x00000008
MIN_CACHE_SIZE = 50*1024*1024
MAX_CACHE_SIZE = 1024*1024*1024
RESERVE_PER_PROCESS_MEMORY = 50*1024*1024
USE_PERCENT_FROM_TOTAL_MEMORY = 0.6

COMMON_ARGS = [
    '--stream-source-node',
    '--private-node', '1',
    '--monitor-node-ip', '127.0.0.1',
    '--skip-internal-tracker',
    '--source-reconnect-interval', '20',
    '--close-connections-from-same-peer', '1',
    '--max-peers', '10',
    '--stats-report-interval', '4',
    '--stats-report-peers',
    '--service-remote-access',
    '--permanent',
    '--live-cache-type', 'memory',
    '--log-backup-count', '1',
]

COMMON_ARGS_HLS = [
    '--stream-support-node',
    '--private-node', '1',
    '--monitor-node-ip', '127.0.0.1',
    '--hide-hls-segments',
    '--hls-broadcast-last-source-piece',
    '--hls-bad-manifest-max-errors', '5',
    '--hls-bad-manifest-retry-interval', '2',
    '--close-connections-from-same-peer', '1',
    '--max-peers', '10',
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
]

def get_config(config, args):
    controller_path = config.get_controller("source_node")

    if controller_path.startswith("http:") or controller_path.startswith("https:"):
        return get_remote_config(controller_path, config, args)
    else:
        return get_local_config(controller_path, config, args)

def get_remote_config(url, config, args):
    if args.get_remote_metadata:
        if "?" in url:
            url += "&get_metadata"
        else:
            url += "?get_metadata"

    r = requests.get(url)
    r.raise_for_status()
    response = r.json()

    if 'error' in response:
        raise UserError(response['error'])
    elif not 'result' in response:
        raise UserError("missing result")

    return response['result']

def get_local_config(path, config, args):
    #TODO: handle 'args.get_remote_metadata'
    path = config.get_abs_path(path)
    with open(path, 'rb') as f:
        return json.load(f)

def get_base_url(url):
    p = urlparse.urlparse(url)
    return urlparse.urlunparse((p.scheme, p.netloc, p.path, None, None, None))

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def update_metadata(stream_name, metadata, args):
    config = Config()

    metadata_dir = config.get_dir("metadata")

    last_seq = int(metadata['last_seq'])
    private_key = metadata['private_key']

    if not (stream_name and last_seq and private_key):
        return False

    seq_path = os.path.join(metadata_dir, "%s.restart" % (stream_name,))
    key_path = os.path.join(metadata_dir, "%s.sauth" % (stream_name,))

    if os.path.isfile(seq_path):
        with open(seq_path, 'rb') as f:
            local_seq = int(f.read())
        if local_seq != last_seq:
            logger.error("metadata mismatch seq: local=%r remote=%r path=%s", local_seq, last_seq, seq_path)
            return False

    if os.path.isfile(key_path):
        with open(key_path, 'rb') as f:
            local_private_key = f.read()
        if local_private_key != private_key:
            logger.error("metadata mismatch seq: local_hash=%s remote_hash=%s path=%s", hashlib.sha1(local_private_key).hexdigest(), hashlib.sha1(private_key).hexdigest(), key_path)
            return False

    if args.dry_run:
        logger.info("DRY-RUN: update metadata: seq_path=%s key_path=%s", seq_path, key_path)
    else:
        write_file(seq_path, str(last_seq))
        write_file(key_path, str(private_key))

    return True

def create_transport_files(config, stream_data, url, base_url, title, public_path, private_path, sid, categories):
    logger.info(
        "create_transport_files: title=%s url=%s public=%s private=%s",
        title,
        url,
        public_path,
        private_path
        )

    engine_path = config.get_engine_path(stream_data['engine_version'])

    args = [
        str(engine_path),
        '--create-hls-transport',
        '--hide-hls-manifest',
        '--title', encode_fs(title),
        '--url', str(url),
        '--output-public', str(public_path),
        '--output-private', str(private_path),
        '--sid', str(sid),
        '--log-debug', '1',
    ]

    if base_url:
        args.extend(['--base-url', str(base_url)])

    provider_key = config.get_provider_key()
    if provider_key:
        args.extend(['--provider-key', str(provider_key)])

    # add trackers
    for t in config.get_trackers():
        args.extend(['--tracker', str(t)])

    # add categories
    for c in categories:
        if not c in ALLOWED_CATEGORIES:
            logger.error("bad category: %s", c)
        else:
            args.extend(['--category', str(c)])

    retval = subprocess.call(args)
    logger.info("create_transport_files: retval=%r", retval)
    return (retval == 0)


def start_single_stream(name, sid, port, config, stream_data, cli_args, force_create_transport_file=True):
    required_keys = [
        'cache_size',
        'extended_logging',
        'engine_version',
    ]
    for k in required_keys:
        if not k in stream_data:
            raise UserError("Missing %r in stream data: port=%r" % (k, port))

    try:
        cache_size = int(stream_data['cache_size'])
    except:
        raise UserError("Malformed cache_size: %r" % (stream_data['cache_size'],))

    if cache_size < MIN_CACHE_SIZE:
        raise UserError("Too low: cache_size=%r min=%r" % (cache_size, MIN_CACHE_SIZE))

    logger.info("%s: engine=%s debug=%r name=%s port=%r cache=%r",
        "DRY-RUN" if cli_args.dry_run else "start",
        stream_data['engine_version'],
        stream_data['extended_logging'],
        name,
        port,
        stream_data['cache_size']
        )

    stream_data['extended_logging'] = int(stream_data['extended_logging'])

    log_path = os.path.join(config.get_dir("log"), "source_node_%d.log" % (port,))
    cache_path = os.path.join(config.get_dir("cache"), "source_node_%d_cache" % (port,))
    state_path = os.path.join(config.get_dir("state"), "source_node_%d_state" % (port,))
    engine_path = config.get_engine_path(stream_data['engine_version'])

    if cli_args.clear_logs_on_start and os.path.isfile(log_path):
        os.remove(log_path)

    # paths for hls transport files
    public_path = os.path.join(config.get_dir("public"), "%s.acelive" % (name,))
    private_path = os.path.join(config.get_dir("private"), "%s_private.acelive" % (name,))

    if stream_data['type'] == 'ts':
        bitrate = int(stream_data['bitrate'])
        if bitrate <= 0:
            logger.error("skip stream with null bitrate: port=%r url=%s", port, stream_data['url'])
            return False

        args = [
            engine_path,
            '--log-file', str(log_path),
            '--port', str(port),
            '--source', str(stream_data['url']),
            '--bitrate', str(bitrate),
            '--name', str(name),
            '--title', encode_fs(stream_data['title']),
            '--quality', stream_data['quality'],
            '--publish-dir', str(config.get_dir("public")),
            '--metadata-dir', str(config.get_dir("metadata")),
            '--cache-dir', str(cache_path),
            '--state-dir', str(state_path),
            '--pid-file-dir', str(config.get_dir("pid")),
            '--provider-key', str(config.get_provider_key()),
            '--sid', str(sid),
            '--live-mem-cache-size', str(cache_size),
        ]

        # add trackers
        for t in config.get_trackers():
            args.extend(['--tracker', str(t)])

        # add categories
        for c in stream_data['categories']:
            if not c in ALLOWED_CATEGORIES:
                logger.error("bad category: category=%s url=%s", c, stream_data['url'])
            else:
                args.extend(['--category', str(c)])

        args.extend(COMMON_ARGS)

        if 'metadata' in stream_data:
            if not update_metadata(stream_data['stream_uid'], stream_data['metadata'], cli_args):
                return False

    elif stream_data['type'] == 'hls':
        if (cli_args.force_creating_transport_files
            or not (os.path.isfile(private_path) and os.path.isfile(public_path))):
            if not create_transport_files(
                config,
                stream_data,
                stream_data['url'],
                get_base_url(stream_data['url']),
                stream_data['title'],
                public_path,
                private_path,
                sid,
                stream_data['categories']
                ):
                return False

        args = [
            engine_path,
            '--log-file', str(log_path),
            '--port', str(port),
            '--url', private_path,
            '--public-transport-file', public_path,
            '--cache-dir', str(cache_path),
            '--state-dir', str(state_path),
            '--metadata-dir', str(config.get_dir("metadata")),
            '--pid-file-dir', str(config.get_dir("pid")),
            '--live-mem-cache-size', str(cache_size),
        ]

        args.extend(COMMON_ARGS_HLS)

        if 'force_monotonic_sequence' in stream_data:
            args.extend(['--hls-force-monotonic-sequence', str(stream_data['force_monotonic_sequence'])])

    else:
        logger.error("unknown stream type: %s", stream_data['type'])
        return False

    # common params
    token = config.get("node_access_token", required=False)
    if token:
        args.extend(['--service-access-token', str(token)])

    if 'upload_to' in stream_data:
        for addr in stream_data['upload_to']:
            args.extend(['--upload-to', addr])

    if stream_data['extended_logging'] == 1:
        args.extend(COMMON_DEBUG_ARGS)

    if cli_args.dry_run:
        logger.info('DRY-RUN: start engine: args=%r', args)
        pass
    else:
        if sys.platform == "win32":
            subprocess.Popen(args, creationflags=DETACHED_PROCESS, stdin=None, stderr=subprocess.STDOUT, stdout=open(log_path, "a"))
        else:
            # need "nohup" otherwise engine process will stop on shell logout
            args.insert(0, 'nohup')
            subprocess.Popen(args, close_fds=True, stdin=None, stderr=subprocess.STDOUT, stdout=open(log_path, "a"))

    return True

def parse_args():
    params = sys.argv[1:]
    parser = argparse.ArgumentParser(prog="monitor")

    # params definitions
    parser.add_argument("--port", help="port of node to start", type=int)
    parser.add_argument("--dry-run", help="dry run", action="store_true")
    parser.add_argument("--get-remote-metadata", help="get remote metadata", action="store_true")
    parser.add_argument("--force-creating-transport-files", help="force creating transport files", action="store_true")
    parser.add_argument("--clear-logs-on-start", help="clear logs on start", action="store_true")

    return parser.parse_args(params)

def main():
    args = parse_args()

    try:
        config = Config()

        instances = get_running_instances(with_data=True)
        streams = get_config(config, args)

        logger.info("%d running instances, loaded %d streams", len(instances), len(streams))

        instances_by_port = {}
        busy_ports = set()
        running_source_urls = {}

        for instance in instances:
            if instance.get('data') is not None:
                busy_ports.add(instance['port'])

                if 'source_url' in instance['data']:
                    url = instance['data']['source_url']
                elif 'hls_manifest_url' in instance['data']:
                    url = instance['data']['hls_manifest_url']
                else:
                    url = None

                if not url:
                    logger.error("instance with no source url: pid=%r port=%r", instance['pid'], instance['port'])
                else:
                    url = get_base_url(url)
                    running_source_urls[url] = {
                        'port': instance['port'],
                        'pid': instance['pid'],
                        }
                    instances_by_port[instance['port']] = instance
            elif 'error' in instance:
                logger.error("instance failed: pid=%r port=%r error=%s", instance['pid'], instance['port'], instance['error'])
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

        port_map = {}
        for stream_data in streams:
            if args.port and int(stream_data['port']) != int(args.port):
                continue

            stream_url = get_base_url(stream_data['url'])
            stream_name = stream_data['stream_uid']
            stream_data['cache_size'] = cache_size

            if stream_url in running_source_urls:
                port = running_source_urls[stream_url]['port']
                pid = running_source_urls[stream_url]['pid']
                logger.debug("already running: url=%s port=%r pid=%r", stream_url, port, pid)
                instances_by_port[port]['_exists'] = True
            else:
                port = int(stream_data['port'])
                if port in busy_ports:
                    raise UserError("port is busy: port=%r url=%s" % (port, stream_url))

                stream_started = start_single_stream(stream_name, stream_name, port, config, stream_data, args)

                if stream_started:
                    busy_ports.add(port)
                    running_source_urls[stream_url] = {
                        'port': port,
                        'pid': 0,
                    }

            port_map[stream_name] = {
                'title': stream_data['title'],
                'url': stream_url,
                'port': port
                }

        # check running instances which are not in the playlist
        if not args.port:
            for instance in instances:
                exists = instance.get('_exists')
                if not exists:
                    url = None
                    if instance.get('data') is not None:
                        url = instance['data'].get('source_url')
                    logger.info("instance not exists in the playlist, stop: pid=%r port=%r url=%s", instance['pid'], instance['port'], url)

                    if not args.dry_run:
                        try:
                            os.kill(instance['pid'], signal.SIGTERM)
                        except:
                            logger.info("failed to kill instance: pid=%r port=%r", instance['pid'], instance['port'])

        if not args.dry_run:
            path = os.path.join(config.get_dir("public"), "port_map.json")
            with open(path, 'w') as f:
                json.dump(port_map, f, indent=4)

    except UserError as e:
        print "Error", e

if __name__ == "__main__":
    main()
