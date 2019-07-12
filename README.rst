Overview
========

This repo contains a set of utilities to start streaming with Ace Stream.

Utilities themselves are wrappers (written in Python) around Ace Stream app which can be downloaded here: http://wiki.acestream.org/wiki/index.php/Download#Linux

You should be familiar with this info to understand what's happening:

* http://wiki.acestream.org/wiki/index.php/Streaming
* http://wiki.acestream.org/wiki/index.php/Create_HLS_Broadcast

Features currently available:

* start a set of source/support nodes based on config
* local (JSON file) and remote (URL which return JSON) configs are supported
* stop nodes
* collect info about running nodes and send it to monitoring server

Usage
=====

Start all source nodes:
``python src/start_source_nodes.py``

Start all support nodes:
``python src/start_support_nodes.py``

When all source/support nodes are started app always tries to match running nodes with config.
This means that:

* all nodes from config are started if they were not already started
* when there are running nodes which are not present in config they are stopped

Start single source node by port:
``python src/start_source_nodes.py --port <port>``

Start single support node by port:
``python src/start_support_nodes.py --port <port>``

Stop all running nodes:
``python src/stop_nodes all``

Stop single node by its port:
``python src/stop_nodes <port>``

Send monitoring data and metadata to configured endpoints (usually you run this periodically from cron job):
``python src/monitor_nodes.py --node-type <source|support>``
``python src/update_metadata.py``

App Config
==========

App config describes environment and sets some global options.
It should be placed in ``config/config.json`` file.

Options:

* ``engine_path``: path to engine executable (usually it's ``start-engine`` shell script).
  You can specify path to three engine versions. Which one is used is set in the config for each stream.

  * ``stable``: path to stable version
  * ``beta``: path to beta version
  * ``alpha``: path to alpha version

* ``root``: root folder (all other dirs are described relatively to root)
* ``controller``: list of endpoints used by tool to communicate with other apps.
  Some endpoints can be both local or remote.
  Local endpoint is set as path to local file (either absolute or relatively to ``root``)
  Remote endpoint is set as an URL (it must start with http: or https:)

  * ``source_node``: path to `source node config`_ (local or remote)
  * ``support_node``: path to `support node config`_ (local or remote)
  * ``monitor``: URL which will receive monitoring data (remote only)
  * ``metadata_receiver``: URL which will receive nodes' metadata (remote only)

* ``dirs``: path to dirs which are used by this tool
* ``trackers``: list of trackers_ (you must add at least one tracker)
* ``provider_key``: optional `provider key`_
* ``node_access_token``: optional `node access token`_


Trackers
--------
Preferred tracker is XBT (https://github.com/OlafvdSpek/xbt)
You should add tracker's announce URL to the config (e.g. ``udp://tracker1.example.com:2710/announce``)


Provider key
------------
It's a string which identifies you as a broadcaster. It's written to transport file and used by clients when they send statistics to P2P network.


Node access token
-----------------
It's a string which prevents unauthorized access to node's API interface (see http://wiki.acestream.org/wiki/index.php/AceStream_3.0/en#Node.27s_web-interface)


Source node config
------------------

See ``examples/source_node_config.json``

* ``stream_uid``: internal unique stream id; your should use only latin chars, digits and underscores
* ``title``: title of stream (this is what users see when they watch this stream)
* ``url``: URL of the original stream
* ``bitrate``: stream bitrate in bytes/s (Used only when input stream is TS)
* ``categories``: list of categories (for allowed values see ``ALLOWED_CATEGORIES`` in ``common.py``)
* ``quality``: SD|HD
* ``type``: ts|hls (currently acestream supports two types of input streams: MPEG-TS over HTTP and HLS)
* ``force_monotonic_sequence``: (0|1, optional, default=0) Used only when input stream is HLS


Support node config
-------------------

See ``examples/support_node_config.json``

* ``source_ip``: source node which to download data from
* ``source_port``: port of the source node


Common config params
--------------------

(for both source and support node)

* ``port``: node port
* ``engine_version``: stable|beta|alpha (it can be used to run several streams on the newest alpha/beta engine before going to productions)
* ``extended_logging``: 0|1 (used to enable extended logging on the node)

Recommended infrastructure
--------------------------

1 private source node + 2 support nodes.
All three nodes should be places on different servers.
Up to 50 total nodes on one server 32 Gb RAM + some modern quad code CPU (actual number depends on the total bitrate and available bandwidth).


Monitoring
==========

App can send monitoring data to the server configured by "monitor" endpoint.

Data is sent by running ``src/monitor_node.py`` script.
It collects data about each running node and sends it via HTTP POST request to the endpoint.
For each running node a separate request is made.

Info about collected data: http://wiki.acestream.org/wiki/index.php/AceStream_3.0/en#Monitoring

Nodes' metadata
===============

Metadata is sent to the server configured by "metadata_receiver" endpoint by running script ``src/update_metadata.py``

It contains important data which must be persisted between node restart.
This includes:

* ``.sauth`` and ``.restart`` files for TS streams
* monotonic sequence metadata for HLS streams

In production environment you should persist this data somewhere outside the server with running nodes to be able to recover in the case of server failure.
