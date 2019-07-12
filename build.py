#!/usr/bin/python
import os
import sys
import shutil

COMMON_FILES = [
    'config/config-template.json',
    'src/config.py',
    'src/common.py',
    'src/logger.py',
    'src/errors.py',
    'src/utils.py',
    'src/stop_nodes.py',
    'src/cleanup.py',
    'src/monitor_nodes.py',
]

STREAMER_FILES = [
    'src/start_streamers.py',
    'src/update_metadata.py',
]

SUPPORT_FILES = [
    'src/start_support_nodes.py',
]

curdir = os.path.abspath(os.path.dirname(sys.argv[0]))

def copy_files(name, files, dest_path):
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
    os.makedirs(dest_path)

    for path in COMMON_FILES + files:
        print "[%s] copy %s" % (name, path)
        src = os.path.join(curdir, path)
        dest = os.path.join(dest_path, path)
        dest_dir = os.path.dirname(dest)
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir)

        if os.path.isdir(src):
            shutil.copytree(src, dest)
        else:
            shutil.copy(src, dest)

def main():
    dist_dir = os.path.join(curdir, "dist")
    dist_streamer_dir = os.path.join(dist_dir, "streamer")
    dist_support_dir = os.path.join(dist_dir, "support")

    copy_files("streamer", STREAMER_FILES, dist_streamer_dir)
    copy_files("support", SUPPORT_FILES, dist_support_dir)

    print "SUCCESS"

if __name__ == "__main__":
    main()