import os
import sys
import shutil

from config import Config

def main():
    config = Config()

    to_delete = [config.get_dir(dirname, auto_create=False) for dirname in ["log", "cache", "pid"]]
    for path in to_delete:
        if os.path.isdir(path):
            print "remove dir %s" % (path,)
            shutil.rmtree(path)

if __name__ == "__main__":
    main()