import sys
import logging
import logging.handlers

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s|%(threadName)s|%(name)s|%(message)s')

def add_log_file(path, mode='a', max_size=10*1024*1024, backup_count=2, encoding=None):
    root_logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s|%(threadName)s|%(name)s|%(message)s')
    handler = logging.handlers.RotatingFileHandler(path, mode, max_size, backup_count, encoding=encoding)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

def get_logger(name="root"):
    return logging.getLogger(name)