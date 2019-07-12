import sys
import os
import json

def load_config(curdir, filename):
    config_path = os.path.join(curdir, "..", "config", filename)
    if not os.path.isfile(config_path):
        raise Exception("missing config %r" % (config_path,))

    with open(config_path, "rb") as f:
        config = json.load(f)

    return config

class Config:

    def __init__(self):
        curdir = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.config = load_config(curdir, "config.json")

    def get(self, name, default=None, required=True):
        if required and not name in self.config:
            raise Exception("missing config value for %r" % (name,))
        return self.config.get(name, default)

    def get_engine_path(self, version):
        engine_path_list = self.get('engine_path')
        if not version in engine_path_list:
            raise Exception("Unknown engine version: %r" % (version,))

        engine_path = engine_path_list[version]
        engine_path = os.path.expandvars(engine_path)

        if not os.path.isfile(engine_path):
            raise Exception("Engine not found: %s" % (engine_path,))

        return engine_path

    def get_controller(self, endpoint, required=True):
        controller = self.get("controller")

        if not isinstance(controller, dict):
            raise Exception("Malformed config: 'controller' must be a dict")

        if not endpoint in controller:
            if required:
                raise Exception("Missing controller for %r" % (endpoint,))
            else:
                return None

        return controller[endpoint]

    def get_trackers(self):
        return self.get("trackers")

    def get_provider_key(self):
        return self.get("provider_key", required=False)

    def get_root(self):
        if not 'root' in self.config:
            raise Exception("missing root")

        return self.config['root']

    def get_abs_path(self, path):
        if not os.path.isabs(path):
            path = os.path.join(self.get_root(), path)

        return path

    def get_dir(self, dirname, auto_create=True):
        if not 'dirs' in self.config:
            raise Exception("missing dirs")

        if not dirname in self.config['dirs']:
            raise Exception("missing %s in dirs" % (dirname,))

        path = self.config['dirs'][dirname]
        if not os.path.isabs(path):
            path = os.path.join(self.get_root(), path)

        if auto_create and not os.path.isdir(path):
            os.makedirs(path)

        return path
