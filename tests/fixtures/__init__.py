import os


root_path = os.path.dirname(__file__)


def path(name):
    return os.path.join(root_path, name)
