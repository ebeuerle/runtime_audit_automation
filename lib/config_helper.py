import os
import yaml


class ConfigHelper(object):
    def __init__(self):
        config = self.read_yml('configs')
        self.pc_user = config["prisma_cloud"]["username"]
        self.pc_pass = config["prisma_cloud"]["password"]
        self.pc_cust = config["prisma_cloud"]["customer_name"]
        self.pc_api_base = config["prisma_cloud"]["api_base"]
        self.pc_api_port = config["prisma_cloud"]["api_port"]

    @classmethod
    def read_yml(self, f):
        yml_path = os.path.join(os.path.dirname(__file__), "../config/%s.yml" % f)
        with open(yml_path,'r') as stream:
            return yaml.safe_load(stream)
