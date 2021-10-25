import lib
import json
from loguru import logger

class RT_audit_auto():
    def __init__(self):
        self.config = lib.ConfigHelper()
        self.pc_sess = lib.PCSession(self.config.pc_user, self.config.pc_pass, self.config.pc_cust,
                                     self.config.pc_api_base, self.config.pc_api_port)

    def get_runtime_rules(self):
        self.url = "https://" + self.config.pc_api_base + ":" + self.config.pc_api_port + "/api/v1/policies/runtime/container"
        self.pc_sess.authenticate_client()
        resp = self.pc_sess.client.get(self.url)
        runtime_rules = resp.json()

        #for rule in runtime_rules_json['rules']:
        #    print(rule['name'])
        return runtime_rules
    
    def extract_runtime_details(self,rules):
        active_rt = {}
        for rule in rules['rules']:
            if 'disabled' not in rule:
                active_rt = { rule['name'] :{ "proc_whitelist": rule['processes']['whitelist'], "port_whitelist": rule['network']['whitelistListeningPorts']}}
        print(active_rt)

    def run(self):
        runtime_rules = self.get_runtime_rules()
        self.extract_runtime_details(runtime_rules)

def main():
    RT_audit_sync = RT_audit_auto()
    RT_audit_sync.run()

if __name__ == "__main__":
    main()
