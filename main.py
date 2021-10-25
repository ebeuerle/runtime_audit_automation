import lib
import json
from loguru import logger

class RT_audit_auto():
    def __init__(self):
        self.config = lib.ConfigHelper()
        self.pc_sess = lib.PCSession(self.config.pc_user, self.config.pc_pass, self.config.pc_cust,
                                     self.config.pc_api_base, self.config.pc_api_port)

    def get_runtime_rules(self):
        self.url = "https://" + self.config.pc_api_base + self.config.pc_api_port + "policies/runtime/container"
        self.pc_sess.authenticate_client()
        resp = self.pc_sess.client.get(self.url)
        runtime_rules_json = resp.json()

        print(runtime_rules_json)

    def run(self):
        self.get_runtime_rules()

def main():
    RT_audit_sync = RT_audit_auto()
    RT_audit_sync.run()

if __name__ == "__main__":
    main()
