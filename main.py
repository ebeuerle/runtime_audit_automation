import lib
import sys
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
        if resp.ok:
            runtime_rules = resp.json()
            logger.info("Pulling all runtime rules...")
            return runtime_rules
        else:
            raise Exception("Failed to get runtime rules, error: {}", resp.status_code)

    def extract_runtime_details(self,rules):
        active_rt = {}
        count = 0
        for rule in rules['rules']:
            if 'disabled' not in rule:
                active_rt = { rule['name'] :{ "proc_whitelist": rule['processes']['whitelist'], "port_whitelist": rule['network']['whitelistListeningPorts']}}
                count += 1
        #print(active_rt)
        logger.info("Active runtime rules: {}", count)
        if count == 0:
            logger.info("No active runtime rules - please add one to ensure this script will work.")
            sys.exit("Exiting script - nothing to do")
        else:
            return active_rt

    def pull_runtime_audits(self):
        #set variables for looping and pagination handling
        offsetval = 0
        finished = False
        proc_audits=[]
        #pull processes runtime audits first
        while not finished:
            self.url = "https://" + self.config.pc_api_base + ":" + self.config.pc_api_port + "/api/v1/audits/runtime/container?type=processes&limit=50&offset=" + str(offsetval)
            self.pc_sess.authenticate_client()
            resp = self.pc_sess.client.get(self.url)
            if resp.ok:
                resp_js = resp.json() 
                if resp_js:
                    total_val = resp.headers.get('Total-Count')
                    logger.info("Pulling all runtime audits - this could take a bit. Offset: {}", offsetval)
                    proc_audits.extend(resp_js)
                    offsetval += 50
                else:
                    finished = True

            else:
                raise Exception("Failed to get runtime audits, error: {}", resp.status_code)
        
        logger.info("Total runtime audits: {}", len(proc_audits))
        
        return proc_audits

    def run(self):
        runtime_rules = self.get_runtime_rules()
        active_runtime_rules = self.extract_runtime_details(runtime_rules)
        runtime_audits = self.pull_runtime_audits()

def main():
    RT_audit_sync = RT_audit_auto()
    RT_audit_sync.run()

if __name__ == "__main__":
    main()
