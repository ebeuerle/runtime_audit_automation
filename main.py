import lib
import sys
import json
import copy
from loguru import logger
from collections import defaultdict

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
        rules = copy.deepcopy(rules)
        active_rt = {}
        temp_rt = {}
        count = 0
        for rule in rules['rules']:
            if 'disabled' not in rule:
                temp_rt = { rule['name'] :{ "proc_whitelist": rule['processes']['whitelist'], "port_whitelist": rule['network']['whitelistListeningPorts']}}
                active_rt.update(temp_rt)
                count += 1
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

    def extract_processes(self,proc_audits):
        parsed_proc = defaultdict(set) 
        for proc in proc_audits:
            if proc['attackType'] == "unexpectedProcess":
                parsed_proc[proc['ruleName']].add(proc['processPath'])
        logger.info("Extracting out unique list of processes per rule name...")

        return parsed_proc

    def merge_runtime_data(self, active_runtime_rules, parsed_proc):
        for rt_name,rt_procs_ports in active_runtime_rules.items():
            for audit_name, audit_procs in parsed_proc.items():
                if rt_name == audit_name:
                    #adds the processees from audit events to runtime rule dict
                    rt_procs_ports['proc_whitelist'].extend(audit_procs)
        for rt_name,rt_procs_ports in active_runtime_rules.items():
            #dedup processes via set and then put it back as a list
            rt_procs_ports['proc_whitelist'] = set(rt_procs_ports['proc_whitelist']) 
            rt_procs_ports['proc_whitelist'] = list(rt_procs_ports['proc_whitelist'])

        logger.info("Merging audit runtime processes with runtime rules")

        return active_runtime_rules

    def combine_put_new_rules(self, runtime_rules, new_runtime_data):
        for rule in runtime_rules['rules']:
            for name, procs in new_runtime_data.items():
                if rule['name'] == name:
                    rule['processes']['whitelist'] = procs['proc_whitelist']
        logger.info("Runtime rules are ready to be pushed to console")

        self.url = "https://" + self.config.pc_api_base + ":" + self.config.pc_api_port + "/api/v1/policies/runtime/container"
        self.pc_sess.authenticate_client()
        resp = self.pc_sess.client.put(self.url, json.dumps(runtime_rules))
        if resp.ok:
            logger.info("Successfully pushed revised runtime rules to console")
        else:
            raise Exception("Failed to push revised runtime rules, error: {}", resp.status_code)


    def run(self):
        runtime_rules = self.get_runtime_rules()
        active_runtime_rules = self.extract_runtime_details(runtime_rules)
        proc_audits = self.pull_runtime_audits()
        parsed_proc = self.extract_processes(proc_audits)
        new_runtime_data = self.merge_runtime_data(active_runtime_rules, parsed_proc)
        self.combine_put_new_rules(runtime_rules,new_runtime_data)

def main():
    RT_audit_sync = RT_audit_auto()
    RT_audit_sync.run()

if __name__ == "__main__":
    main()
