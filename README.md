# Prisma Cloud Compute Runtime audit automation 

Version: *1.0*
Author: *Eddie Beuerlein*

### Summary
This script will:
1.  connect to compute console via a provided local username/password
2. Review all current runtime audit events (max 25K)
3. Extract "Unexpected Process" and "Unexpected Listening Port" entries
4. For Unexpected Processes, we will extract out a list of unique processes
5. For Unexpected Ports, we will extract out a list of unique ports
6. For each runtime rule that is impacted, we will add the list of binaries/ports to the allow list

### Requirements and Dependencies

1. Python 3.7 or newer

2. OpenSSL 1.0.2 or newer

(if using on Mac OS, additional items may be nessessary.)

3. Pip

```sudo easy_install pip```

4. Requests (Python library)

```sudo pip install requests```

5. YAML (Python library)

```sudo pip install pyyaml```


### Configuration

1. Navigate to ```config/configs.yml```

2. Fill out your Prisma Cloud access key/secret, stack info, and RQL to be run. (Ignore filename - this will be used in future.)  
   *To determine stack, look at your browser when access console (appX.prismacloud.io, where X is the stack number.  
   Change this to apiX.prismacloud.io and populate it in the configs.yml.  
    Or go here for more information:* https://api.docs.prismacloud.io/

### Run

```
python main.py
```
