# Prisma Cloud Compute Runtime audit automation 

Version: *1.0*
Author: *Eddie Beuerlein*

### Summary
This script will:
1.  connect to compute console via a provided local username/password
2. Review all current runtime audit events (max 25K)
3. Extract "Unexpected Process" and "Unexpected Listening Port"(to be added in near future) entries
4. For Unexpected Processes, we will extract out a list of unique processes
5. For Unexpected Ports, we will extract out a list of unique ports (to be added in near future)
6. For each runtime rule that is impacted, we will add the list of binaries/ports to the allow list

### Requirements and Dependencies

1. Python 3.7 or newer

2. OpenSSL 1.0.2 or newer

3. Pip

4. Requests (Python library)

```sudo pip install requests```

5. YAML (Python library)

```sudo pip install pyyaml```

6. JSON

```sudo pip install json```

7. Loguru

```sudo pip install loguru```


### Configuration

1. Navigate to ```config/configs.yml```

2. Fill out your Prisma Cloud access key/secret(username/password), console URL (don't include https - just the FQDN), and port (API listening port).   

### Run

```
python main.py
```
