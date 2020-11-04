#!/usr/bin/env python3

import argparse
import json
import re
import subprocess



def dumpSignInfo(enclave):
    return subprocess.run(["oesign", "dump", "-e", enclave], check=True, stdout=subprocess.PIPE).stdout.decode()

def parseSignInfo(info):
    config = {}

    m = re.findall(r"security_version=(\d+)", info)
    if len(m) <= 0:
        raise Exception("Couldn't find security_version in signature info")
    config["SecurityVersion"] = int(m[0])

    m = re.findall(r"product_id=(\d+)", info)
    if len(m) <= 0:
        raise Exception("Couldn't find product_id in signature info")
    config["ProductID"] = [int(m[0])]

    m = re.findall(r"mrenclave=([abcdef\d]+)", info)
    if len(m) <= 0:
        raise Exception("Couldn't find mrenclave in signature info")
    config["UniqueID"] = m[0]

    m = re.findall(r"mrsigner=([abcdef\d]+)", info)
    if len(m) <= 0:
        raise Exception("Couldn't find mrsigner in signature info")
    config["SignerID"] = m[0]

    return config

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--enclave', help="enclave image", required=True)
    parser.add_argument('-o', '--output',  help="file to store configuration")
    args = parser.parse_args()
    
    signInfo = dumpSignInfo(args.enclave)
    config = parseSignInfo(signInfo)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(config, f, indent=4)
    else:
        print(json.dumps(config, indent=4))
