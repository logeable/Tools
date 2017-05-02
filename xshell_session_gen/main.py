# -*- coding: utf-8 -*-
import getopt
import os
import sys

sessions_dir = os.path.join(os.path.expanduser("~"), r"Documents\NetSarang\Xshell\Sessions")


def get_template():
    with open("session_template.txt") as f:
            template = f.read()
            return template


def save_session(session_name, template, force):
    session_filepath = os.path.join(sessions_dir, session_name + ".xsh")
    if not os.path.exists(session_filepath) or force:
        with open(session_filepath, "w") as f:
            f.write(template)
        print("save successful: " + session_name)
    else:
        print(session_name + " exists: " + session_name)


def clear_empty(l):
    for x in l:
        if isinstance(x, str) and not x.strip():
            l.remove(x)


def parse_host_re(host_base, dynamic):    
    hosts = []
    if "*" not in host_base:
        hosts.append(host_base)
        return hosts

    host_base = host_base.replace("*", "{}", 1)
    for x in dynamic:
        hosts.extend(parse_host_re(host_base.format(x), dynamic))
    return hosts        


def parse_host(host_str):
    hosts = []
    host_base_dynamic = host_str.split(":", 1)
    clear_empty(host_base_dynamic)

    if len(host_base_dynamic) == 2:
        host_base = host_base_dynamic[0]
        dynamic = host_base_dynamic[1].split(",")
        clear_empty(dynamic)
        hosts = parse_host_re(host_base, dynamic)
    else:
        if check_host(host_base_dynamic[0]):
            hosts.append(host_base_dynamic[0])
    return hosts


def check_host(host):
    tmp = host.split(".")
    if len(tmp) != 4:
        return False
    for x in tmp:
        try:
            num = int(x)
            if num < 0 or num > 255:
                return False
        except Exception as e:
            return False
    return True


def get_user_key(is_old=False):
    if is_old:
        return "RSA-200610-openssh"
    else:
        return "RSA-201608-openssh"


def get_port(args):
    port = args.get("port")
    if port is None:
        if args.get("old", True):
            port = 22
        else:
            port = 8022
    return port


def main():
    options = getopt.getopt(sys.argv[1:], "h:p:", ["old"])[0]
    args = {}
    for opt, val in options:
        if opt == "-h":
            args["host"] = parse_host(val)
        elif opt == "-p":
            args["port"] = int(val)
        elif opt == "--old":
            args["old"] = val
        elif opt == "-f":
            args["force"] = True
    print(args)
    user_key = get_user_key(args.get("old", False))    
    port = get_port(args)
    force = args.get("force", True)

    for host in args["host"]:
        print("port: %s" % port)
        print("user key: %s\n" % user_key)
        name = host.split(".", 2)[-1]
        template = get_template()        
        template = template.format(Host=host, Port=port, UserKey=user_key) 
        save_session(name, template, force)
        print("===========\n")

if __name__ == "__main__":
    """usage: -h10.10.16.21*:1,2,3,4,5 -p8022 --old
    """
    main()
