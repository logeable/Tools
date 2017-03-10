#!/usr/bin/env python
# -*- coding: utf-8 -*-
import subprocess
import logging
import sys
import argparse
import shutil
import os
import py_compile
import re
import json

logger = logging.getLogger("patch3")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler())

CONFIG = {
    "status": ["M", "A", "D"],
    "patch_dir": "patch_dir",
    "screw_php": "/home/logeable/backend/scripts/php-screw",
    "compile_patterns": [r"^python/", r"^api/"],
    "screw_patterns": [r"^web"],
    "deploy_dirs": [
        {
            "path": "/usr/share/locale/en_US/LC_MESSAGES/",
            "patterns": [r"^locale/en_US.mo"]
        },
        {
            "path": "/usr/share/locale/zh_CN/LC_MESSAGES/",
            "patterns": [r"^locale/zh_CN.mo"]
        },
        {
            "path": "/usr/share/shterm/",
            "patterns": [r"^doc/PGSQL"]
        },
        {
            "path": "/usr/lib/python2.6/site-packages/shterm/",
            "patterns": [r"^python/"]
        },
        {
            "path": "/usr/libexec/shterm/",
            "patterns": [r"^libexec/"]
        },
        {
            "path": "/var/www/shterm/",
            "patterns": [r"^web/"]
        },
        {
            "path": "/usr/lib/shterm/api/",
            "patterns": [r"^api/"]
        }
    ],
    "services_policy": [
        {
            "service": "shterm-rdpextsrv",
            "patterns": [r"^python/rdpextsrv"],
            "policy": "restart"
        },
        {
            "service": "httpd",
            "patterns": [r".*\.mo$"],
            "policy": "restart"
        },
        {
            "service": "shterm-healthd",
            "patterns": [r"^python/auth.py", r"^libexec/permsrv"],
            "policy": "restart"
        },
        {
            "service": "shterm-permsrv",
            "patterns": [r"^libexec/permsrv2"],
            "policy": "restart"
        },
        {
            "service": "uwsgi",
            "patterns": [r"^api/"],
            "policy": "restart"
        }
    ],
    "tmpl": {
        "install_chk_tmpl": ("\t[ -f {dest_bak} ] || " +
                             "mkdir -p {dest_dir}; cp" +
                             " {dest} {dest_bak}\n"),
        "install_cp_tmpl": "\tcp {patch_src_rel} {dest}\n",
        "install_rm_tmpl": "\trm -rf {dest}\n",
        "uninstall_chk_tmpl": "\t[ -f {dest_bak} ] && mv {dest_bak} {dest}\n",
        "uninstall_rm_tmpl": "\trm -rf {dest}\n",
        "service_tmpl": "\tservice {service} {policy}\n"
    }
}


def get_name_status_ref(ref):
    p = subprocess.Popen(
            ["git", "show", ref, "--name-status", "--format=format:"],
            stdout=subprocess.PIPE)
    output, err = p.communicate()
    assert err is None
    return output


def get_name_status_stdin():
    return sys.stdin.read()


def get_name_status(from_stdin, ref):
    if from_stdin:
        output = get_name_status_stdin()
    else:
        output = get_name_status_ref(ref)
    output = output.decode("utf-8")
    logger.debug(output)

    return [line.strip().split(None, 1)
            for line in output.strip().splitlines()
            if line.strip()]


def preprocess_name_status(name_status_list):
    result = []
    has_po = False
    for status, src in name_status_list:
        ext = os.path.splitext(src)[1]
        if ext == ".po":
            has_po = True
            continue
        result.append((status, src))
    logger.debug("preprocess name status: locale: [{has_po}]"
                 .format(has_po=has_po))
    if has_po:
        generate_locale()
        result.insert(0, ("M", "locale/en_US.mo"))
        result.insert(0, ("M", "locale/zh_CN.mo"))
    return result


def generate_locale():
    logger.debug("generate locale files")
    os.chdir("locale")
    p = subprocess.Popen(["make"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    output, err = p.communicate()
    os.chdir("..")


def validate_status(name_status):
    status, src = name_status
    assert status in CONFIG["status"],\
        "status: [{status}] not supported".format(status=status)


def prepare_patch_dir(name_status):
    status, src = name_status
    if status == "M":
        patch_src = copy_files(src)
    elif status == "A":
        patch_src = copy_files(src)
    elif status == "D":
        patch_src = None
    return status, patch_src, src


def copy_py(src, dest, is_compile):
    logger.info("copy py: {src} -> {dest} [compile: {compile}]"
                 .format(src=src, dest=dest, compile=is_compile))
    dirname = os.path.dirname(dest)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if is_compile:
        py_compile.compile(src, dest)
    else:
        copy_direct(src, dest)


def copy_php(src, dest, is_screw):
    logger.info("copy php: {src} -> {dest} [screw: {screw}]"
                 .format(src=src, dest=dest, screw=is_screw))
    dirname = os.path.dirname(dest)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if is_screw:
        p = subprocess.Popen([CONFIG["screw_php"], "-o", dest, src],
                             stdout=subprocess.PIPE)
        output, err = p.communicate()
        assert err is None
    else:
        copy_direct(src, dest)


def copy_direct(src, dest):
    logger.info("copy direct: {src} -> {dest}"
                 .format(src=src, dest=dest))
    dirname = os.path.dirname(dest)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    shutil.copy(src, dest)


def copy_files(src):
    if os.path.isdir(src):
        return
    ext = os.path.splitext(src)[1]
    patch_src = os.path.join(CONFIG["patch_dir"], src)
    if ext == ".py":
        if need_compile(src):
            patch_src = patch_src + "c"
            copy_py(src, patch_src, True)
        else:
            copy_py(src, patch_src, False)
    elif ext == ".php":
        copy_php(src, patch_src, need_screw(src))
    elif ext == ".mo":
        if "en_US.mo" in src:
            mo_src = "en_US/shterm.mo"
        elif "zh_CN.mo" in src:
            mo_src = "zh_CN/shterm.mo"
        else:
            logger.warn("mo file not handled: [{mo}]".format(mo=src))
        patch_src = os.path.join(CONFIG["patch_dir"], mo_src)
        copy_direct(src, patch_src)
    else:
        copy_direct(src, patch_src)
    return patch_src


def is_match(src, patterns):
    result = False
    for pattern in patterns:
        if re.match(pattern, src):
            result = True
            break
    return result


def need_compile(src):
    return is_match(src, CONFIG["compile_patterns"])


def need_screw(src):
    return is_match(src, CONFIG["screw_patterns"])


def matched_dir(src):
    for dir_patterns in CONFIG["deploy_dirs"]:
        if is_match(src, dir_patterns["patterns"]):
            return dir_patterns["path"]
    return None


def generate_patch_vars(status_patch_src):
    logger.debug("generate patch_vars: \n{data}"
                 .format(data=json.dumps(status_patch_src, indent=4)))
    result = []
    for status, patch_src, src in status_patch_src:
        # patch_src_rel, dest_bak
        if status in ("M", "A"):
            patch_src_rel = patch_src[len(CONFIG["patch_dir"] + "/"):]
            dest_bak = "{0}.bak".format(patch_src_rel)
        elif status == "D":
            patch_src_rel = None
            dest_bak = "{0}.bak".format(src)

        # dest
        dir_path = matched_dir(src)
        assert dir_path, "not handled: {0}".format(src)
        dest = os.path.join(dir_path, patch_src_rel.split(os.sep, 1)[-1])

        # dest_dir
        dest_dir = os.path.dirname(dest)

        result.append((status, patch_src_rel, dest, dest_dir, dest_bak))

    return result


def generate_makefile(patch_vars):
    """
    patch_vars:  (status, patch_src_rel, dest, dest_dir, dest_bak)
    """
    makefile_path = os.path.join(CONFIG["patch_dir"], "Makefile")
    logger.debug("generate makefile: {makefile_path}\n{data}"
                 .format(makefile_path=makefile_path,
                         data=json.dumps(patch_vars, indent=4)))

    tmpl = CONFIG["tmpl"]

    install_chk_lines = []
    install_do_lines = []
    uninstall_chk_lines = []
    uninstall_do_lines = []
    install_services_lines = set()
    uninstall_services_lines = set()
    for status, patch_src, dest, dest_dir, dest_bak in patch_vars:
        context = {
            "patch_src_rel": patch_src,
            "dest": dest,
            "dest_dir": dest_dir,
            "dest_bak": dest_bak
        }

        if status == "A":
            install_do_lines.append(tmpl["install_cp_tmpl"]
                                    .format(**context))
            uninstall_do_lines.append(tmpl["uninstall_rm_tmpl"]
                                      .format(**context))
        elif status == "M":
            install_chk_lines.append(tmpl["install_chk_tmpl"]
                                     .format(**context))
            install_do_lines.append(tmpl["install_cp_tmpl"]
                                    .format(**context))
            uninstall_chk_lines.append(tmpl["uninstall_chk_tmpl"]
                                       .format(**context))
        elif status == "D":
            install_chk_lines.append(tmpl["install_chk_tmpl"]
                                     .format(**context))
            install_chk_lines.append(tmpl["install_rm_tmpl"]
                                     .format(**context))
            uninstall_do_lines.append(tmpl["uninstall_chk_tmpl"]
                                      .format(**context))

        for sp in CONFIG["services_policy"]:
            service_context = {
                "service": sp["service"],
                "policy": sp["policy"]
            }

            if is_match(patch_src, sp["patterns"]):
                install_services_lines.add(
                        tmpl["service_tmpl"].format(**service_context))
                uninstall_services_lines.add(
                        tmpl["service_tmpl"].format(**service_context))

    with open(makefile_path, "w") as f:
        f.write("install:\n")
        f.writelines(install_chk_lines)
        f.writelines(install_do_lines)
        f.writelines(install_services_lines)
        f.write('\t@echo "install done"\n')
        f.write("uninstall:\n")
        f.writelines(uninstall_chk_lines)
        f.writelines(uninstall_do_lines)
        f.writelines(uninstall_services_lines)
        f.write('\t@echo "uninstall done"\n')


def parse_args():
    parser = argparse.ArgumentParser(description="patch for backend")
    parser.add_argument("--ref", action="store", dest="ref",
                        help="ref in git", default="HEAD")
    parser.add_argument("--stdin", action="store_true",
                        help="name status from stdin")
    parser.add_argument("--dir", action="store", dest="dir",
                        help="patch dir", default="patch_dir")
    return parser.parse_args()


def create_patch_dir():
    directory = CONFIG["patch_dir"]
    if not os.path.exists(directory):
        os.makedirs(directory)
        return
    logger.debug("clear old patch dir: [{directory}]"
                 .format(directory=directory))
    shutil.rmtree(directory)
    os.makedirs(directory)


def patch():
    CONFIG["arguments"] = parse_args()
    from_stdin = CONFIG["arguments"].stdin
    ref = CONFIG["arguments"].ref
    CONFIG["patch_dir"] = CONFIG["arguments"].dir

    create_patch_dir()

    name_status_list = preprocess_name_status(
            get_name_status(from_stdin, ref))
    logger.debug(name_status_list)

    status_patch_src = []
    for ns in name_status_list:
        validate_status(ns)
        status_patch_src.append(prepare_patch_dir(ns))

    patch_vars = generate_patch_vars(status_patch_src)
    generate_makefile(patch_vars)


if __name__ == "__main__":
    patch()

