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

logger = logging.getLogger("patch3")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

CONFIG = {
    "status": ["M", "A", "D"],
    "patch_dir": "patch_dir",
    "screw_php": "/home/logeable/backend/scripts/php-screw",
    "compile_patterns": [r"^python"],
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
            "path": "/usr/lib/python/2.6/site-packages/shterm/",
            "patterns": [r"^python/"]
        },
        {
            "path": "/usr/libexec/shterm/",
            "patterns": [r"^libexec/"]
        },
        {
            "path": "/var/www/shterm/",
            "patterns": [r"^web/"]
        }
    ],
    "tmpl": {
        "install_chk_tmpl": "\t[ -f {src_bak} ] || mkdir -p {dest_dir}; cp {dest} {src_bak}\n",
        "install_cp_tmpl": "\tcp {patch_src} {dest}\n",
        "uninstall_chk_tmpl": "\t[ -f {src_bak} ] && mv {src_bak} {dest}\n",
        "uninstall_rm_tmpl": "\trm -rf {dest}\n"
    }
}


def get_name_status_ref(ref):
    p = subprocess.Popen(["git", "show", ref, "--name-status", "--format=format:"],
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
    patch_src = None
    if status == "M":
        patch_src = copy_files(src)
    elif status == "A":
        patch_src = copy_files(src)
    elif status == "D":
        patch_src = src
    return status, patch_src, src


def copy_py(src, dest, is_compile):
    logger.debug("copy py: {src} -> {dest} [compile: {compile}]"
            .format(src=src, dest=dest, compile=is_compile))
    dirname = os.path.dirname(dest)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if is_compile:
        py_compile.compile(src, dest)
    else:
        copy_direct(src, dest)


def copy_php(src, dest, is_screw):
    logger.debug("copy php: {src} -> {dest} [screw: {screw}]"
            .format(src=src, dest=dest, screw=is_screw))
    dirname = os.path.dirname(dest)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if is_screw:
        p = subprocess.Popen([CONFIG["screw_php"], "-o", dest, src], stdout=subprocess.PIPE)
        output, err = p.communicate()
        assert err is None
    else:
        copy_direct(src, dest)


def copy_direct(src, dest):
    logger.debug("copy direct: {src} -> {dest}"
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

def generate_status_src_dest(status_patch_src):
    result = []
    for status, patch_src, src in status_patch_src:
        dest = None
        if status in ( "M", "A"):
            dir_path = matched_dir(src)
            assert dir_path, "not handled: {0}".format(status_patch_src)
            _, _, sub_path = patch_src.split(os.path.sep, 2)
            dest = os.path.join(dir_path, sub_path)
        elif status == "D":
            patch_src = src
        result.append((status, patch_src, dest))

    return result


def generate_makefile(status_src_dest):
    makefile_path = os.path.join(CONFIG["patch_dir"], "Makefile")
    logger.debug("generate makefile: {makefile_path}\n{data}"
            .format(makefile_path=makefile_path,data=status_src_dest))

    tmpl = CONFIG["tmpl"]

    install_chk_lines = []
    install_do_lines = []
    uninstall_chk_lines = []
    uninstall_do_lines = []
    has_locale = False
    for status, patch_src, dest in status_src_dest:
        if os.path.splitext(patch_src)[1] == ".mo":
            has_locale = True
        context = {
            "patch_src": patch_src,
            "dest": dest,
            "dest_dir": os.path.dirname(dest),
            "src_bak": "{0}.bak".format(patch_src)
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
            pass

    with open(makefile_path, "w") as f:
        f.write("install:\n")
        f.writelines(install_chk_lines)
        f.writelines(install_do_lines)
        if has_locale:
            f.write("\tservice httpd restart\n")
        f.write('\t@echo "install done"\n')
        f.write("uninstall:\n")
        f.writelines(uninstall_chk_lines)
        f.writelines(uninstall_do_lines)
        if has_locale:
            f.write("\tservice httpd restart\n")
        f.write('\t@echo "uninstall done"\n')


def parse_args():
    parser = argparse.ArgumentParser(description="patch for backend")
    parser.add_argument("--ref", action="store", dest="ref",
            help="ref in git", default="HEAD")
    parser.add_argument("--stdin", action="store_true",
            help="name status from stdin")
    return parser.parse_args()


def clear_patch():
    directory = CONFIG["patch_dir"]
    if not os.path.isdir(directory):
        return
    logger.debug("clear old patch dir: [{directory}]"
            .format(directory=directory))
    shutil.rmtree(directory)


def patch():
    CONFIG["arguments"] = parse_args()
    from_stdin = CONFIG["arguments"].stdin
    ref = CONFIG["arguments"].ref

    clear_patch()

    name_status_list = preprocess_name_status(
            get_name_status(from_stdin, ref))
    logger.debug(name_status_list)

    status_patch_src = []
    for ns in name_status_list:
        validate_status(ns)
        status_patch_src.append(prepare_patch_dir(ns))

    status_src_dest = generate_status_src_dest(status_patch_src)
    generate_makefile(status_src_dest)


if __name__ == "__main__":
    patch()

