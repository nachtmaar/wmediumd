#!/usr/bin/env python


from fabric.api import *
from fabric.contrib.project import rsync_project
import os

env.disable_known_hosts = True

def deploy_code(start_cmd=None, deploy_cmd=None, start_debug=False, quiet=False, callgrind=False,bg=False):
    bg = (bg=='True')

    PATH_WMEDIUMD="/root/wmediumd/"
    PATH_WMEDIUMD_SOURCE=os.path.join(PATH_WMEDIUMD, "wmediumd/")

    os.chdir("../")

    if deploy_cmd is not None:
        with cd(PATH_WMEDIUMD_SOURCE):
            run(deploy_cmd)
    else:
        rsync_project(
            local_dir=os.path.join(os.getcwd()),
            remote_dir="/root/",
            exclude=["*.pyc", "*.o"],
            delete=True,
            ssh_opts="-o StrictHostKeyChecking=no"
        )
    with cd(PATH_WMEDIUMD_SOURCE):
        run("./compile.sh")
    with cd(PATH_WMEDIUMD):
        run("bash create_single_node_config.sh")
        with settings(warn_only=True):
            run("rm wmediumd.log")
            run("killall -9 wmediumd")
        run("echo $PWD")

        if start_cmd is None:
            start_cmd = "wmediumd/wmediumd -c 2_node.cfg"

        if quiet:
            start_cmd += " >/dev/null 2>/dev/null "

        if callgrind:
            start_cmd = " valgrind --dsymutil=yes --tool=callgrind {}".format(start_cmd)

        if start_debug:
            start_cmd = "{} {}".format("gdb --args", start_cmd)

        if bg:
            start_cmd = "nohup {} &".format(start_cmd)

        run(start_cmd)