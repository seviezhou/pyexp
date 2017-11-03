#!/usr/bin/env python

"""
Copyright (c) 2016 seviezhou (http://pwdme.cc/)
"""
import sys
import os
import time

from lib.core.data import logger
from lib.core.common import dataToStdout

try:
    from lib.core.data import conf
    from lib.core.data import cmdLineOptions
    from lib.core.data import paths
    from lib.core.option import initOptions
    from lib.core.option import init
    from lib.core.common import banner
    from lib.core.common import setPaths
    from lib.parse.cmdline import cmdLineParser
    from lib.controller.controller import run
    from lib.core.expection import PyExpSyntaxException
    from lib.core.expection import PyExpSystemException
except KeyboardInterrupt:
    errMsg = "Be aborted by user"
    logger.error(errMsg)

def rootPath():
    _ = __file__
    return os.path.dirname(os.path.realpath(_))

def setEnvironment():
    paths.PYEXP_ROOT_PATH = rootPath()

def main():

    try:

        setEnvironment()
        setPaths()

        banner()
        cmdLineOptions.update(cmdLineParser().__dict__)
        initOptions(cmdLineOptions)

        init()

        run()

    except PyExpSyntaxException as ex:
        logger.error(ex)
        msg = "\n[*] Pyexp is shutting down at %s.\n\n" % time.strftime("%H:%M:%S")
        dataToStdout(msg)
        raise SystemExit
    except PyExpSystemException as ex:
        logger.critical(ex)
        msg = "\n[*] Pyexp is shutting down at %s.\n\n" % time.strftime("%H:%M:%S")
        dataToStdout(msg)
        raise SystemExit

if __name__ == "__main__":
    main()
