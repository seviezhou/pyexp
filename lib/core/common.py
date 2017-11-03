import sys
import os

from lib.core.settings import BANNER
from lib.core.data import paths
from lib.core.expection import PyExpSystemException
from thirdparty.termcolor.termcolor import colored
from lib.core.log import LOGGER_HANDLER

def setColor(message, bold=False):

    retVal = message

    if message and getattr(LOGGER_HANDLER, "is_tty", False):  # colorizing handler
        if bold:
            retVal = colored(message, color=None, on_color=None, attrs=("bold",))

    return retVal

def dataToStdout(data, bold=False):
    """
    Writes text to the stdout (console) stream
    """

    message = ""

    # if forceOutput or not getCurrentThreadData().disableStdOut:
    #     if kb.get("multiThreadMode"):
    #         logging._acquireLock()

    message = data

    sys.stdout.writelines(setColor(message, bold))

    try:
        sys.stdout.flush()
    except IOError:
        pass

    # if kb.get("multiThreadMode"):
    #     logging._releaseLock()

def checkFile(filename):
    """
    check if file exist and is readable
    """
    checked = True

    if filename is None or not os.path.isfile(filename):
        checked = False

    if checked:
        try:
            with open(filename, "rb"):
                pass
        except:
            checked = False

    if not checked:
        raise PyExpSystemException("unable to read file '%s'" % filename)

    return checked

def banner():
    """
    Set absolute paths for project.
    """
    if not any(_ in sys.argv for _ in ("--version")):
        _ = BANNER

        print(BANNER)

def setPaths():
    """
    Set absolute paths for project.
    """
    paths.PYEXP_TXT_PATH = os.path.join(paths.PYEXP_ROOT_PATH, "txt")
    paths.PYEXP_DOC_PATH = os.path.join(paths.PYEXP_ROOT_PATH, "doc")
    paths.PYEXP_CIPHER_PATH = os.path.join(paths.PYEXP_ROOT_PATH, "cipher")

    #PyExp files
    paths.COMMON_ENGLISH_WORDS = os.path.join(paths.PYEXP_TXT_PATH, "CommonEnglishWords.txt")
    paths.USER_AGENT = os.path.join(paths.PYEXP_TXT_PATH, "user-agent.txt")

    for path in paths.values():
        if any(path.endswith(_) for _ in (".txt", ".xml")):
            checkFile(path)




