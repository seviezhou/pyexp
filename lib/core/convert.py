import sys

from lib.core.settings import IS_WIN
from lib.core.settings import UNICODE_ENCODING

def singleTimeWarnMessage(message):  # Cross-linked function
    sys.stdout.write(message)
    sys.stdout.write("\n")
    sys.stdout.flush()

def stdoutencode(data):
    retVal = None

    try:
        data = data or ""

        # Reference: http://bugs.python.org/issue1602
        if IS_WIN:
            output = data.encode(sys.stdout.encoding, "replace")

            if '?' in output and '?' not in data:
                warnMsg = "cannot properly display Unicode characters "
                warnMsg += "inside Windows OS command prompt "
                warnMsg += "(http://bugs.python.org/issue1602). All "
                warnMsg += "unhandled occurances will result in "
                warnMsg += "replacement with '?' character. Please, find "
                warnMsg += "proper character representation inside "
                warnMsg += "corresponding output files. "
                singleTimeWarnMessage(warnMsg)

            retVal = output
        else:
            retVal = data.encode(sys.stdout.encoding)
    except:
        pass

    return retVal

# if subprocess.mswindows:
#     import ctypes
#     import ctypes.wintypes

    # Reference: https://gist.github.com/vsajip/758430
#     #            https://github.com/ipython/ipython/issues/4252
#     #            https://msdn.microsoft.com/en-us/library/windows/desktop/ms686047%28v=vs.85%29.aspx
#     ctypes.windll.kernel32.SetConsoleTextAttribute.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.WORD]
#     ctypes.windll.kernel32.SetConsoleTextAttribute.restype = ctypes.wintypes.BOOL

