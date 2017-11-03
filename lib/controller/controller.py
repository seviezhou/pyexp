import threading

from thirdparty.pyperclip import pyperclip
from lib.core.data import conf
from lib.core.data import ru
from lib.core.data import logger
from lib.core.common import dataToStdout
from lib.techniques.detectEnglish import isEnglish
from lib.core.expection import PyExpSystemException
from lib.core.dnstype import ThreadedUDPServer
from lib.core.dnstype import ThreadedTCPServer
from lib.core.dnstype import ThreadedTCPHandler
from lib.core.dnstype import ThreadedUDPHandler
from lib.ssh.ssh import sshKeyGen
from lib.ssh.ssh import sshLocalForward
from lib.ssh.ssh import sshRemoteForward
from lib.ssh.ssh import sshDirect

import time
import os
import sys
import termios

def pressAnyExit():
    """
    User can press q to quit
    """
    fd = sys.stdin.fileno()
    old_ttyinfo = termios.tcgetattr(fd)
    new_ttyinfo = old_ttyinfo[:]
    new_ttyinfo[3] &= ~termios.ICANON
    new_ttyinfo[3] &= ~termios.ECHO
    sys.stdout.flush()
    termios.tcsetattr(fd, termios.TCSANOW, new_ttyinfo)
    s = os.read(fd, 7)
    if s.decode() == "q":
        msg = "User quit."
        logger.critical(msg)
        msg = "[*] Pyexp is shutting down at %s.\n\n" % time.strftime("%H:%M:%S")
        dataToStdout("\n")
        dataToStdout(msg)
        raise SystemExit
    termios.tcsetattr(fd, termios.TCSANOW, old_ttyinfo)

def runCipher():

    text = conf.text

    if not conf.file:

        msg = "[+] The input text is \033[40m%s\033[0m and length is %d\n" % (text, len(text))
        dataToStdout(msg)


    if not conf.brute:
        msg = "Starting cipher module."
        logger.info(msg)

        mode = "encrypt" if conf.encrypt else "decrypt"
        key = conf.key
        result = ru.cipherfunc(text, key, mode)

        if conf.lower:
            result = result.lower

        msg = "[+] Work done!\n"
        msg += "[+] Result is \033[40m%s\033[0m\n" % result
        dataToStdout(msg)
        pyperclip.copy(result)
        msg = "[+] Result copying to clipboard, use Ctrl+v to paste.\n"
        dataToStdout(msg)

    else:
        msg = "Starting bruter module."
        logger.info(msg)

        msg = "Starting bruter successfully."
        logger.info(msg)
        msg = 'Start bruting...'
        logger.info(msg)

        result = ru.cipherfunc(text)

        if conf.lower:
            for key in list(result.keys()):
                result[key] = result[key].lower()

        if result != None:
            if conf.verbose:
                msg = "All the possible result:"
                logger.info(msg)
                for key in result.keys():
                    msg = "[+] Key %s: \033[40m%s\033[0m\n" % (key, result[key])
                    dataToStdout(msg)

            else:
                count = 0
                for key in result.keys():
                    if isEnglish(result[key]):
                        count += 1
                        msg = 'Possible encryption hack %d:' % count
                        logger.info(msg)
                        msg = "[+] Possible encryption hack with key %s: \033[40m%s\033[0m\n" % (key, result[key])
                        dataToStdout(msg)
                        pyperclip.copy(result[key])
                        msg = "[+] Result copying to clipboard, use Ctrl+v to paste.\n"
                        dataToStdout(msg)
                if count == 0:
                    msg = "No possible sentence found, use -v to see the full result."
                    logger.warning(msg)
        else:
            msg = "No possible result found."
            logger.critical(msg)

def startDNSProxy(interface, nametodns, nameserver, port="53", ipv6=False, tcp=False):

    try:
        if tcp:
            msg = "Running in tcp mode."
            logger.info(msg)
            server = ThreadedTCPServer((interface, int(port)), ThreadedTCPHandler, nametodns, nameserver, ipv6)
        else:
            server = ThreadedUDPServer((interface, int(port)), ThreadedUDPHandler, nametodns, nameserver, ipv6)

        msg = "DNS proxy start on interface %s:%s" % (interface, port)
        logger.info(msg)

        msg = "Press q to exit..."
        logger.info(msg)

        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        while True:
            pressAnyExit()

    except Exception as e:
        raise PyExpSystemException(e)

def run():

    msg = "[*] Pyexp is Starting at %s.\n\n" % time.strftime("%H:%M:%S")
    dataToStdout(msg)

    if conf.cipher:

        runCipher()

    if conf.dnsproxy:

        startDNSProxy(interface=conf.interface, nametodns=conf.nametodns, nameserver=conf.nameserver, tcp=conf.tcp, ipv6=conf.ipv6)

    if conf.ssh:

        if conf.sshdirect:

            sshDirect(ru.sshhost, ru.sshuser, ru.sshport, ru.sshpassword, ru.sshkeyfile)

        if conf.sshkeygen:

            sshKeyGen(bits=conf.bits, ktype=conf.ktype)

        if conf.sshlocal:
            sshLocalForward(sshlocal=conf.sshlocal, remote=conf.remote, key_filename=conf.privfile,
                            password=conf.password)

        if conf.sshremote:
            sshRemoteForward(sshremote=conf.sshremote, remote=conf.remote, key_filename=conf.privfile,
                             password=conf.password)

    msg = "\n[*] Pyexp is shutting down at %s.\n\n" % time.strftime("%H:%M:%S")
    dataToStdout(msg)



