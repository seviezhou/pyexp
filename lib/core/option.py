import os
import imp
import re
import getpass

from dnslib import RDMAP

from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths
from lib.core.data import ru
from lib.core.datatype import AttribDict
from lib.core.expection import PyExpSystemException
from lib.core.expection import PyExpSyntaxException
from lib.core.expection import PyExpFileNotFoundException
from lib.core.settings import CIPHER_TYPE
from lib.techniques.detectEnglish import loadDictionary
from lib.core.common import checkFile

def _setCipher():

    if conf.cipher:

        if conf.cipher not in CIPHER_TYPE:
            msg = "Cipher type not supported, check if you have input the right name."
            raise PyExpSystemException(msg)

        if conf.file:
            checkFile(conf.file)
            file = open(conf.file)
            conf.text = file.read()

        if not conf.text:
            msg = "No input text, cipher work aborted."
            raise PyExpSystemException(msg)

        if not conf.encrypt and not conf.decrypt and not conf.brute:
            msg = "Encrypt or Decrypt or Brute not set."
            raise PyExpSystemException(msg)

        if conf.brute:
            conf.englishWords = loadDictionary()

        cfile = conf.cipher
        cfile = cfile.strip()

        if os.path.exists(os.path.join(paths.PYEXP_CIPHER_PATH, "%s.py" % cfile)):
            cfile = os.path.join(paths.PYEXP_CIPHER_PATH, "%s.py" % cfile)

        infoMsg = "loading module '%s.py'" % conf.cipher
        logger.info(infoMsg)

        try:
            file, pathname, description = imp.find_module(conf.cipher, [paths.PYEXP_CIPHER_PATH])
            mod = imp.load_module(conf.cipher, file, pathname, description)
            if not conf.brute:
                try:
                    ru.cipherfunc = mod.cipher
                    infoMsg = "'%s.py' cipher module loaded successfully." % conf.cipher
                    logger.info(infoMsg)
                except:
                    msg = "No cipher function found."
                    raise PyExpSystemException(msg)
            else:
                try:
                    ru.cipherfunc = mod.bruter
                    infoMsg = "'%s.py' bruter module loaded successfully." % conf.cipher
                    logger.info(infoMsg)
                except:
                    msg = "No bruter function found."
                    raise PyExpSystemException(msg)
        except ImportError:
            raise SystemExit

def _initConfAttr():

    debugMsg = "initializing the configuration"
    logger.debug(debugMsg)

    conf.cipher = None
    conf.encrypt = False
    conf.decrypt = False
    conf.brute = False
    conf.text = None
    conf.key = None
    conf.verbose = False
    conf.file = None
    conf.dnsproxy = False
    conf.fakeip = None
    conf.fakeipv6 = None
    conf.fakemail = None
    conf.fakealias = None
    conf.fakens = None
    conf.fakedomain = None
    conf.truedomain = None
    conf.nameserver = None
    conf.interface = None
    conf.tcp = False
    conf.ipv6 = False
    conf.ssh = False
    conf.sshdirect = None
    conf.sshkeygen = False
    conf.bits = None
    conf.ktype = None
    conf.sshlocal = None
    conf.sshremote = None
    conf.remote = None
    conf.password = False
    conf.privfile = None

def _initRuAttr():

    debugMsg = "initializing the runingconf"
    logger.debug(debugMsg)

    ru.cipherfunc = None
    ru.sshhost = None
    ru.sshuser = None
    ru.sshport = None
    ru.sshpassword = None
    ru.sshkeyfile = None

def _setCmdOptionsToConf(CmdOptions):

    if hasattr(CmdOptions, "items"):
        inputOptionsItems = CmdOptions.items()
    else:
        inputOptionsItems = CmdOptions.__dict__.items()
    for key, value in inputOptionsItems:
        conf[key] = value

def _checkOptionConflict():

    if conf.encrypt and conf.decrypt:
        errMsg = "option -E(--encrypt) is incompatible with -D(--decrypt)"
        raise PyExpSyntaxException(errMsg)

    if conf.file and conf.text:
        errMsg = "option -f(--file) is incompatible with -T(--text)"
        raise PyExpSyntaxException(errMsg)

    if (not conf.dnsproxy) and (conf.fakeip or conf.fakeipv6 or conf.fakemail or conf.fakealias or conf.fakens or conf.fakedomain or conf.truedomain):
        errMsg = "You have to use --dns to enable DNS proxy!"
        raise PyExpSyntaxException(errMsg)

    if conf.fakedomain and conf.truedomain:
        errMsg = "You can not specify both \"fakedomain\" and \"truedomain\""
        raise PyExpSyntaxException(errMsg)

    if not (conf.fakeip or conf.fakeipv6) and (conf.fakedomain or conf.truedomain):
        errMsg = "Can not specify domain to spoof and not specify ip."
        raise PyExpSyntaxException(errMsg)

    if not conf.ssh and (conf.sshdirect or conf.sshkeygen or conf.sshlocal or conf.sshremote or conf.remote or conf.password or conf.privfile):
        errMsg = "Use --ssh to enable the SSH module."
        raise PyExpSyntaxException(errMsg)

    if conf.password and conf.privfile:
        errMsg = "Can not use -P and --private-key at the same time."
        raise PyExpSyntaxException(errMsg)

def _setDNSProxy():

    if conf.dnsproxy:

        conf.nametodns = dict()

        for qtype in RDMAP.keys():

           conf.nametodns[qtype] = dict()

        if conf.ipv6:
            infoMsg = "Enable ipv6 mode."
            logger.info(infoMsg)
            if conf.interface == "127.0.0.1":
                conf.interface = "::1"

            if conf.nameserver == "8.8.8.8":
                conf.nameserver = "2001:4860:4860:8888"

        if conf.nameserver:
            conf.nameserver = conf.nameserver.split(",")

        if conf.fakeipv6 or conf.fakeip or conf.fakemail or conf.fakealias or conf.fakens:

            if conf.fakedomain:

                for domain in conf.fakedomain.split(","):

                    domain = domain.lower()
                    domain = domain.strip()

                    if conf.fakeip:
                        conf.nametodns["A"][domain] = conf.fakeip
                        msg = "Cooking A replies to point to %s matching: %s" % (conf.fakeip, domain)
                        logger.info(msg)

                    if conf.fakeipv6:
                        conf.nametodns["AAAA"][domain] = conf.fakeipv6
                        msg = "Cooking AAAA replies to point to %s matching: %s" % (conf.fakeipv6, domain)
                        logger.info(msg)

                    if conf.fakemail:
                        conf.nametodns["MX"][domain] = conf.fakemail
                        msg = "Cooking MX replies to point to %s matching: %s" % (conf.fakemail, domain)
                        logger.info(msg)

                    if conf.fakens:
                        conf.nametodns["NS"][domain] = conf.fakens
                        msg = "Cooking NS replies to point to %s matching: %s" % (conf.fakens, domain)
                        logger.info(msg)

                    if conf.fakealias:
                        conf.nametodns["CNAME"][domain] = conf.fakealias
                        msg = "Cooking CNAME replies to point to %s matching: %s" % (conf.fakealias, domain)
                        logger.info(msg)

            elif conf.truedomain:

                for domain in conf.truedomain.split(","):

                    doamin = domain.lower()
                    domain = domain.strip()

                    if conf.fakeip:
                        conf.nametodns["A"][doamin] = False
                        conf.nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = conf.fakeip
                        msg = "Cooking A replies to point to %s not matching: %s" % (conf.fakeip, domain)
                        logger.info(msg)

                    if conf.fakeipv6:
                        conf.nametodns["AAAA"][doamin] = False
                        conf.nametodns["AAAA"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakeipv6
                        msg = "Cooking AAAA replies to point to %s not matching: %s" % (conf.fakeipv6, domain)
                        logger.info(msg)

                    if conf.fakemail:
                        conf.nametodns["MX"][domain] = False
                        conf.nametodns["MX"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakemail
                        msg = "Cooking MX replies to point to %s not matching: %s" % (conf.fakemail, domain)
                        logger.info(msg)

                    if conf.fakens:
                        conf.nametodns["NS"][domain] = False
                        conf.nametodns["NS"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakens
                        msg = "Cooking NS replies to point to %s not matching: %s" % (conf.fakens, domain)
                        logger.info(msg)

                    if conf.fakealias:
                        conf.nametodns["CNAME"][domain] = False
                        conf.nametodns["CNAME"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakealias
                        msg = "Cooking CNAME replies to point to %s not matching: %s" % (conf.fakealias, domain)
                        logger.info(msg)

            else:

                if conf.fakeip:
                    conf.nametodns["A"]['*.*.*.*.*.*.*.*.*.*'] = conf.fakeip
                    msg = "Cooking all A replies to point to %s" % conf.fakeip
                    logger.info(msg)

                if conf.fakeipv6:
                    conf.nametodns["AAAA"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakeipv6
                    msg = "Cooking all AAAA replies to point to %s" % conf.fakeipv6
                    logger.info(msg)

                if conf.fakemail:
                    conf.nametodns["MX"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakemail
                    msg = "Cooking all MX replies to point to %s" % conf.fakemail
                    logger.info(msg)

                if conf.fakens:
                    conf.nametodns["NS"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakens
                    msg = "Cooking all NS replies to point to %s" % conf.fakens
                    logger.info(msg)

                if conf.fakealias:
                    conf.nametodns["CNAME"]["*.*.*.*.*.*.*.*.*.*"] = conf.fakealias
                    msg = "Cooking all CNAME replies to point to %s" % conf.fakealias
                    logger.info(msg)

def _setSSH():

    if conf.ssh:

        if conf.sshdirect:

            if not (conf.password or conf.privfile):

                errMsg = "You should specific at least one method(password or private key file) to make ssh connection."
                raise PyExpSyntaxException(errMsg)

            direct = conf.sshdirect

            if re.match("\w+@.+:\d+", direct):

                ru.sshuser = direct.split("@")[0]
                ru.sshhost = direct.split("@")[1].split(":")[0]
                ru.sshport = direct.split("@")[1].split(":")[1]

            else:
                errMsg = "Please use the correct pattern user@ip:port!"
                raise PyExpSyntaxException(errMsg)

            if conf.password:

                ru.sshpassword = getpass.getpass("Enter the password for %s@%s:" % (ru.sshuser, ru.sshhost))

            else:

                if os.path.exists(conf.privfile):
                    ru.sshkeyfile = conf.privfile
                else:
                    errMsg = "File %s does not exist." % conf.privfile
                    raise PyExpFileNotFoundException(errMsg)

def initOptions(CmdOptions=AttribDict()):
    _initConfAttr()
    _initRuAttr()
    _setCmdOptionsToConf(CmdOptions)

def init():
    _checkOptionConflict()
    _setDNSProxy()
    _setCipher()
    _setSSH()