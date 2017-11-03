import sys
import os
import getpass
import re
import paramiko
import threading

from lib.core.expection import PyExpSystemException
from lib.core.settings import USERHOME
from lib.ssh.sshtype import RemoteSSHHandler
from lib.ssh.sshtype import forward_tunnel
from lib.ssh.interactive import interactive_shell
from lib.core.settings import key_dispatch_table
from lib.core.data import logger
from lib.core.data import conf
from lib.core.common import dataToStdout

from binascii import hexlify
from paramiko.py3compat import u
from paramiko import SSHClient

def sshDirect(host, user, port, password, key_filename):

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    msg = "Connecting to %s@%s..." % (user, host)
    logger.info(msg)

    try:
        client.connect(hostname=host, port=int(port), username=user, password=password, key_filename=key_filename, timeout=5)
        chan = client.invoke_shell()
        msg = (repr(client.get_transport()))
        dataToStdout(msg)
        msg = "Connected to %s successfully, opening interactive shell...      " % host
        logger.info(msg)
        msg = "Successfully, opening shell for %s...\n" % user
        logger.info(msg)
        interactive_shell(chan)
        msg = "\nUser logout."
        logger.info(msg)
        chan.close()
        client.close()

    except Exception as e:
        errMsg = str(e)
        try:
            client.close()
        except:
            pass
        raise PyExpSystemException(errMsg)

def sshKeyGen(bits, ktype):

    sshkeyfile = input("Enter file in which to save the key, default:(%s/.ssh/id_rsa):" % USERHOME)

    if not sshkeyfile:
        if not os.path.exists("%s/.ssh" % USERHOME):
            os.makedirs("%s/.ssh" % USERHOME)
        sshkeyfile = "%s/.ssh/id_rsa" % USERHOME
    else:

        filedir = re.match('.+/', sshkeyfile)
        filedir = filedir.group(0)
        while not os.path.exists(filedir):
            msg = "Please enter a vaild directory."
            logger.error(msg)
            sshkeyfile = input("Enter file in which to save the key, default:(%s/.ssh/id_rsa):" % USERHOME)
            filedir = re.match('.+/', sshkeyfile)
            filedir = filedir.group(0)

    passphraefir = getpass.getpass("Enter passphrase (empty for no passphrase): ")
    passphraesec = getpass.getpass("Enter same passphrase again: ")

    while passphraefir != passphraesec:
        msg = "Passphrases do not match.  Try again."
        logger.error(msg)
        passphraefir = getpass.getpass("Enter passphrase (empty for no passphrase): ")
        passphraesec = getpass.getpass("Enter same passphrase again: ")

    passphrae = passphraefir

    privateKey = key_dispatch_table[ktype].generate(bits=bits, progress_func=progress)
    privateKey.write_private_key_file(sshkeyfile, password=passphrae)

    msg = "Your identification has been saved in %s" % sshkeyfile
    logger.info(msg)

    publicKey = key_dispatch_table[ktype](filename=sshkeyfile, password=passphrae)

    with open("%s.pub" % sshkeyfile, 'w') as f:
        f.write("%s %s" % (publicKey.get_name(), publicKey.get_base64()))

    hash = u(hexlify(publicKey.get_fingerprint()))
    msg = "Fingerprint: %d %s %s.pub (%s)" % (
    conf.bits, ":".join([hash[i:2 + i] for i in range(0, len(hash), 2)]), conf.sshkeyfile, conf.ktype.upper())
    logger.info(msg)


def sshLocalForward(sshlocal, remote, key_filename=None, password=False):
    localport, remoteserverip, remoteserverport = sshlocal.split(":")
    sshserveruser, sshserver = remote.split("@")
    sshserverip, sshserverport = sshserver.split(":")

    if password:
        password = getpass.getpass("Enter SSH password: ")

    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    msg = 'Connecting to ssh host %s:%s ...' % (sshserverip, sshserverport)
    logger.info(msg)

    try:
        client.connect(sshserverip, int(sshserverport), username=sshserveruser, key_filename=None, look_for_keys=True,
                       password=password, banner_timeout=3)
    except Exception as e:
        msg = 'Failed to connect to %s:%s: %r' % (sshserverip, sshserverport, e)
        logger.error(msg)
        raise SystemExit

    msg = 'Now forwarding port %s to %s:%s ....' % (localport, remoteserverip, remoteserverport)
    logger.info(msg)

    try:
        forward_tunnel(int(localport), remoteserverip, int(remoteserverport), client.get_transport())
    except KeyboardInterrupt:
        msg = 'C-c: Port forwarding stopped.'
        logger.info(msg)
        raise SystemExit


def sshRemoteForward(sshremote, remote, key_filename=None, password=False):
    remoteport, remoteserverip, remoteserverport = sshremote.split(":")
    sshserveruser, sshserver = remote.split("@")
    sshserverip, sshserverport = sshserver.split(":")

    if password:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    msg = 'Connecting to ssh host %s:%s ...' % (sshserverip, sshserverport)
    logger.info(msg)

    try:
        client.connect(sshserverip, int(sshserverport), username=sshserveruser, key_filename=None, look_for_keys=True,
                       password=password, banner_timeout=3)
    except Exception as e:
        msg = 'Failed to connect to %s:%s: %r' % (sshserverip, sshserverport, e)
        logger.error(msg)
        raise SystemExit

    msg = 'Now forwarding remote port %s to %s:%s ....' % (remoteport, remoteserverip, remoteserverport)
    logger.info(msg)

    try:
        reverse_forward_tunnel(int(remoteport), remoteserverip, int(remoteserverport), client.get_transport())
    except KeyboardInterrupt:
        msg = 'C-c: Port forwarding stopped.'
        logger.info(msg)
        raise SystemExit

def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):

    transport.request_port_forward('', server_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(target=RemoteSSHHandler, args=(chan, remote_host, remote_port))
        thr.setDaemon(True)
        thr.start()

def progress(arg=None):

    if not arg:
        sys.stdout.write('0%\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'p':
        sys.stdout.write('25%\x08\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'h':
        sys.stdout.write('50%\x08\x08\x08\x08 ')
        sys.stdout.flush()
    elif arg[0] == 'x':
        sys.stdout.write('75%\x08\x08\x08\x08 ')
        sys.stdout.flush()