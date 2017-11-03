import sys
import re
import os

from paramiko import RSAKey
from paramiko import DSSKey

VERSION = "1.0.0#"
SITE = "http://pwdme.cc"
EMAIL = "i@pwdme.cc"
IS_WIN = False
MSWINDOWS = (sys.platform == "win32")
BANNER = """\033[34m
 ____        _____            
|  _ \ _   _| ____|_  ___ __\033[0m{\033[31m%s\033[0m}\033[034m  
| |_) | | | |  _| \ \/ / '_ \ 
|  __/| |_| | |___ >  <| |_) |
|_|    \__, |_____/_/\_\ .__/ 
       |___/           |_|   \033[0m\033[4;37m%s\033[0m

email: %s\033[0m\n
""" % (VERSION ,SITE, EMAIL)
UNICODE_ENCODING = "utf8"
BASIC_HELP_ITEMS = (
    "cipher",
    "encrypt",
    "decrypt",
    "brute",
    "file",
    "text",
    "key",
    "dnsproxy",
    "fakeip",
    "fakedomain",
    "truedomain",
    "ssh",
    "sshdirect",
    "sshkeygen",
    "sshlocal",
    "sshremote",
    "remote",
    "password",
    "privfile",
)
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
UPPERLETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERLETTERS = "abcdefghijklmnopqrstuvwxyz"
SYMBOLS = """ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
LETTERS_AND_SPACE = LETTERS + ' \t\n_'
CIPHER_TYPE = ["reverse", "caesar", "transposition", "affine", "sub", "bacon", "vigenere"]
nonLettersOrSpacePattern = re.compile('[^A-Z\s]')
NONLETTERS_PATTERN = re.compile('[^A-Z]')
# frequency taken from http://en.wikipedia.org/wiki/Letter_frequency
englishLetterFreq = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I':\
6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R':5.99, 'D': 4.25, 'L': 4.03, 'C':\
2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F':2.23, 'G': 2.02, 'Y': 1.97, 'P':\
1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J':0.15, 'X': 0.15, 'Q': 0.10, 'Z':\
0.07}
ETAOIN = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
USERHOME = os.environ["HOME"]
key_dispatch_table = {
    'dsa': DSSKey,
    'rsa': RSAKey,
}