import sys
import re

from optparse import OptionGroup
from optparse import OptionParser
from optparse import SUPPRESS_HELP

from lib.core.settings import BASIC_HELP_ITEMS
from lib.core.settings import VERSION
from lib.core.common import dataToStdout

def cmdLineParser(argv=None):

    if not argv:
        argv = sys.argv

    try:
        usage = "usage: python3 %prog [options] arg1 arg2"

        parser = OptionParser(usage=usage)

        parser.add_option("--hh", dest="advancedHelp",
                          action="store_true",
                          help="Show advanced help message and exit")
        parser.add_option("--version", dest="showVersion",
                          action="store_true",
                          help="Show program's version number and exit")
        parser.add_option("-t", "--thread", dest="threads",default=1,
                          type=int,
                          help="Set the number of threads, default 1.")
        parser.add_option("-v", "--verbose", dest="verbose",default=False,
                          action="store_true",
                          help="Show the result as verbosely as possible.")
        parser.add_option("-o", "--output", dest="out",
                          action="store",
                          help="Store the result to a file.")


        cipher = OptionGroup(parser, "Cipher", "Cipher module, have both classic cipher and advanced cipher methods.")

        cipher.add_option("--cipher", dest="cipher",
                          help="encrypt or decrypt text using the given method, they are: reverse, caesar, transposition, affine, sub, bacon, vigenere")
        cipher.add_option("-E", "--encrypt", dest="encrypt",default=False,
                          action="store_true",
                          help="enable encrypt mode.")
        cipher.add_option("-D", "--decrypt", dest="decrypt",default=False,
                          action="store_true",
                          help="enable decrypt mode.")
        cipher.add_option("-B", "--brute", dest="brute", default=False,
                          action="store_true",
                          help="use the brute force to decrypt text, use with the option --decrypt")
        cipher.add_option("-T", "--text", dest="text",
                          help="input the text waiting to be ciphered, please use with \"\"")
        cipher.add_option("--cipher-key", dest="key",
                          help="specify the key used in encrypt or decrypt.")
        cipher.add_option("-f", "--file", dest="file",
                          help="Use file content as the input text.")
        cipher.add_option("--lower", dest="lower", default=False,
                          action="store_true",
                          help="Set the output as lower letters.")

        parser.add_option_group(cipher)

        dns = OptionGroup(parser, "DNS Proxy", "A simple DNS proxy, can modify dns record.")

        dns.add_option("--dns", dest="dnsproxy", default=False,
                       action="store_true",
                       help="Enable DNS proxy module.")
        dns.add_option("--fakeip", dest="fakeip", metavar="192.0.2.1",
                       action="store",
                       help="IP address to use for matching DNS queries. If you use this parameter without specifying domain names, then all \'A\' queries will be spoofed. Consider using --file argument if you need to define more than one IP address."
                       )
        dns.add_option("--fakeipv6", dest="fakeipv6", metavar="2001:db8::1",
                       action="store",
                       help="Use IPV6 IP address for fakeip.")
        dns.add_option("--fakemail", dest="fakemail", metavar="mail.fake.com",
                       action="store",
                       help="Use fake MX record.")
        dns.add_option("--fakealias", dest="fakealias", metavar="www.fake.com",
                       action="store",
                       help="Use fake CNAME record.")
        dns.add_option("--fakens", dest="fakens", metavar="ns.fake.com",
                       action="store",
                       help="Use fake NS record."
                       )
        dns.add_option("--fakedomain", dest="fakedomain", metavar="baidu.com",
                       action="store",
                       help="A list separated by comma, specify the domains which will be resolved to fake values given above."
                       )
        dns.add_option("--truedomain", dest="truedomain", metavar="baidu.com",
                       action="store",
                       help="A list separated by comma, specify the domains which will be resolved to true values."
                       )
        dns.add_option("--nameserver", dest="nameserver",
                       metavar="8.8.8.8#53 or 4.2.2.1#53#tcp or 2001:4860:4860::8888", default="8.8.8.8",
                       action="store",
                       help="A list separated by comma of alternative DNS servers to use with proxied requests. Nameservers can have either IP or IP#PORT format. A randomly selected server from the list will be used for proxy requests when provided with multiple servers. By default, the tool uses Google\'s public DNS server 8.8.8.8 when running in IPv4 mode and 2001:4860:4860::8888 when running in IPv6 mode."
                       )
        dns.add_option("--interface", metavar="127.0.0.1 or ::1", default="127.0.0.1",
                       action="store",
                       help="Define an interface to use for the DNS listener. By default, the tool uses 127.0.0.1 for IPv4 mode and ::1 for IPv6 mode."
                       )
        dns.add_option("--tcp", dest="tcp", default=False,
                       action="store_true",
                       help="Enable TCP mode."
                       )
        dns.add_option("--ipv6", dest="ipv6", default=False,
                       action="store_true",
                       help="Run in IPV6 mode."
                       )

        parser.add_option_group(dns)

        ssh = OptionGroup(parser, "SSH", "Module for ssh key generate, forwarding and so on.")

        ssh.add_option("--ssh", dest="ssh", default=False,
                       action="store_true",
                       help="Enable ssh module.")
        ssh.add_option("-d", "--direct", dest="sshdirect", metavar="user@ssh_host:ssh_host_port",
                       action="store",
                       help="Connect to the remote ssh server directly, such as the openssh, can be used with the -P to input the password or --private-key to use key file.")
        ssh.add_option("--ssh-keygen", dest="sshkeygen", default=False,
                       action="store_true",
                       help="Generate ssh key pair.")
        ssh.add_option("--bits", dest="bits", metavar="bits", default=1024,
                       type="int",
                       action="store",
                       help="Number of bits in the key to create")
        ssh.add_option("--ktype", dest="ktype", metavar="ktype", default="rsa",
                       action="store",
                       help="Specify type of key to create (dsa or rsa).")
        ssh.add_option("-L", dest="sshlocal", metavar="local_port:host:host_port",
                       action="store",
                       help="Set up a forward tunnel across an SSH server, and was followed by the parttern \033[4m[local_port]:[host]:[host_port]\033[0m, this is similar to the openssh -L option.")
        ssh.add_option("-R", dest="sshremote", metavar="remote_port:host:host_port",
                       action="store",
                       help="Set up a remote port forward tunnel across ana SSH server, and was followed by the parttern \033[4m[remote_port]:[host]:[host_port]\033[0m, this is similar to the openssh -R option.")
        ssh.add_option("--remote", dest="remote", metavar="user@ssh_ip:ssh_port",
                       action="store",
                       help="Remote user, host and port to forward to, like the openssh, followed by the pattern \033[4m[user@][ssh_ip]:[ssh_port]\033[0m.")
        ssh.add_option("-P", dest="password", default=False,
                       action="store_true",
                       help="Read password (for key or password auth) from stdin.")
        ssh.add_option("--private-key", dest="privfile",
                       action="store",
                       help="Private key file to use for SSH authentication.")

        parser.add_option_group(ssh)

        option = parser.get_option("--hh")
        option._short_opts = ["-hh"]
        option._long_opts = []

        option = parser.get_option("-h")
        option.help = option.help.capitalize().replace("this help", "basic help")

        _ = []
        advancedHelp = True

        for arg in argv:
            _.append(arg)
        argv = _

        for i in range(len(argv)):
            if argv[i] == "-hh":
                argv[i] = "-h"
            elif re.search(r"\A-\w=.+", argv[i]):
                print("[!] potentially miswritten (illegal '=') short option detected ('%s')\n" % argv[i])
                raise SystemExit
            elif argv[i] == "--version":
                print(VERSION)
                raise SystemExit
            elif argv[i] == "-h":
                advancedHelp = False
                for group in parser.option_groups[:]:
                    found = False
                    for option in group.option_list:
                        if option.dest not in BASIC_HELP_ITEMS:
                            option.help = SUPPRESS_HELP
                        else:
                            found = True
                        if not found:
                            parser.option_groups.remove(group)
            elif argv[i] == "--cipher=reverse":
                argv.append("-E")

        try:
            (options, args) = parser.parse_args(argv)
        except SystemExit:
            if "-h" in sys.argv and not advancedHelp:
                dataToStdout("\033[32m\n[!] to see full list of options run with '-hh'\n\033[0m")
            raise

        if len(argv) == 1:
            errMsg = "missing a mandatory option, "
            errMsg += "use -h for basic or -hh for advanced help"
            parser.error(errMsg)

        return options

    except SystemExit:
        raise


