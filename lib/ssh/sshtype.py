import socketserver
import select
import socket

from lib.core.data import logger

class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip',
                                                   (self.chain_host, self.chain_port),
                                                   self.request.getpeername())
        except Exception as e:
            msg = 'Incoming request to %s:%s failed: %s' % (self.chain_host,
                                                            self.chain_port,
                                                            repr(e))
            logger.error(msg)
            return

        if chan is None:
            msg = 'Incoming request to %s:%s was rejected by the SSH server.' % (self.chain_host, self.chain_port)
            logger.error(msg)
            return

        msg = 'Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(),
                                                          chan.getpeername(), (self.chain_host, self.chain_port))
        logger.info(msg)
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        chan.close()
        self.request.close()
        msg = 'Tunnel closed from %r' % (peername,)
        logger.info(msg)

def RemoteSSHHandler(chan, host, port):

    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        msg = 'Forwarding request to %s:%d failed: %r' % (host, port, e)
        logger.error(msg)
        return

    msg = 'Connected!  Tunnel open %r -> %r -> %r' % (chan.origin_addr, chan.getpeername(), (host, port))
    logger.info(msg)

    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    msg = 'Tunnel closed from %r' % (chan.origin_addr,)
    logger.info(msg)

def forward_tunnel(local_port, remote_host, remote_port, transport):

    class SubHander(Handler):

        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport

    ForwardServer(('', local_port), SubHander).serve_forever()
