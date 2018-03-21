import argparse
import atexit
import fcntl
import json
import logging
import os
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


class Message(object):
    HEADER_FMT = b'!BI'
    HEADER_FMT_LEN = struct.calcsize(HEADER_FMT)
    M_NOOP = 0x00
    M_TUN_OPEN = 0x01
    M_TUN_CLOSE = 0x02
    M_TUN_DATA = 0x03
    M_TUN_ASSIGN = 0x04
    M_ERROR = 0x80

    def __str__(self):
        return '<Message type={0} body_len={1}>'.format(self.type, self.body_len)

    def __init__(self, body=b'', mtype=0):
        self.body = body
        self.body_len = len(body)
        self.type = mtype

    def pack(self):
        return struct.pack(self.HEADER_FMT, self.type, self.body_len) + self.body

    def unpack(self, m, throw=True):
        if len(m) < Message.HEADER_FMT_LEN:
            raise ValueError('Unable to parse Message: incomplete header')
        self.type, self.body_len = struct.unpack(self.HEADER_FMT, m[:self.HEADER_FMT_LEN])
        self.body = m[Message.HEADER_FMT_LEN:]
        if (self.body_len != len(self.body)) and throw:
            raise ValueError('Received invalid Message')


class Tun(object):
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = TUNSETIFF + 2
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    ROUTE_ADD = 'ip route add {0} via {1}'
    ROUTE_DEL = 'ip route del {0} via {1}'
    FW_ADD = 'iptables -t nat -I POSTROUTING -j MASQUERADE'
    FW_DEL = 'iptables -t nat -D POSTROUTING -j MASQUERADE'

    def __init__(self, local_addr, iface='tun0'):
        self.local_addr = local_addr
        self.routes = []

        # Create tun interface
        self.tun = open('/dev/net/tun', 'r+b')
        ifr = struct.pack('16sH', iface, Tun.IFF_TUN | Tun.IFF_NO_PI)
        self.iface = fcntl.ioctl(self.tun, Tun.TUNSETIFF, ifr)[:16].strip(b'\x00')
        fcntl.ioctl(self.tun, Tun.TUNSETOWNER, os.geteuid())

        # Bring up the tun interface and assign IP address
        subprocess.check_call('ip link set dev {0} up mtu 1500'.format(self.iface), shell=True)
        subprocess.check_call('ip addr add dev {0} {1}'.format(self.iface, self.local_addr), shell=True)

        # Enable IP forwarding
        subprocess.check_call('echo 1 >/proc/sys/net/ipv4/ip_forward', shell=True)
        subprocess.check_call(self.FW_ADD, shell=True)

        # Add atexit to clean up all this shiz
        atexit.register(self.cleanup)

    def fileno(self):
        return self.tun.fileno()

    def write(self, data):
        os.write(self.tun.fileno(), data)

    def read(self, n=1500):
        return os.read(self.tun.fileno(), n)

    def add_route(self, subnet, via):
        if '/' not in subnet:
            raise ValueError('Expected a subnet value like "127.0.0.1/24"')
        if subnet in self.routes:
            return
        subprocess.check_call(self.ROUTE_ADD.format(subnet, via), shell=True)
        self.routes.append(subnet)

    def del_route(self, subnet, via):
        if '/' not in subnet:
            raise ValueError('Expected a subnet value like "127.0.0.1/24"')
        if subnet not in self.routes:
            return
        subprocess.check_call(self.ROUTE_DEL.format(subnet, via), shell=True)
        self.routes.remove(subnet)

    def cleanup(self):
        # Remove fw forwarding
        subprocess.check_call(self.FW_DEL, shell=True)

        # Clear routes list. Actual routes are deleted at host level when interface goes down
        self.routes = []

        # Remove interface
        subprocess.check_call('ip link del dev {0}'.format(self.iface), shell=True)


class IpNetwork(object):
    def __init__(self, cidr_address):
        self.cidr_address = cidr_address
        self.current = self.network_address

    def __iter__(self):
        return self

    def next(self):
        self.current = self.int_to_ip(self.ip_to_int(self.current) + 1)
        if self.ip_to_int(self.current) >= self.ip_to_int(self.broadcast_address):
            raise StopIteration
        return self.current

    @property
    def network_address(self):
        return self.int_to_ip(self.ip_to_int(self.cidr_address.split('/')[0]) & self.cidr_mask)

    @property
    def host_bits(self):
        return int(self.cidr_address.split('/')[1])

    @property
    def broadcast_address(self):
        return self.int_to_ip((self.cidr_mask ^ 0xffffffff) | self.ip_to_int(self.network_address))

    @property
    def subnet_mask(self):
        return self.int_to_ip(self.cidr_mask)

    @property
    def cidr_mask(self):
        return (0xffffffff >> (32 - self.host_bits)) << (32 - self.host_bits)

    @staticmethod
    def ip_to_int(i):
        i, = struct.unpack('!I', socket.inet_aton(i))
        return i

    @staticmethod
    def int_to_ip(i):
        return socket.inet_ntoa(struct.pack('!I', i))


class VpnBase(object):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.tun = None  # type: Tun
        self.transport = None  # type: socket.socket
        self.proxy_thread = None  # type: threading.Thread
        self.keepalive_thread = None  # type: threading.Timer
        self.data_counters = [0, 0]  # [tx, rx]
        self.should_stop = False
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()
        signal.signal(signal.SIGINT, self.kill_thread)

    def kill_thread(self, *args):
        self.logger.debug('Received stop command')
        self.should_stop = True
        if self.keepalive_thread is not None:
            self.keepalive_thread.join()
        if self.proxy_thread is not None:
            self.proxy_thread.join()
        sys.exit(0)

    def _recv_all(self, n):
        data = b''
        while len(data) < n:
            d = self.transport.recv(n - len(data))
            if not d:
                raise ValueError('Remote end sent EOF')
            data += d
        return data

    def recv_message(self):
        self.recv_lock.acquire()
        header = self._recv_all(Message.HEADER_FMT_LEN)
        msg = Message()
        msg.unpack(header, throw=False)
        msg.body = self._recv_all(msg.body_len)
        self.recv_lock.release()
        self.data_counters[1] += (msg.body_len + msg.HEADER_FMT_LEN)
        return msg

    def send_message(self, m):
        data = m.pack()
        self.send_lock.acquire()
        self.transport.sendall(data)
        self.send_lock.release()
        self.data_counters[0] += len(data)

    def proxy(self):
        self.logger.debug('Starting a proxy thread')
        while True:
            if self.should_stop:
                self.logger.warning('Terminating proxy thread')
                return
            try:
                r, _, _ = select.select([self.transport, self.tun], [], [], 0.1)
                if self.transport in r:
                    msg = self.recv_message()
                    if msg.type == Message.M_TUN_DATA:
                        self.tun.write(msg.body)
                        # TODO : handle other message types
                if self.tun in r:
                    msg = Message(body=self.tun.read(), mtype=Message.M_TUN_DATA)
                    self.send_message(msg)
            except Exception as e:
                self.logger.critical('Problem encountered while using tun/network')
                os.kill(os.getpid(), signal.SIGINT)

    def run(self):
        raise NotImplementedError('You must provide the run() method in your subclass')


class VpnServer(VpnBase):
    def __init__(self, transport_ip, transport_port, tun_subnet, tun_iface, key, cert):
        super(VpnServer, self).__init__()
        self.transport_bind_addr = (transport_ip, transport_port)
        self.transport_client_addr = None
        self.tun_network = IpNetwork(tun_subnet)
        self.tun_local_ip = self.tun_network.next()
        self.tun_remote_ip = self.tun_network.next()
        self.certfile = cert
        self.keyfile = key

        # Set up the server
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(self.transport_bind_addr)
        self.server.listen(1)

        # Create tun device
        self.tun = Tun('{0}/{1}'.format(self.tun_local_ip, self.tun_network.host_bits), iface=tun_iface)
        self.tun_iface = self.tun.iface

    def __str__(self):
        return '<VpnServer iface={0} ip={1} tx={2} rx={3}>'.format(self.tun_iface, self.tun_local_ip,
                                                                   *self.data_counters)

    @property
    def routes(self):
        return self.tun.routes

    def keepalive(self):
        self.logger.debug('Keepalive thread starting')
        t = time.time()
        while not self.should_stop:
            if time.time() - t > 30:
                t = time.time()
                self.send_message(Message(mtype=Message.M_NOOP))
            else:
                time.sleep(1)
        self.logger.debug('Keepalive thread exiting')
        return

    def run(self):
        # Accept a client connection
        self.logger.debug('Waiting for client to connect on {0}:{1}'.format(*self.transport_bind_addr))
        self.transport, self.transport_client_addr = self.server.accept()
        self.transport = ssl.wrap_socket(self.transport, keyfile=self.keyfile, certfile=self.certfile, server_side=True)
        self.logger.warning('Accepted client connection from {0}:{1}'.format(*self.transport_client_addr))

        # Send IP address assignment and wait for M_TUN_OPEN
        self.send_message(
            Message(
                mtype=Message.M_TUN_ASSIGN,
                body=json.dumps({
                    'address': '{0}'.format(self.tun_remote_ip),
                    'remote_address': self.tun_local_ip,
                    'cidr': self.tun_network.host_bits
                })
            )
        )
        msg = self.recv_message()
        if msg.type != Message.M_TUN_OPEN:
            raise ValueError('Invalid message received. Wanted M_TUN_OPEN and got {0}'.format(msg))

        # Start a thread to handle data proxying
        self.proxy_thread = threading.Thread(target=self.proxy)
        self.proxy_thread.start()

        # Start a thread to handle keepalives
        self.keepalive_thread = threading.Thread(target=self.keepalive)
        self.keepalive_thread.start()


class VpnProxy(VpnBase):
    def __init__(self, server_ip, server_port):
        super(VpnProxy, self).__init__()
        self.transport_addr = (server_ip, server_port)
        self.tun_local_ip = None
        self.tun_remote_ip = None
        self.tun_iface = None

        # Create tun device
        self.tun = None

    def __str__(self):
        return '<VpnProxy iface={0} ip={1} tx={2} rx={3}>'.format(self.tun_iface, self.tun_local_ip,
                                                                  *self.data_counters)

    def run(self):
        # Connect to server
        self.logger.debug('Connecting to {0}:{1}'.format(*self.transport_addr))
        self.transport = socket.socket()
        self.transport.connect(self.transport_addr)
        self.transport = ssl.wrap_socket(self.transport)

        # Receive address assignment, send M_TUN_OPEN
        msg = self.recv_message()
        if msg.type != Message.M_TUN_ASSIGN:
            raise ValueError('Invalid message received. Wanted M_TUN_ASSIGN and got {0}'.format(msg))
        assignment = json.loads(msg.body)
        self.tun_local_ip = assignment['address']
        self.tun_remote_ip = assignment['remote_address']
        tun_iface = assignment.get('iface', '')
        self.tun = Tun('{0}/{1}'.format(self.tun_local_ip, assignment['cidr']), iface=tun_iface)
        self.tun_iface = self.tun.iface

        self.send_message(Message(mtype=Message.M_TUN_OPEN))

        # Proxy data between network/Tun
        self.proxy()


def server_main(args):
    s = VpnServer(args.bind_ip, args.bind_port, args.tunnel_subnet, args.tun_iface, args.key, args.cert)
    s.run()
    while True:
        print('---')
        print('1 - Add a route to target network')
        print('2 - Remove a route to target network')
        print('3 - See tunnel stats')
        print('q - burn')
        p = raw_input('> ')
        if p == '1':
            subnet = raw_input('Subnet> ')
            try:
                s.tun.add_route(subnet, s.tun_remote_ip)
            except Exception as e:
                print('[!] Unable to add that subnet! ' + str(e))
        if p == '2':
            subnet = raw_input('Subnet> ')
            try:
                s.tun.del_route(subnet, s.tun_remote_ip)
            except Exception as e:
                print('[!] Unable to remove that subnet! ' + str(e))
        elif p == '3':
            print('Tunnel Info')
            print('\tTun iface: {0}'.format(s.tun_iface))
            print('\tTunnel IP: {0}'.format(s.tun_local_ip))
            print('\tTunnelNet: {0}'.format(s.tun_network.cidr_address))
            print('\tClient:    {0}:{1}'.format(*s.transport_client_addr))
            print('\tBytes TX:  {0}'.format(s.data_counters[0]))
            print('\tBytes RX:  {0}'.format(s.data_counters[1]))
            if s.routes:
                print('\nRoutes:\n\t' + '\n\t'.join(s.routes))
            print('')
        elif p == 'q':
            s.kill_thread()
            s.proxy_thread.join()
            return


def proxy_main(args):
    p = VpnProxy(args.server_ip, args.server_port)
    p.run()
    return


def main():
    if os.geteuid() != 0:
        print('[!] Re-run as root')
        return

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    # General options
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--tun-iface', default='', help='Name of the tunnel interface (will be created)')

    # Server options
    parser_s = subparsers.add_parser('server', help='Run in server mode (i.e. accept connections)')
    parser_s.add_argument('--bind-ip', default='', help='IP address to listen on')
    parser_s.add_argument('--bind-port', default=443, type=int, help='Port to listen on')
    parser_s.add_argument('--tunnel-subnet', default='10.8.0.0/24', help='Internal tunnel IP')
    parser_s.add_argument('--cert', required=True, help='A file containing TLS certificate')
    parser_s.add_argument('--key', required=True, help='A file containing TLS key')
    parser_s.set_defaults(main=server_main)

    # Proxy options
    parser_p = subparsers.add_parser('proxy', help='Run in proxy mode (i.e. connect out)')
    parser_p.add_argument('--server-ip', required=True, help='IP to connect to')
    parser_p.add_argument('--server-port', default=443, type=int, help='Port to connect on')
    parser_p.set_defaults(main=proxy_main)

    # Parse and apply args
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(datefmt='%Y-%m-%d %H:%M:%S', format='[%(asctime)s] %(name)s %(levelname)s - %(message)s',
                        level=level)

    args.main(args)


if __name__ == '__main__':
    main()
