# STRANGERDANGER

This is a Python-based connect-back userland VPN.

An operator sets up the Server on a publicly routable endpoint, and executes the Proxy on target. The Proxy connects out to the Server, and the operator adds routes on the server that force traffic through the connection, proxying through the target network.

## Requirements
- Python 2.6 or 2.7
- root-level access (see Artifacts)

## Artifacts
Note: All these target-side artifacts are cleaned up when the Python process exits
- Creates a tun adapter and assigns an IP address
- Creates a route to the tunnel subnet
- Adds an iptables rule to SNAT traffic (to route traffic beyond the target endpoint)
- Python process in process list, TLS connection to Server

## Tested
- CentOS 6.7 with Python 2.6.6
- CentOS 7.2 with Python 2.7.5
- Ubuntu 16.04 LTS with Python 2.7.12

## Server usage
```
$ bash bin/genkeys.sh  # Replace with e.g. certbot certificate/key generation
$ sudo python strangerdanger.py -d server --cert cert.pem --key key.pem
```

## Proxy usage
```
$ sudo python strangerdanger.py -d proxy --server-ip <IP/domain of server>
```

## Advanced routes
To overwrite the default gateway, you can do the following (this is NOT recommended!!):
```
In a normal terminal:
# ip route add <ip you're connected from>/32 via <default gateway IP>
# ip route add <public IP target connects from>/32 via <default gateway IP>

Via strangerdanger menu, add these routes:
128.0.0.0/1
0.0.0.0/1
```
This is how OpenVPN overrides the default gateway without reassigning it, and makes cleanup easier down the road.
