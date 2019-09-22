# etherwake-nfqueue


## Wake up computers on netfilter match

**etherwake-nfqueue** is a fork of the **etherwake** Wake-on-LAN client,
with support to send magic packets only after a queued packet is received
from the Linux *nfnetlink_queue* subsystem.

When running **etherwake-nfqueue** on a residential gateway or other type of
router, it can wake up hosts on its network based on packet filtering rules.

For instance, when your set-top box wants to record a TV programme and
tries to access a network share on your NAS, which is in sleep or standby mode,
**etherwake-nfqueue** can wake up your NAS. Or when you set up port forwarding
to a host on your home network, **etherwake-nfqueue** can wake up your host
when you try to access it over the Internet.

A **package feed for OpenWrt** based routers and its documentation can be found
on its
[GitHub site](https://github.com/mister-benjamin/etherwake-nfqueue-openwrt).


## Building

### Dependencies

**etherwake-nfqueue** depends on the userspace library
[libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/)
which will communicate with the kernel *nfnetlink_queue* subsystem.

On Debian based systems, the development package can be installed with
```
apt install libnetfilter-queue-dev
```

### Compiling

The distribution contains a **cmake** file. You can compile with
```
mkdir build
cd build/
cmake ..
make
```
and optionally install with
```
sudo make install
```


## Running

**etherwake-nfqueue** has all the command line options of *etherwake*.
It adds the *-q <nfqueue_num>* option. Without that option,
**etherwake-nfqueue** behaves just like **etherwake** and immediately sends
out a magic packet when started. When using the *-q <nfqueue_num>* option,
**etherwake-nfqueue** waits for packet metadata to be received from the
*nfnetlink_queue* identified by the *-q* option's argument *nfqueue_num*.
Values between 0 and 65535 are accepted.

The idea is that you set up filtering rules with *iptables* with the *NFQUEUE*
target, which will tell the kernel to add a matched packet to the
corresponding queue.

As an example, if you would want to wake up **Host A** with MAC address
**00:25:90:00:d5:fd**, which is physically connected to your router's
interface **enp3s0**, start **etherwake-nfqueue** on your router:

```
etherwake-nfqueue -i enp3s0 -q 0 00:25:90:00:d5:fd
```

Notice that we used queue number 0 here.

You could now, for instance, wake **Host A** with IP address 192.168.0.10 when
**Host B** sends a HTTP GET request to port 80 or 443 on **Host A**. When this
request enters the router, it can trigger **etherwake-nfqueue**, if we
previously set up a firewall rule similar to this one:

```
iptables --insert FORWARD\
         --protocol tcp\
         --destination 192.168.0.10 --destination-port 80:443\
         --match conntrack --ctstate NEW\
         --match limit --limit 3/hour --limit-burst 1\
         --jump NFQUEUE --queue-num 0 --queue-bypass
```

The rule basically states, that whenever a TCP packet is forwarded to
192.168.0.10 with destination port 80 or 443, it should be added to NFQUEUE
number 0. *conntrack* and *limit* are used to limit matches to new connections
and only consider roughly one packet per 20 minutes. These options could be
left out for testing or tweaked to your needs. The *--queue-bypass* option
helps in the situation, when **etherwake-nfqueue** isn't running. Packets will
then be handled as if the rule wasn't present.


## Important Network Prerequisites

In order to let the *netfilter* framework of the kernel see the packets,
they need to pass through the router. This is usually not the case when
hosts are on the same subnet and don't require network layer routing.
The data will only pass through the router's switch on the link layer.

As a consequence, we can only use packets as a trigger which need to be
routed or bridged by the router. Packets being forwarded between WAN
and LAN are of that type. For other SOHO use cases, partitioning your
network by means of subnets or VLANs might be necessary. The latter
is often used to set up a DMZ.

Using two LANs or VLANs with the same network address and bridging them again
is a trick to setup a transparent (or bridging) firewall on the same subnet.
This way, packets can be seen by *netfilter* on the router even if the
packets are not routed. Unfortunately this doesn't help when the host
which we want to wake up is offline, as the ARP requests for the destination
IP address are not answered and thus the client trying to reach out to its
destination will not send any *network layer* packets. We could use *arptables*
instead to wake the host when someone requests its MAC address, but this
would probably happen to often and no fine-grained control would be possible.

As a workaround, it might be possible to configure a static ARP entry on your
router (untested), e.g. with:
```
arp -i enp3s0 -s 192.168.0.10 00:25:90:00:d5:fd
```
or
```
ip neigh add 192.168.0.10 lladdr 00:25:90:00:d5:fd nud permanent dev enp3s0
```

To make your firewall rules work with bridging, you need the 
[br_netfilter](https://ebtables.netfilter.org/documentation/bridge-nf.html)
kernel module and set the kernel parameter `net.bridge.bridge-nf-call-iptables`
to 1, e.g.:
```
sysctl net.bridge.bridge-nf-call-iptables=1
```


## Troubleshooting

### Debug mode

**etherwake-nfqueue** doesn't log anything by default. You can provide the
*-v* and *-D* options to turn on verbose and debug mode, e.g.:
```
etherwake-nfqueue -v -D -i enp0s3 -q 0 00:25:90:00:d5:fd
```

### Inspect netfilter

To inspect the working of your firewall rules, you can print statistics
of the chains you used, e.g.:
```
iptables --verbose --list FORWARD
```

If you happen to have the *procps* package installed, you can watch them:
```
watch iptables --verbose --list FORWARD
```

To see, if your queues are in place, use:
```
cat /proc/net/netfilter/nfnetlink_queue
```


## Potential improvements

* Hold packets back until the target host is reachable, this way we could
  potentially avoid the need of a client side retry after the first
  connection attempt
* Alternatively, when holding back packets is not desired and the connection to
  the host should have the least possible jitter at all times, verdicts
  should be issued right away and sending the magic packets should happen in a
  different thread. In this case, it might be better to only look at the packet
  counters and don't send packet metadata to userspace.
* **etherwake-nfqueue** uses deprecated parts of the *libnetfilter_queue* API,
  its implementation should be updated to use the library like in this
  [example](http://git.netfilter.org/libnetfilter_queue/tree/examples/nf-queue.c).


## Use case example 1

### Wake-on-Port-Forwarding

After having configured your router to do port forwarding for your port
from WAN to a local machine on your home network, you could add a rule
like this:

```
iptables --insert FORWARD\
         --protocol tcp --in-interface=<wan-interface> --out-interface=<lan-interface>\
         --destination <destination-ip-addr> --destination-port <destination-port>\
         --match conntrack --ctstate NEW\
         --match limit --limit 3/hour --limit-burst 1\
         --jump NFQUEUE --queue-num 0 --queue-bypass
```

It might be undesirable, that script kiddies wake up or prevent your host from
going to sleep with their annoying SSH brute force attacks or similar. To shut
this off, you can either set up a VPN or configure the port forwarding to only
match incoming traffic from a specific IP or range. 

When you have a server on the internet at your disposal, you can use an
SSH tunnel and limit the port forwarding rule to your server's address.

#### Example for using SSH over SSH tunnel (via intermediate server):

All the following commands are entered locally, on your workstation or laptop.
*\<your-home-router\>* refers to your router's public IP or dynamic DNS hostname.

```
sudo ssh -N -L 22:<your-home-router>:22 root@<your-internet-server>
```
Then in a different user session, you can SSH into the host as if it were
the local machine:
```
ssh root@localhost
```

If you already have an SSH daemon listening on port 22 locally,
use another local port:

```
ssh -N -L 2222:<your-home-router>:22 root@<your-internet-server>
```

And use the same port in your SSH command:
```
ssh root@localhost -p 2222
```

#### Example for using HTTPS over chained SSH tunnel (via intermediate server):

When you want to access any service on your home network for which you didn't
set up port forwarding, you can chain SSH tunnels. So traffic travels from
your local machine to your intermediate server, then to your host which is
reachable by SSH via your router's port forwarding, and finally to the desired
service, e.g. the Web Interface of your printer.

```
sudo ssh -N -L 22:<your-home-router>:22 root@<your-internet-server>
```
And in a separate user session (*\<your-printer\>* refers to the local IP
address or hostname of your printer):
```
sudo ssh -N -L 443:<your-printer>:443 root@localhost
```
You should now be able to use your browser and access your printer's web server
at https://localhost.

And again, if port 22 and/or 443 are already used locally:

```
ssh -N -L 2222:<your-home-router>:22 root@<your-internet-server>
```
```
ssh -N -L 4443:<your-printer>:443 -p 2222 root@localhost
```

Use https://localhost:4443 in your browser, then.

It might be convenient to set those tunnels up in a GUI SSH client.


## Use case example 2

### Dreambox records to NAS network share

Add a rule to match when your Dreambox tries to access a CIFS (or NFS) share
on your NAS, similar to this one:

```
iptables --insert FORWARD\
         --protocol tcp --in-interface=<dreambox-iface> --out-interface=<nas-iface>\
         --source <dreambox-ip-addr>
         --destination <nas-ip-addr> --destination-port 445:2049\
         --match conntrack --ctstate NEW\
         --match limit --limit 3/hour --limit-burst 1\
         --jump NFQUEUE --queue-num 0 --queue-bypass
```

Setting up your network mount on your Dreambox can be done in various ways.
For me, just adding an entry to `/etc/auto.network` to use *autofs* worked
quite well for me:

```
nas -fstype=cifs,rw,rsize=8192,wsize=8192 ://192.168.0.10/shared
```
After that, my shared folder was available at */media/net/nas*.

After configuring the recording paths, I noticed that the Dreambox was trying
to access the network share during boot for some reason. As I only want
the Dreambox to wake the NAS for *Timer* recordings, I edited the
*/etc/engima2/settings* file manually so that the path to my NAS only appears
in one place:

`
config.usage.timer_path=/media/net/nas/tv-recording/
`

Notice that before editing the file by hand, you need to stop *enigma2* with
`systemctl stop enigma2` and when you're done start it again with
`systemctl start enigma2`.
