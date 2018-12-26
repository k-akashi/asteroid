# Asteroid: Virtual Network Wireless Emulator

## Package install

```bash
apt-get install libnl-3-200 libnl-3-dev libnl-genl-3-200 libnl-genl-3-dev libnl-route-3-200 libnl-route-3-dev libjson-c-dev libjson-c2
```

## Compile

```bash
cd adteroid/
make
```

## mac80211\_hwsim

Mac80211\_hwsim is the Wi-Fi virtual simulator installed as standard on Linux.

Asteroid uses Wi-Fi communiation using mac80211\_hwsim.

```bash
# Load pseudo interface module
modprobe mac80211_hwsim radios=<Number of interfaces>
```
If radios is not specified, two radios are created.

## Configration physical interface

```bash
ip addr add <IP_ADDRESS/PREFIX> brd <BROADCAST_ADDRESS> dev <PHYSICAL_INTERFACE>
ip link set up dev <PHYSICAL_INTERFACE>
```

## Configuration WLAN interface

Asteroid supports all modes such as 802.11s, adhoc mode and infrastructure mode.

  * 11s mode

```bash
iw dev wlan0 interface add mesh0 type mesh
ip link set address <MAC_ADDRESS> dev mesh0
ip link set up dev mesh0
iw dev wlan0 mesh join <MESH_ID>
ip addr add <IP_ADDRESS/PREFIX> brd <BROADCAST_ADDRESS> dev mesh0
```

  * adhoc mode

```bash
ip link set address <MAC_ADDRESS> dev wlan0
iwconfig wlan0 mode ad-hoc
iwconfig wlan0 essid <ESSID>
ip addr add <IP_ADDRESS/PREFIX> brd <BROADCAST_ADDRESS> dev wlan0
```

  * infrastructure mode

```bash
ip link set address <MAC_ADDRESS> dev wlan0
```

* note

In order to communicate between the radio interfaces of each node, it is necessary to change the MAC Address to a unique one.

## Run Asteroid

```bash
./bin/asteroid -a -w <WIRELESS_INERFACE> -p <PHYSICAL_INTERFACE> [-P DESTINATION_ADDRESS] [-i vni] [-d] [-v [-x]] [-t -r RATE]
-P: Destination Address of physical interface
-d: Daemon mode
-v: verbose mode, -x option is hex dump
```

## Option

### Frame capture(radio tap)

  * from PHY module

```bash
ip link set up dev hwsim0
tcpdumo -eni hwsim0
```

  * from wlan interface

```bash
iw phy phyX interface add mon0 type monitor
ip link set up dev mon0
tcpdump -eni mon0
```

