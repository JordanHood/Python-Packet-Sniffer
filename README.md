# Python-Packet-Sniffer

## Prerequisites

* Minimun of Python 3.x installed
* https://github.com/mike01/pypacker installed
* https://github.com/CoreSecurity/pcapy installed

## Usage 

* `sudo python3 sniffer.py` is the basic usage where you will get prompted for which network interface you which to sniff on, and the script will capture a 30 second

```
usage: sniffer.py [-h] [-t TIME] [-i INTERFACE]

optional arguments:
  -h, --help            show this help message and exit
  -t TIME, --time TIME  The length of time to capture packets for
  -i INTERFACE, --interface INTERFACE
                        The network interface to capture traffic on
```
