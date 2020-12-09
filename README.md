# Python-Packet-Sniffer

## Overview

Packet Sniffer created in Python 3. 
It allows you to monitor traffic running through local network. Allows the user to be able to view Source of the packets, Target host and the type of protocol used e.g. UDP,TCP, ICMP. More on the details subsection

## Requirement
  - Python 3.6.9 (untested with others, be my guest :) )
  - Privileged/Administrative Rights
  - Linux or Windows Operating System

## Usage

On linux:
```bash
sudo python3 Packet-Sniffer.py
```

On Windows:
 To be defined

## Details

Protocols recognized: IPv4, IPv6, ARP <br>
Within IPv4: TCP, UDP, ICMP. <br>
Within IPv6: TCP, UDP, ICMPv6, Hop-by-Hop Options, Destination options, Routing, Fragment, Authentication, Encapsuling Header ( This one is just a dummy recognition as of now :) )

The original package has been broken down into a more structured approach, separating responsibilities from IPv4/IPv6 packets into their own files, as well as shared protocols into a file to be used by both. 
The Packet-Sniffer.py could use a few more cleanups since we have some outputs there still.

The output formatting is a bit on the nose and needs refactoring, since it's not optimal the way it's done now.

IPv6 next header order is based on RFC8200 [1]. Other RFCs are referenced throughout the code.


* The Python 3 sockets library, for capturing the packets, is using AF_PACKET for capturing both internet protocols. Beware of that, since there are AF_INET/AF_INET6 for specific protocols (IPv4 only, IPv6 only) and your use case might not fit. More on: [2]

[1] https://tools.ietf.org/html/rfc8200 

[2] https://docs.python.org/3/library/socket.html
