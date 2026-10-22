# Reproduction Notes

These are the steps used to recreate the baseline Wireshark exercise.

## Start the capture

Open Wireshark, select the active network adapter and start capturing.

## DNS

~~~cmd
nslookup github.com
~~~

Filter:

~~~text
dns
~~~

## ICMP

~~~cmd
ping 1.1.1.1
~~~

Filter:

~~~text
icmp
~~~

## HTTP

Open:

~~~text
http://neverssl.com
~~~

Filter:

~~~text
http
~~~

## HTTPS / TLS

Open:

~~~text
https://github.com
~~~

Filter:

~~~text
tls
~~~

## TCP sessions

~~~text
tcp
~~~

~~~text
tcp.flags.syn == 1
~~~

~~~text
tcp.flags.syn == 1 && tcp.flags.ack == 0
~~~

## Statistics

Review:

- Statistics -> Protocol Hierarchy
- Statistics -> Conversations
- Statistics -> Endpoints
- Statistics -> I/O Graphs

Only capture traffic on networks and systems you are authorised to analyse.
