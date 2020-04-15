# pinginrust

4/15/20

Will likely need to use a library to abstract raw sockets. Also don't think I'll be able to test this on a Mac, probably need to use a linux environment. smoltcp looks like a good rust library

Reference implementation didn't work on mac. Set up on digitialocean and was successful. However, this implementation doesn't run forever as ping is supposed to. See:

 Running `target/debug/examples/ping tap0 1.1.1.1`
40 bytes from 1.1.1.1: icmp_seq=0, time=2ms
40 bytes from 1.1.1.1: icmp_seq=1, time=1ms
40 bytes from 1.1.1.1: icmp_seq=2, time=1ms
40 bytes from 1.1.1.1: icmp_seq=3, time=2ms
--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss
root@pinginrustdev:~/smoltcp# ping 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=59 time=1.33 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=59 time=1.27 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=59 time=1.25 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=59 time=1.26 ms
64 bytes from 1.1.1.1: icmp_seq=5 ttl=59 time=1.32 ms
64 bytes from 1.1.1.1: icmp_seq=6 ttl=59 time=1.32 ms
64 bytes from 1.1.1.1: icmp_seq=7 ttl=59 time=1.32 ms
^C
--- 1.1.1.1 ping statistics ---
21 packets transmitted, 21 received, 0% packet loss, time 20031ms
rtt min/avg/max/mdev = 1.212/1.290/1.394/0.063 ms
