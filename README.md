# pinginrust

Usage: `ping <VALID IP OR HOSTNAME> [<NETWORK INTERFACE>]`
  
Requires elevated privileges as it sniffs packets. 


4/15/20

Will likely need to use a library to abstract raw sockets. Also don't think I'll be able to test this on a Mac, probably need to use a linux environment. smoltcp looks like a good rust library

smoltcp reference implementation doesn't run forever as ping is supposed to and instead stops after 4 packets. Also doesn't support hostname translation. 

Completed pattern match logic using Haskell style case statement. Feeling pretty good for a Rust newbie!


4/16/20

Managed to send an echo request packet which showed up on wireshark!! yay!! might need to go down a level of abstraction to get the replies though

I have an MVP! An echo reply comes in. Need to figure out how to run both the echo request and handle echo reply on a loop. After that, I plan to change the transport layer echo request sender with the datalink sender. I'm not yet populating the icmp requests with a sequence number, so need to add that too. I'm leaning pretty heavily on pnet datalink layer API and packet structs, but I think this is a manageable level of abstraction. 

4/17/20

I'm done! That was fun. I'd like to clean it up a bit. The biggest challenges were with the network interface. It requires elevated privileges to sniff packets. Picking a default interface chooses something that is up and not loopback, but the "good" interface returned fails to create a channel with Error: Device not configured (os error 6). This was happening intermittently, and I found [an issue about it](https://github.com/imsnif/bandwhich/issues/31) related to a different networking library, so I think the bug is pretty low level and a workaround makes sense. That's why interface is an optional parameter. 

I chose to send echo request packets as regular IPv4 packets at the transport level. I could make the publisher use the Ethernet channel, but I'm not sure what the benefits of that would be. Having to deal with consuming packets at Ethernet level is kind of a pain. 

Resources consulted:<br/>
[The Rust Language](https://doc.rust-lang.org/book/index.html)<br/>
[Ping Explanation Whitepaper](http://images.globalknowledge.com/wwwimages/whitepaperpdf/WP_Mays_Ping.pdf)<br/>
[Ping in C Geeksforgeeks](https://www.geeksforgeeks.org/ping-in-c/)<br/>
[libpnet Examples](https://github.com/libpnet/libpnet/tree/master/examples)<br/>




