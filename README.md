# pinginrust

4/15/20

Will likely need to use a library to abstract raw sockets. Also don't think I'll be able to test this on a Mac, probably need to use a linux environment. smoltcp looks like a good rust library

smoltcp reference implementation didn't work on mac. Set up on digitialocean and was successful. However, it doesn't run forever as ping is supposed to and instead stops after 4 packets. Also doesn't support hostname translation. 

Completed pattern match logic using Haskell style case statement. Feeling pretty good for a Rust newbie!


4/16/20

Managed to send an echo request packet which showed up on wireshark!! yay!! might need to go down a level of abstraction to get the replies though

I have an MVP! An echo reply comes in. Need to figure out how to run both the echo request and handle echo reply on a loop. After that, I plan to change the transport layer echo request sender with the datalink sender. I'm not yet populating the icmp requests with a sequence number, so need to add that too. I'm leaning pretty heavily on pnet datalink layer API and packet structs, but I think this is a manageable level of abstraction. 

