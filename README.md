# pinginrust

4/15/20

Will likely need to use a library to abstract raw sockets. Also don't think I'll be able to test this on a Mac, probably need to use a linux environment. smoltcp looks like a good rust library

Reference implementation didn't work on mac. Set up on digitialocean and was successful. However, this implementation doesn't run forever as ping is supposed to and instead stops after 4 packets. Also doesn't support hostname translation. 



