use std::env;
use smoltcp::wire::{Ipv4Address};
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};

fn main() {
    let args: Vec<String> = env::args().collect();
   
    let addr = args[1].to_string();

    let ip = IPv4Validator {
        port: ValidatorOption::NotAllow,
        local: ValidatorOption::NotAllow,
        ipv6: ValidatorOption::Allow
    };

    let addr2 = ip.parse_string(addr).unwrap();
}



