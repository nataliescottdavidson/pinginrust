use std::env;
use smoltcp::wire::{Ipv4Address};
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{DomainValidator};

fn main() {
    let args: Vec<String> = env::args().collect();
   
    let addr = args[1].to_string();

    let ip = IPv4Validator {
        port: ValidatorOption::NotAllow,
        local: ValidatorOption::NotAllow,
        ipv6: ValidatorOption::Allow
    };
    let domain = DomainValidator {
        port: ValidatorOption::NotAllow,
        localhost: ValidatorOption::NotAllow
    }
    let addr_ = ip.parse_string(addr);
    if addr_.is_ok() {
        assert_eq!("1.1.1.1", addr_.unwrap());
    }
    else {
        let addr__ = domain.parse_string(addr);
        if addr__.is_ok() {
            assert_eq!( "google.com", addr.unwrap()

        }
    }
}



