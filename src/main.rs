use std::env;
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{Domain, DomainValidator};
use dns_lookup::lookup_host;
use pnet::packet::{MutablePacket, Packet};
extern crate pnet_datalink;

fn dns(domain : Domain) {
    match lookup_host(domain.get_full_domain()) {
        Ok(ips) => println!("{:?}", ips),
        Err(_) => println!("DNS lookup did not resolve")
     }
}


fn main() {
    let args: Vec<String> = env::args().collect();
   
    let raw_addr = args[1].to_string().clone();

    let ipv4 = IPv4Validator {
        port: ValidatorOption::NotAllow,
        local: ValidatorOption::NotAllow,
        ipv6: ValidatorOption::Allow
    };
    let domain = DomainValidator {
        port: ValidatorOption::NotAllow,
        localhost: ValidatorOption::NotAllow
    };

    for interface in pnet_datalink::interfaces() {
        println!("{}", interface);
    }

    match ipv4.parse_string(raw_addr.clone()) {
        Ok(ipv4_addr) => assert_eq!(raw_addr, ipv4_addr.get_full_ipv4()),
        Err(_) => match domain.parse_string(raw_addr.clone()) {
            Ok(domain) => {
                //assert_eq!(raw_addr, domain.get_full_domain());
                dns(domain)
            }
            Err(_) => println!("Not valid ip or hostname")
        }
    }
}



