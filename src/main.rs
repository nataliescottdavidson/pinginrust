use std::env;
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{DomainValidator};

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

    match ipv4.parse_string(raw_addr.clone()) {
        Ok(ipv4_addr) => assert_eq!("1.1.1.1", ipv4_addr.get_full_ipv4()),
        Err(_) => match domain.parse_string(raw_addr.clone()) {
            Ok(domain) => assert_eq!("google.com", domain.get_domain()),
            Err(_) => println!("Not valid ip or hostname")
        }
    }
}



