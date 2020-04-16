use std::env;
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{Domain, DomainValidator};
use dns_lookup::lookup_host;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::transport_channel;
use pnet_packet::ip::IpNextHeaderProtocols;

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

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    
}



