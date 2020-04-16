use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{Domain, DomainValidator};
use dns_lookup::lookup_host;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::transport_channel;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::icmp::{Icmp, IcmpType, IcmpCode};

extern crate pnet_datalink;

fn dns(domain : Domain) -> IpAddr {
    match lookup_host(domain.get_full_domain()) {
        Ok(ips) => {
            println!("{:?}", ips);
            ips[0]
        },
        Err(_) => panic!("DNS lookup did not resolve")
     }

}

fn get_ip_from_raw_addr(raw_addr : &String) -> IpAddr {

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
        Ok(ipv4_addr) => {
            assert_eq!(raw_addr, ipv4_addr.get_full_ipv4());
            let ip_addr = std::net::IpAddr::V4(*ipv4_addr.get_ipv4_address());
            ip_addr
        }
        Err(_) => match domain.parse_string(raw_addr.clone()) {
            Ok(domain) => {
                //assert_eq!(raw_addr, domain.get_full_domain());
                dns(domain)

            }
            Err(_) => panic!("Not valid ip or hostname")
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
   
    let raw_addr = args[1].to_string().clone();

    let ip_addr = get_ip_from_raw_addr(&raw_addr);


    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut sender, mut reciever) = match transport_channel(4096, Layer3(IpNextHeaderProtocols::Icmp)) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };
    let mut vec = Vec::new();
    vec.push(1);

    let packet = Icmp {
        icmp_type : IcmpType(8),
        icmp_code : IcmpCode(0),
        checksum : 0,
        payload : vec
    };



}



