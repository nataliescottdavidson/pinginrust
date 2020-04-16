use std::env;
use std::net::IpAddr;
use validators::ValidatorOption;
use validators::ipv4::{IPv4Validator};
use validators::domain::{Domain, DomainValidator};
use dns_lookup::lookup_host;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::transport_channel;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes, checksum};

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

    let (mut sender, _) = match transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    let mut buffer = [0u8; 42];
    let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
    packet.set_sequence_number(0);
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_icmp_code(IcmpCode::new(0));
    let echo_checksum = checksum(&IcmpPacket::new(packet.packet()).unwrap());
    packet.set_checksum(echo_checksum);

    match sender.send_to(packet, ip_addr) {
        Ok(_size) => println!("Sent successfully"),
        Err(e) => println!("{:?}", e)
    }

}



