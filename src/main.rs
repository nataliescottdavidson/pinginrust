use dns_lookup::lookup_host;
use pnet::datalink::interfaces;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{checksum, IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::icmp::{echo_reply, echo_request};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportSender;
use pnet::util::MacAddr;
use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;
use std::{thread, time};
use validators::domain::{Domain, DomainValidator};
use validators::ipv4::IPv4Validator;
use validators::ValidatorOption;
use bincode::{serialize, deserialize};
use pnet_macros_support::packet::FromPacket;

fn dns(domain: Domain) -> IpAddr {
    match lookup_host(domain.get_full_domain()) {
        Ok(ips) => {
            ips[0]
        }
        Err(_) => panic!("DNS lookup did not resolve"),
    }
}

fn get_ip_from_raw_addr(raw_addr: &String) -> IpAddr {
    let ipv4 = IPv4Validator {
        port: ValidatorOption::NotAllow,
        local: ValidatorOption::NotAllow,
        ipv6: ValidatorOption::Allow,
    };
    let domain = DomainValidator {
        port: ValidatorOption::NotAllow,
        localhost: ValidatorOption::NotAllow,
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
            Err(_) => panic!("Not valid ip or hostname"),
        },
    }
}

fn send_echo_request(mut sender: TransportSender, ip_addr: IpAddr) {
    let mut icmp_seq = 0;
    loop {
        let mut buffer = [0u8; 42];
        let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
        let target: Option<time::SystemTime>  = Some(time::SystemTime::now());
        let encoded: Vec<u8> = serialize(&target).unwrap();
        let decoded: Option<time::SystemTime> = deserialize(&encoded[..]).unwrap();
        assert_eq!(target, decoded);

        packet.set_sequence_number(icmp_seq);
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(IcmpCode::new(0));
        let echo_checksum = checksum(&IcmpPacket::new(packet.packet()).unwrap());
        packet.set_checksum(echo_checksum);
        //packet.set_payload(&encoded);
        match sender.send_to(packet, ip_addr) {
            Ok(_size) => (),
            Err(e) => println!("{:?}", e),
        }
        unsafe {
            seq_time_map.push(time::SystemTime::now());
        }
        icmp_seq = icmp_seq + 1;
        thread::sleep(time::Duration::from_secs(1));
    }
}

fn calculate_rtt(icmp_seq : u16) -> time::Duration {
    let index = icmp_seq as usize;
    unsafe {
        let request_time = seq_time_map[index];
        match time::SystemTime::now().duration_since(request_time) {
            Ok(n) => n,
            Err(_) => panic!("Failed to determine duration")
        }
    }
}

fn handle_icmp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    ttl: u8,
    packet_size: usize
) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                let rtt = calculate_rtt(echo_reply_packet.get_sequence_number());
                println!(
                    "{} bytes from {}: icmp_seq={:?} ttl={} time={:?}.{} ms",
                    packet_size,
                    source,
                    echo_reply_packet.get_sequence_number(),
                    ttl,
                    rtt.as_millis(),
                    rtt.as_nanos(),
                );
            },
            _ => (),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8], ttl: u8, packet_size: usize) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        match icmpv6_packet.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                let rtt = calculate_rtt(echo_reply_packet.get_sequence_number());
                println!(
                    "{} bytes from {}: icmp_seq={:?} ttl={} time={:?}.{} ms",
                    packet_size,
                    source,
                    echo_reply_packet.get_sequence_number(),
                    ttl,
                    rtt.as_millis(),
                    rtt.as_nanos(),
                );
            },
            _ => (),
        }
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    ttl: u8,
    packet_size: usize,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet, ttl, packet_size)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet, ttl, packet_size)
        }
        _ => (),
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.get_ttl(),
            Ipv4Packet::packet_size(&header.from_packet()),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.get_hop_limit(),
            Ipv6Packet::packet_size(&header.from_packet()),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        _ => (),
    }
}

static mut seq_time_map : Vec<time::SystemTime> = Vec::new();

fn main() {
    let raw_addr = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: ping <VALID IP OR HOSTNAME> [<NETWORK INTERFACE>]").unwrap();
            process::exit(1);
        }
    };

    let ip_addr = get_ip_from_raw_addr(&raw_addr);

    let (sender, _) = match transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Icmp))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}", e),
    };

    let mut interfaces = datalink::interfaces()
        .into_iter()
        .filter(|e| e.is_up() && !e.is_loopback() && e.ips.len() > 0);

    let interface = match env::args().nth(2) {
        Some(n) => {
            let interface_names_match = |iface: &NetworkInterface| iface.name == n;
            interfaces
                .filter(interface_names_match)
                .next()
                .unwrap_or_else(|| panic!("Argument {} does not match any valid interface", n))
        },
        None => {
            interfaces
                .next()
                .unwrap_or_else(|| panic!("No valid network interface"))
        },

    };


    println!("interface {}", interface);
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type: {}"),
        Err(e) => {
            writeln!(io::stderr(), "Default network interface selection failed. Please specify interface.").unwrap();
            process::exit(1);
        }
    };

    thread::spawn(move || send_echo_request(sender, ip_addr.clone()));

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(target_os = "macos")
                    && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("Unable to receive packet: {}", e),
        }
    }
}
