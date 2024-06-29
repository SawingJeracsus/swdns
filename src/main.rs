use std::net::UdpSocket;

use dns_server::DnsServer;
mod byte_packet_buffer;
mod dns_header;
mod dns_packet;
mod dns_question;
mod dns_records;
mod dns_server;
mod errors;
mod query_type;
mod result_code;

fn main() {
    let mut dns_server = DnsServer::default();
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    loop {
        match dns_server.handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
