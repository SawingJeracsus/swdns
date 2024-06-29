use rand::{rngs::ThreadRng, Rng};
use std::net::{Ipv4Addr, UdpSocket};

use crate::{
    byte_packet_buffer::BytePacketBuffer,
    dns_packet::DnsPacket,
    dns_question::DnsQuestion,
    errors::{DnsServerError, DnsServerResult},
    query_type::QueryType,
    result_code::ResultCode,
};

pub struct DnsServer {
    root: Ipv4Addr,
    port: u16,
    rng: ThreadRng,
}

impl DnsServer {
    pub fn recursive_lookup(
        &mut self,
        qname: &str,
        query_type: QueryType,
    ) -> DnsServerResult<DnsPacket> {
        let mut name_server = self.root.clone();

        loop {
            let ns_copy = name_server;
            println!(
                "attempting lookup of {:?} {} with ns {}",
                query_type, qname, name_server
            );

            let response = self.lookup((ns_copy, 53), qname, query_type)?;

            println!("response - {:?}", response);

            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                return Ok(response);
            }
            if response.header.rescode == ResultCode::NXDOMAIN {
                return Ok(response);
            }

            if let Some(new_ns) = response.get_resolved_ns(qname) {
                name_server = new_ns;

                continue;
            }

            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response),
            };

            let recursive_response = self.recursive_lookup(&new_ns_name, QueryType::A)?;

            if let Some(new_ns) = recursive_response.get_first_a_record() {
                name_server = new_ns;
            } else {
                return Ok(response);
            }
        }
    }
    fn lookup(
        &mut self,
        server: (Ipv4Addr, u16),
        qname: &str,
        qtype: QueryType,
    ) -> DnsServerResult<DnsPacket> {
        let socket = UdpSocket::bind(("0.0.0.0", self.port))?;

        let mut packet = DnsPacket::default();
        let id: u16 = self.rng.gen();

        packet.header.id = id;
        packet.header.questions = 1;
        packet.header.recursion_desired = true;
        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        socket.send_to(&req_buffer.buff[0..req_buffer.pos], server)?;

        let mut res_buffer = BytePacketBuffer::new();
        socket.recv_from(&mut res_buffer.buff)?;

        let result_packet = DnsPacket::from_buffer(&mut res_buffer)?;

        if result_packet.header.id != id {
            return Err(DnsServerError::PacketIdCorrupted {
                sent_id: id,
                received_id: result_packet.header.id,
            });
        }

        Ok(result_packet)
    }

    pub fn handle_query(&mut self, socket: &UdpSocket) -> DnsServerResult<()> {
        let mut req_buffer = BytePacketBuffer::new();

        let (_, src) = socket.recv_from(&mut req_buffer.buff)?;

        let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

        let mut packet = DnsPacket::default();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if let Some(question) = request.questions.pop() {
            println!("Received query: {:?}", question);

            if let Ok(result) = self.recursive_lookup(&question.name, question.query_type) {
                packet.questions.push(question);
                packet.header.rescode = result.header.rescode;

                for rec in result.answers {
                    println!("Answer: {:?}", rec);
                    packet.answers.push(rec);
                }
                for rec in result.authorities {
                    println!("Authority: {:?}", rec);
                    packet.authorities.push(rec);
                }
                for rec in result.resources {
                    println!("Resource: {:?}", rec);
                    packet.resources.push(rec);
                }
            } else {
                packet.header.rescode = ResultCode::SERVFAIL;
            }
        } else {
            packet.header.rescode = ResultCode::FORMERR;
        }

        let mut res_buffer = BytePacketBuffer::new();
        packet.write(&mut res_buffer)?;

        socket.send_to(&res_buffer.buff[0..res_buffer.pos], src)?;

        Ok(())
    }
}

impl Default for DnsServer {
    fn default() -> Self {
        let rng = rand::thread_rng();

        Self {
            // For now we're always starting with *a.root-servers.net*.
            root: "198.41.0.4".parse::<Ipv4Addr>().unwrap(),
            port: 43210,
            rng,
        }
    }
}
