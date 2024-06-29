use std::net::Ipv4Addr;

use crate::{
    byte_packet_buffer::{BytePacketBuffer, BytePacketBufferResult},
    dns_header::DnsHeader,
    dns_question::DnsQuestion,
    dns_records::DnsRecord,
};

#[derive(Debug, Clone, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<Self> {
        let mut result = DnsPacket::default();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            result.questions.push(DnsQuestion::from_buffer(buffer)?);
        }

        for _ in 0..result.header.answers {
            result.answers.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.authoritative_entries {
            result.authorities.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.resource_entries {
            result.resources.push(DnsRecord::read(buffer)?);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<()> {
        self.header.questions = self.questions.len() as u16; // I hope we woun't get more then 65k questions, I'm not event it is possible due a size of dns packet, btw, I wount  put here a validation due it is a pet project :D
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in &self.answers {
            rec.write(buffer)?;
        }

        for rec in &self.authorities {
            rec.write(buffer)?;
        }

        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_first_a_record(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { addr, .. } => Some(*addr),
                _ => None,
            })
            .next()
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
