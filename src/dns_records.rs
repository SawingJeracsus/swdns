use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    byte_packet_buffer::{BytePacketBuffer, BytePacketBufferResult},
    query_type::QueryType,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<Self> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let query_type_u16 = buffer.read_u16()?;
        let query_type: QueryType = query_type_u16.into();
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match query_type {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    ((raw_addr1 >> 0) & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    ((raw_addr2 >> 0) & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    ((raw_addr3 >> 0) & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    ((raw_addr4 >> 0) & 0xFFFF) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize);

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    query_type: query_type_u16,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?; //data length

                let octets = addr.octets();
                for i in 0..4 {
                    buffer.write_u8(octets[i])?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record {:?}", self);
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.into())?;
                buffer.write_u16(1)?; // CLASS
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?; // RDLENGTH

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2); //size of the host string
                buffer.set_u16(pos, size as u16);
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?; //reserve place;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
