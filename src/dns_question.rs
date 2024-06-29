use crate::{
    byte_packet_buffer::{BytePacketBuffer, BytePacketBufferResult},
    query_type::QueryType,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub query_type: QueryType,
}

impl DnsQuestion {
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<Self> {
        let mut result = Self::new(String::new(), QueryType::UNKNOWN(0));
        result.read(buffer)?;

        Ok(result)
    }

    pub fn new(name: String, query_type: QueryType) -> Self {
        Self { name, query_type }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<()> {
        buffer.read_qname(&mut self.name)?;
        self.query_type = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16(); // class, for now we don't handle it

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> BytePacketBufferResult<()> {
        buffer.write_qname(&self.name)?;

        let typenum: u16 = self.query_type.into();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?; // stands for class;

        Ok(())
    }
}
