use crate::errors::BytePacketBufferError;

const MAX_JUMPS: usize = 5;
const BUFFER_SIZE: usize = 512;
const JUMP_BITS: u8 = 0xC0;

pub type BytePacketBufferResult<T> = std::result::Result<T, BytePacketBufferError>;

pub struct BytePacketBuffer {
    pub buff: [u8; BUFFER_SIZE],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buff: [0; 512],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn read(&mut self) -> BytePacketBufferResult<u8> {
        let res = self.get(self.pos)?;
        self.step(1);

        Ok(res)
    }

    pub fn get(&self, pos: usize) -> BytePacketBufferResult<u8> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::PosOutOfRange);
        }

        Ok(self.buff[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> BytePacketBufferResult<&[u8]> {
        if start + len > 512 {
            return Err(BytePacketBufferError::RangeOutOfTheBuffer);
        }

        Ok(&self.buff[start..start + len as usize])
    }

    pub fn read_u16(&mut self) -> BytePacketBufferResult<u16> {
        // Whe read 8bits and put in allocated 16 bits, then we shift them to the right and add next 8bits
        // self.read -> xxxx xxxx
        // as u16 -> 0000 0000 xxxx xxxx
        // << 8 -> xxxx xxxx 0000 0000
        // | self.read() -> xxxx xxxx yyyy yyyy
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> BytePacketBufferResult<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> BytePacketBufferResult<()> {
        let mut pos = self.pos;
        let mut jumped = false;
        let mut jumps_performed = 0;

        let mut delim = "";

        loop {
            if jumps_performed > MAX_JUMPS {
                return Err(BytePacketBufferError::MaxJumpsExceeded { limit: MAX_JUMPS });
            }

            let len = self.get(pos)?;
            let should_jump = (len & JUMP_BITS) == JUMP_BITS;

            if should_jump {
                if !jumped {
                    // we skip next two u8, cause first one indicades that it is jump bits, and second one is the offset of the jump
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jumps_performed += 1;

                continue;
            }

            pos += 1;

            let is_it_the_end = len == 0;

            if is_it_the_end {
                break;
            }

            outstr.push_str(delim);
            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    pub fn write_u8(&mut self, value: u8) -> BytePacketBufferResult<()> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::PosOutOfRange);
        }

        self.buff[self.pos] = value;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, value: u16) -> BytePacketBufferResult<()> {
        self.write_u8((value >> 8) as u8)?;
        self.write_u8(value as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, value: u32) -> BytePacketBufferResult<()> {
        self.write_u16((value >> 16) as u16)?;
        self.write_u16(value as u16)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> BytePacketBufferResult<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 63 {
                return Err(BytePacketBufferError::LabelLengthTooBig {
                    length: len,
                    label: label.into(),
                    input: qname.into(),
                });
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?; //equvialent for the C \0 char

        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) {
        self.buff[pos] = val;
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val >> 8) as u8);
        self.set(pos + 1, (val & 0xFF) as u8);
    }
}
