use arrayref::array_mut_ref;
use byteorder::{BigEndian, ByteOrder};
use std::fmt;

#[derive(PartialEq, Eq)]
pub struct Address {
    instance: u64,
    layer: u32,
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ instance: 0x{:x}, layer: {} }}",
            self.instance, self.layer
        )
    }
}

impl Address {
    pub fn new(layer: u32, instance: u64) -> Self {
        Self { layer, instance }
    }

    pub fn get_instance(&self) -> usize {
        self.instance as usize
    }

    pub fn incr_instance(&mut self) {
        self.instance += 1;
    }

    pub fn normalize_index(&self, mask: u64) -> (Address, usize) {
        let index = self.instance & mask;
        let address = Address {
            layer: self.layer,
            instance: self.instance - index,
        };
        (address, index as usize)
    }

    pub fn next_layer(&mut self) {
        self.layer -= 1;
    }

    pub fn shift(&mut self, height: usize) {
        self.instance >>= height;
    }

    pub fn to_block(&self, counter: u32) -> [u8; 16] {
        let mut block = [0; 16];
        BigEndian::write_u64(array_mut_ref![block, 0, 8], self.instance);
        BigEndian::write_u32(array_mut_ref![block, 8, 4], self.layer);
        BigEndian::write_u32(array_mut_ref![block, 12, 4], counter);
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_block() {
        let address = Address::new(0x01020304, 0x05060708090a0b0c);
        let block = address.to_block(0x0d0e0f00);
        assert_eq!(
            block,
            [5, 6, 7, 8, 9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 0]
        );
    }

    #[test]
    fn test_get_instance() {
        let address = Address::new(0x01020304, 0x05060708090a0b0c);
        let instance = address.get_instance();
        assert_eq!(instance, 0x05060708090a0b0c);
    }

    #[test]
    fn test_incr_instance() {
        let mut address = Address::new(0x01020304, 0x05060708090a0b0c);
        address.incr_instance();
        assert_eq!(
            address,
            Address {
                layer: 0x01020304,
                instance: 0x05060708090a0b0d,
            }
        );
    }

    #[test]
    fn test_next_layer() {
        let mut address = Address::new(0x01020304, 0x05060708090a0b0c);
        address.next_layer();
        assert_eq!(
            address,
            Address {
                layer: 0x01020303,
                instance: 0x05060708090a0b0c,
            }
        );
    }

    #[test]
    fn test_shift() {
        let mut address = Address::new(0x01020304, 0x05060708090a0b0c);
        address.shift(12);
        assert_eq!(
            address,
            Address {
                layer: 0x01020304,
                instance: 0x05060708090a0,
            }
        );
    }

    #[test]
    fn test_normalize_index() {
        let address = Address::new(0x01020304, 0x05060708090a0b0c);
        let (address, index) = address.normalize_index(0xFFF);
        assert_eq!(index, 0xb0c);
        assert_eq!(
            address,
            Address {
                layer: 0x01020304,
                instance: 0x05060708090a0000,
            }
        );
    }
}
