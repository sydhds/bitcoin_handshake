use std::error::Error;

use bytes::BufMut;

pub trait Serializer<T> {
    fn serialize<B: BufMut>(&self, value: &T, buffer: B) -> Result<(), Box<dyn Error>>;

    // Size hint to alloc buffer in advance
    // (lower bound, upper bound)
    // fn size_hint(value: &T) -> (usize, Option<usize>);
}

pub trait Deserializer<T> {
    fn deserialize<'a>(&self, buffer: &'a [u8]) -> Result<(&'a [u8], T), Box<dyn Error + 'a>>;
}

pub type NomError<'a> = nom::error::Error<&'a [u8]>;
