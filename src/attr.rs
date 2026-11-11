//! Атрибуты netlink (`struct nlattr`).
//!
//! Атрибут состоит из заголовка `nla_len: u16` + `nla_type: u16` и payload.
//! Payload выравнивается по 4 байта. Старшие биты `nla_type` содержат флаги
//! (`NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`), поэтому тип нужно маскировать.

use crate::error::{Error, Result};

/// Размер заголовка атрибута, взят из ABI (`struct nlattr`).
pub const NLA_HDRLEN: usize = std::mem::size_of::<libc::nlattr>();

/// Флаг вложенности в ABI-типе `nla_type` (совпадает с `libc::NLA_F_NESTED`).
pub const NLA_F_NESTED_BIT: u16 = 1 << 15;

/// Маска собственно типа атрибута (совпадает с `libc::NLA_TYPE_MASK`).
const NLA_TYPE_MASK: u16 = u16::MAX >> 2;

/// Выравнивание атрибутов; совпадает с `libc::NLA_ALIGNTO`.
const NLA_ALIGNTO: usize = 4;

/// Выравнивает длину атрибута по `NLA_ALIGNTO`.
#[must_use]
pub const fn nla_align(len: usize) -> usize {
    len.saturating_add(NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

/// Строитель набора атрибутов netlink.
///
/// ```
/// # use uu_linux_kernel_netlink::{AttrWriter, Error};
/// # fn main() -> Result<(), Error> {
/// let mut attrs = AttrWriter::new();
/// attrs.u32(1, 7);
/// attrs.str(2, "wlan0");
/// assert_eq!(attrs.len(), 8 + 12);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct AttrWriter {
    buf: Vec<u8>,
    overflow: bool,
}

impl AttrWriter {
    /// Создаёт пустой набор атрибутов.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            overflow: false,
        }
    }

    /// Возвращает `true`, если атрибутов нет.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Длина набора в байтах вместе с заголовками и выравниванием.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Возвращает `true`, если хотя бы один атрибут не поместился в `u16`.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflow
    }

    /// Сырое представление набора атрибутов.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Завершает построение и возвращает байты атрибутов.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::MessageTooLong`], если какой-то атрибут не
    /// помещается в `u16`-поле `nla_len`.
    pub fn finish(self) -> Result<Vec<u8>> {
        if self.overflow {
            return Err(Error::MessageTooLong);
        }
        Ok(self.buf)
    }

    fn begin(&mut self, attr_type: u16, payload_len: usize) {
        if self.overflow {
            return;
        }
        let Some(nla_len) = NLA_HDRLEN
            .checked_add(payload_len)
            .and_then(|len| u16::try_from(len).ok())
        else {
            self.overflow = true;
            return;
        };
        self.buf.extend_from_slice(&nla_len.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(NLA_HDRLEN) {
            self.buf.push(0);
        }
    }

    /// Добавляет уже собранный набор атрибутов без изменений.
    pub fn extend(&mut self, attrs: &[u8]) {
        self.buf.extend_from_slice(attrs);
    }

    /// Добавляет атрибут с произвольным payload.
    pub fn bytes(&mut self, attr_type: u16, data: &[u8]) {
        self.begin(attr_type, data.len());
        if self.overflow {
            return;
        }
        self.buf.extend_from_slice(data);
        self.pad();
    }

    /// Добавляет атрибут-флаг без payload (`nla_len == 4`).
    pub fn zero(&mut self, attr_type: u16) {
        self.begin(attr_type, 0);
    }

    /// Добавляет строковый атрибут с завершающим нулём, как ожидает ядро.
    pub fn str(&mut self, attr_type: u16, value: &str) {
        self.begin(attr_type, value.len().saturating_add(1));
        if self.overflow {
            return;
        }
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        self.pad();
    }

    /// Добавляет однобайтовое значение.
    pub fn u8(&mut self, attr_type: u16, value: u8) {
        self.bytes(attr_type, &[value]);
    }

    /// Добавляет двухбайтовое значение.
    pub fn u16(&mut self, attr_type: u16, value: u16) {
        self.bytes(attr_type, &value.to_ne_bytes());
    }

    /// Добавляет четырёхбайтовое значение.
    pub fn u32(&mut self, attr_type: u16, value: u32) {
        self.bytes(attr_type, &value.to_ne_bytes());
    }

    /// Добавляет восьмибайтовое значение.
    pub fn u64(&mut self, attr_type: u16, value: u64) {
        self.bytes(attr_type, &value.to_ne_bytes());
    }

    /// Добавляет вложенный набор атрибутов с флагом `NLA_F_NESTED`.
    pub fn nested<F>(&mut self, attr_type: u16, build: F)
    where
        F: FnOnce(&mut Self),
    {
        let mut inner = Self::new();
        build(&mut inner);
        if inner.overflow {
            self.overflow = true;
            return;
        }
        self.begin(attr_type | NLA_F_NESTED_BIT, inner.buf.len());
        if self.overflow {
            return;
        }
        self.buf.extend_from_slice(&inner.buf);
        self.pad();
    }
}

/// Итератор по атрибутам netlink.
///
/// Возвращает пары `(тип, payload)`. Тип уже очищен от флагов.
#[derive(Debug)]
pub struct AttrIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> AttrIter<'a> {
    /// Создаёт итератор по сырому буферу атрибутов.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let header_end = self.pos.checked_add(NLA_HDRLEN)?;
        if header_end > self.buf.len() {
            return None;
        }
        let nla_len = usize::from(u16::from_ne_bytes(
            self.buf[self.pos..self.pos + 2].try_into().ok()?,
        ));
        let nla_type = u16::from_ne_bytes(self.buf[self.pos + 2..self.pos + 4].try_into().ok()?);
        let attr_end = self.pos.checked_add(nla_len)?;
        if nla_len < NLA_HDRLEN || attr_end > self.buf.len() {
            return None;
        }
        let payload = &self.buf[header_end..attr_end];
        self.pos = self.pos.saturating_add(nla_align(nla_len));
        Some((nla_type & NLA_TYPE_MASK, payload))
    }
}

/// Читает `u8` из payload атрибута.
#[must_use]
pub const fn read_u8(data: &[u8]) -> Option<u8> {
    data.first().copied()
}

/// Читает `u16` в порядке байт хоста.
#[must_use]
pub fn read_u16(data: &[u8]) -> Option<u16> {
    data.get(0..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_ne_bytes)
}

/// Читает `u32` в порядке байт хоста.
#[must_use]
pub fn read_u32(data: &[u8]) -> Option<u32> {
    data.get(0..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_ne_bytes)
}

/// Читает `u64` в порядке байт хоста.
#[must_use]
pub fn read_u64(data: &[u8]) -> Option<u64> {
    data.get(0..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_ne_bytes)
}

/// Читает строку с завершающим нулём.
#[must_use]
pub fn read_str(data: &[u8]) -> Option<String> {
    let bytes = data.split(|&b| b == 0).next()?;
    String::from_utf8(bytes.to_vec()).ok()
}

/// Читает MAC-адрес.
#[must_use]
pub fn read_mac(data: &[u8]) -> Option<[u8; 6]> {
    data.get(0..6).and_then(|b| <[u8; 6]>::try_from(b).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        AttrIter, AttrWriter, NLA_ALIGNTO, NLA_F_NESTED_BIT, nla_align, read_str, read_u32,
    };

    #[test]
    fn writes_and_reads_attributes() {
        let mut attrs = AttrWriter::new();
        attrs.u32(1, 0xdead_beef);
        attrs.str(2, "wlan0");
        attrs.zero(3);

        let parsed: Vec<_> = AttrIter::new(attrs.as_bytes()).collect();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].0, 1);
        assert_eq!(read_u32(parsed[0].1), Some(0xdead_beef));
        assert_eq!(parsed[1].0, 2);
        assert_eq!(read_str(parsed[1].1).as_deref(), Some("wlan0"));
        assert_eq!(parsed[2], (3, &[][..]));
    }

    #[test]
    fn pads_payload_to_four_bytes() {
        let mut attrs = AttrWriter::new();
        attrs.u8(1, 0xaa);
        attrs.u16(2, 0xbbcc);
        assert_eq!(attrs.len(), 8 + 8);
        assert_eq!(&attrs.as_bytes()[4..8], &[0xaa, 0, 0, 0]);
    }

    #[test]
    fn builds_nested_attributes() {
        let mut attrs = AttrWriter::new();
        attrs.nested(10, |inner| {
            inner.u32(1, 42);
        });

        let raw = attrs.finish().unwrap();
        let raw_type = u16::from_ne_bytes([raw[2], raw[3]]);
        assert_eq!(raw_type, 0x000a | NLA_F_NESTED_BIT);

        let parsed: Vec<_> = AttrIter::new(&raw).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 10);

        let inner: Vec<_> = AttrIter::new(parsed[0].1).collect();
        assert_eq!(read_u32(inner[0].1), Some(42));
    }

    #[test]
    fn stops_on_truncated_attribute() {
        let attrs = [
            8, 0, 3, 0, 0xaa, 0xbb, 0xcc, 0xdd, // type=3, 4 байта данных
            6, 0, 4, 0, 0x11, 0x22, // type=4, 2 байта данных + padding
            0xff, 0xff, // обрезанный заголовок
        ];
        let parsed: Vec<_> = AttrIter::new(&attrs).collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], (3, &[0xaa, 0xbb, 0xcc, 0xdd][..]));
        assert_eq!(parsed[1], (4, &[0x11, 0x22][..]));
    }

    #[test]
    fn rejects_zero_length_attribute() {
        let attrs = [0, 0, 1, 0];
        assert_eq!(AttrIter::new(&attrs).count(), 0);
    }

    #[test]
    fn reports_attribute_that_does_not_fit_u16() {
        let mut attrs = AttrWriter::new();
        attrs.bytes(1, &vec![0u8; usize::from(u16::MAX)]);
        assert!(attrs.overflowed());
        assert!(attrs.finish().is_err());
    }

    #[test]
    fn aligns_to_nlattr_boundary() {
        assert_eq!(nla_align(0), 0);
        assert_eq!(nla_align(1), 4);
        assert_eq!(nla_align(5), 8);
        assert_eq!(i32::try_from(NLA_ALIGNTO).unwrap(), libc::NLA_ALIGNTO);
    }
}
