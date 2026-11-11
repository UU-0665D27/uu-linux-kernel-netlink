//! Заголовки и построение сообщений netlink.
//!
//! `nlmsghdr` (16 байт) → `genlmsghdr` (4 байта, только для generic netlink)
//! → набор атрибутов.
//!
//! Все ABI-константы берутся из `libc`, чтобы не дублировать значения из
//! заголовочных файлов ядра.

use crate::attr::{AttrIter, AttrWriter};
use crate::error::{Error, Result};

pub use libc::{
    NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_FILTERED, NLM_F_DUMP_INTR, NLM_F_ECHO, NLM_F_MATCH,
    NLM_F_MULTI, NLM_F_REQUEST, NLM_F_ROOT, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN,
};

/// Размер заголовка netlink, взят из ABI (`struct nlmsghdr`).
pub const NLMSG_HDRLEN: usize = std::mem::size_of::<libc::nlmsghdr>();

/// Размер заголовка generic netlink, взят из ABI (`struct genlmsghdr`).
pub const GENL_HDRLEN: usize = std::mem::size_of::<libc::genlmsghdr>();

/// Выравнивает длину netlink-сообщения по `align_of::<nlmsghdr>()`.
#[must_use]
pub const fn nlmsg_align(len: usize) -> usize {
    let align = std::mem::align_of::<libc::nlmsghdr>();
    len.saturating_add(align - 1) & !(align - 1)
}

/// Заголовок netlink-сообщения.
///
/// Имена полей повторяют C ABI `struct nlmsghdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetlinkHeader {
    /// Длина сообщения вместе с заголовком.
    pub nlmsg_len: u32,
    /// Тип сообщения или id generic netlink family.
    pub nlmsg_type: u16,
    /// Флаги запроса.
    pub nlmsg_flags: u16,
    /// Номер запроса.
    pub nlmsg_seq: u32,
}

impl NetlinkHeader {
    /// Размер заголовка в байтах.
    pub const LEN: usize = NLMSG_HDRLEN;

    /// Разбирает заголовок из начала буфера.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let raw = buf.get(..Self::LEN)?;
        Some(Self {
            nlmsg_len: u32::from_ne_bytes(raw[0..4].try_into().ok()?),
            nlmsg_type: u16::from_ne_bytes(raw[4..6].try_into().ok()?),
            nlmsg_flags: u16::from_ne_bytes(raw[6..8].try_into().ok()?),
            nlmsg_seq: u32::from_ne_bytes(raw[8..12].try_into().ok()?),
        })
    }
}

/// Заголовок generic netlink-сообщения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenlHeader {
    /// Команда внутри family.
    pub cmd: u8,
    /// Версия family.
    pub version: u8,
    /// Зарезервировано, всегда 0.
    pub reserved: u16,
}

impl GenlHeader {
    /// Размер заголовка в байтах.
    pub const LEN: usize = GENL_HDRLEN;

    /// Разбирает заголовок из начала буфера.
    #[must_use]
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let raw = buf.get(..Self::LEN)?;
        Some(Self {
            cmd: raw[0],
            version: raw[1],
            reserved: u16::from_ne_bytes(raw[2..4].try_into().ok()?),
        })
    }
}

/// Принятое сообщение netlink.
#[derive(Debug, Clone)]
pub struct NlMessage {
    header: NetlinkHeader,
    data: Vec<u8>,
}

impl NlMessage {
    /// Разбирает сообщение из сырых байтов.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::MalformedMessage`], если буфер короче заголовка
    /// или `nlmsg_len` выходит за границы буфера.
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let header = NetlinkHeader::parse(&data).ok_or(Error::MalformedMessage)?;
        let len = usize::try_from(header.nlmsg_len).map_err(|_| Error::MalformedMessage)?;
        if len < NLMSG_HDRLEN || len > data.len() {
            return Err(Error::MalformedMessage);
        }
        Ok(Self { header, data })
    }

    /// Заголовок сообщения.
    #[must_use]
    pub const fn header(&self) -> NetlinkHeader {
        self.header
    }

    /// Сырые байты сообщения.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Забирает сырые байты сообщения.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Заголовок generic netlink, если сообщение его содержит.
    #[must_use]
    pub fn genl_header(&self) -> Option<GenlHeader> {
        GenlHeader::parse(self.payload())
    }

    /// Payload после `nlmsghdr`.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let len = usize::try_from(self.header.nlmsg_len).unwrap_or(self.data.len());
        self.data.get(NLMSG_HDRLEN..len).unwrap_or(&[])
    }

    /// Payload после `nlmsghdr` и `genlmsghdr`.
    #[must_use]
    pub fn genl_payload(&self) -> &[u8] {
        self.payload().get(GENL_HDRLEN..).unwrap_or(&[])
    }

    /// Итератор по атрибутам `genlmsghdr`.
    #[must_use]
    pub fn attrs(&self) -> AttrIter<'_> {
        AttrIter::new(self.genl_payload())
    }
}

/// Строитель netlink-сообщения.
///
/// Флаги принимаются в том же типе, что и константы `libc::NLM_F_*`.
///
/// ```
/// # use uu_linux_kernel_netlink::{Error, MessageBuilder, NLM_F_REQUEST};
/// # fn main() -> Result<(), Error> {
/// let raw = MessageBuilder::genl(1, 0x10, NLM_F_REQUEST, 3, 1)
///     .attr_str(2, "nl80211")
///     .finish()?;
/// assert_eq!(raw.len(), 16 + 4 + 12);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    seq: u32,
    msg_type: u16,
    flags: i32,
    genl: Option<GenlHeader>,
    attrs: AttrWriter,
}

impl MessageBuilder {
    /// Создаёт пустой билдер с указанным `seq`.
    #[must_use]
    pub const fn new(seq: u32) -> Self {
        Self {
            seq,
            msg_type: 0,
            flags: 0,
            genl: None,
            attrs: AttrWriter::new(),
        }
    }

    /// Создаёт generic netlink-сообщение.
    #[must_use]
    pub const fn genl(seq: u32, family_id: u16, flags: i32, cmd: u8, version: u8) -> Self {
        Self {
            seq,
            msg_type: family_id,
            flags,
            genl: Some(GenlHeader {
                cmd,
                version,
                reserved: 0,
            }),
            attrs: AttrWriter::new(),
        }
    }

    /// Создаёт «сырое» netlink-сообщение без `genlmsghdr`.
    #[must_use]
    pub const fn raw(seq: u32, msg_type: u16, flags: i32) -> Self {
        Self {
            seq,
            msg_type,
            flags,
            genl: None,
            attrs: AttrWriter::new(),
        }
    }

    /// Доступ к набору атрибутов.
    #[must_use]
    pub const fn attrs_mut(&mut self) -> &mut AttrWriter {
        &mut self.attrs
    }

    /// Добавляет готовый набор атрибутов.
    #[must_use]
    pub fn attrs(mut self, attrs: &AttrWriter) -> Self {
        self.attrs.extend(attrs.as_bytes());
        self
    }

    /// Добавляет строковый атрибут.
    #[must_use]
    pub fn attr_str(mut self, attr_type: u16, value: &str) -> Self {
        self.attrs.str(attr_type, value);
        self
    }

    /// Добавляет `u32`-атрибут.
    #[must_use]
    pub fn attr_u32(mut self, attr_type: u16, value: u32) -> Self {
        self.attrs.u32(attr_type, value);
        self
    }

    /// Добавляет `u16`-атрибут.
    #[must_use]
    pub fn attr_u16(mut self, attr_type: u16, value: u16) -> Self {
        self.attrs.u16(attr_type, value);
        self
    }

    /// Добавляет произвольный атрибут.
    #[must_use]
    pub fn attr_bytes(mut self, attr_type: u16, value: &[u8]) -> Self {
        self.attrs.bytes(attr_type, value);
        self
    }

    /// Собирает сообщение в байты.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::MessageTooLong`], если длина сообщения не помещается
    /// в `u32`, какой-то атрибут не помещается в `u16` или набор флагов
    /// не помещается в `u16`.
    pub fn finish(self) -> Result<Vec<u8>> {
        let genl_len = if self.genl.is_some() { GENL_HDRLEN } else { 0 };
        let attrs = self.attrs.finish()?;
        let total = NLMSG_HDRLEN
            .checked_add(genl_len)
            .and_then(|len| len.checked_add(attrs.len()))
            .ok_or(Error::MessageTooLong)?;
        let msg_len = u32::try_from(total).map_err(|_| Error::MessageTooLong)?;
        let flags = u16::try_from(self.flags).map_err(|_| Error::MessageTooLong)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&msg_len.to_ne_bytes());
        out.extend_from_slice(&self.msg_type.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&self.seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes()); // pid: 0 → ядро
        if let Some(genl) = self.genl {
            out.push(genl.cmd);
            out.push(genl.version);
            out.extend_from_slice(&genl.reserved.to_ne_bytes());
        }
        out.extend_from_slice(&attrs);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GENL_HDRLEN, GenlHeader, MessageBuilder, NLM_F_DUMP, NLM_F_MULTI, NLM_F_REQUEST,
        NLMSG_ERROR, NLMSG_HDRLEN, NetlinkHeader, NlMessage, nlmsg_align,
    };

    #[test]
    fn aligns_to_four_bytes() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(usize::MAX), usize::MAX & !3);
    }

    #[test]
    fn parses_headers_from_short_buffer() {
        let mut raw = [0u8; NLMSG_HDRLEN];
        raw[0..4].copy_from_slice(&16u32.to_ne_bytes());
        raw[4..6].copy_from_slice(&0x10u16.to_ne_bytes());
        raw[6..8].copy_from_slice(&u16::try_from(NLM_F_REQUEST).unwrap().to_ne_bytes());
        raw[8..12].copy_from_slice(&42u32.to_ne_bytes());

        let hdr = NetlinkHeader::parse(&raw).unwrap();
        assert_eq!(hdr.nlmsg_len, 16);
        assert_eq!(hdr.nlmsg_type, 0x10);
        assert_eq!(hdr.nlmsg_flags, 1);
        assert_eq!(hdr.nlmsg_seq, 42);

        assert!(NetlinkHeader::parse(&raw[..8]).is_none());
        assert!(GenlHeader::parse(&[0; 3]).is_none());
    }

    #[test]
    fn builds_genl_message_with_attribute() {
        let msg = MessageBuilder::genl(7, 0x10, NLM_F_REQUEST, 3, 1)
            .attr_str(2, "nl80211")
            .finish()
            .unwrap();
        let hdr = NetlinkHeader::parse(&msg).unwrap();

        assert_eq!(usize::try_from(hdr.nlmsg_len).unwrap(), msg.len());
        assert_eq!(hdr.nlmsg_type, 0x10);
        assert_eq!(hdr.nlmsg_seq, 7);
        assert_eq!(&msg[NLMSG_HDRLEN..NLMSG_HDRLEN + 4], &[3, 1, 0, 0]);
        assert_eq!(
            &msg[NLMSG_HDRLEN + GENL_HDRLEN..],
            &[12, 0, 2, 0, b'n', b'l', b'8', b'0', b'2', b'1', b'1', 0]
        );
    }

    #[test]
    fn accepts_combined_libc_flags() {
        let msg = MessageBuilder::genl(1, 0x10, NLM_F_REQUEST | NLM_F_DUMP, 5, 0)
            .finish()
            .unwrap();
        let hdr = NetlinkHeader::parse(&msg).unwrap();
        assert_eq!(i32::from(hdr.nlmsg_flags), NLM_F_REQUEST | NLM_F_DUMP);
    }

    #[test]
    fn parses_message_payloads() {
        let raw = MessageBuilder::genl(1, 0x10, NLM_F_REQUEST | NLM_F_MULTI, 5, 0)
            .attr_u32(3, 9)
            .finish()
            .unwrap();
        let msg = NlMessage::parse(raw).unwrap();

        assert_eq!(msg.header().nlmsg_type, 0x10);
        assert_eq!(msg.genl_header().unwrap().cmd, 5);
        assert_eq!(msg.genl_payload().len(), 8);
        let attrs: Vec<_> = msg.attrs().collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].0, 3);
    }

    #[test]
    fn rejects_malformed_message() {
        assert!(NlMessage::parse(vec![0; 4]).is_err());
        assert!(NlMessage::parse(vec![0; 16]).is_err());
    }

    #[test]
    fn rejects_flags_that_do_not_fit_u16() {
        let msg_type = u16::try_from(NLMSG_ERROR).unwrap();
        assert!(MessageBuilder::raw(1, msg_type, i32::MAX).finish().is_err());
    }
}
