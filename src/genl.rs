//! Generic netlink (`genl`): поиск family и обмен командами.
//!
//! Значения команд и атрибутов контроллера берутся из `libc`.

use std::collections::HashMap;

use crate::attr::{AttrIter, AttrWriter, read_str, read_u32};
use crate::error::{Error, Result};
use crate::message::{MessageBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NlMessage};
use crate::socket::NetlinkSocket;

/// Версия протокола generic netlink controller.
pub const CTRL_VERSION: u8 = 1;

/// Multicast-группа generic netlink family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticastGroup {
    /// Имя группы (`"mlme"`, `"config"`, ...).
    pub name: String,
    /// Идентификатор для `NETLINK_ADD_MEMBERSHIP`.
    pub id: u32,
}

/// Описание generic netlink family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenlFamily {
    /// Идентификатор family, который подставляется в `nlmsghdr.nlmsg_type`.
    pub id: u16,
    /// Имя family.
    pub name: Option<String>,
    /// Версия family.
    pub version: Option<u32>,
    /// Размер приватного заголовка family.
    pub hdrsize: Option<u32>,
    /// Максимальный номер атрибута.
    pub maxattr: Option<u32>,
    /// Multicast-группы, объявленные family.
    pub groups: Vec<MulticastGroup>,
}

/// Generic netlink-сокет с кэшем найденных family.
#[derive(Debug)]
pub struct GenlSocket {
    socket: NetlinkSocket,
    families: HashMap<String, u16>,
}

impl GenlSocket {
    /// Открывает generic netlink-сокет.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку сокета, см. [`NetlinkSocket::open`].
    pub fn open() -> Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::open()?,
            families: HashMap::new(),
        })
    }

    /// Ссылка на нижележащий сокет.
    #[must_use]
    pub const fn socket(&self) -> &NetlinkSocket {
        &self.socket
    }

    /// Изменяемая ссылка на нижележащий сокет.
    #[must_use]
    pub const fn socket_mut(&mut self) -> &mut NetlinkSocket {
        &mut self.socket
    }

    /// Возвращает id family по имени, запрашивая его один раз.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::FamilyNotFound`], если family не зарегистрирована,
    /// или ошибку обмена с ядром.
    pub fn family_id(&mut self, name: &str) -> Result<u16> {
        if let Some(id) = self.families.get(name) {
            trace!(name, id = *id, "generic netlink family cached");
            return Ok(*id);
        }
        let family = self.get_family(name)?;
        self.families.insert(name.to_string(), family.id);
        Ok(family.id)
    }

    /// Возвращает id multicast-группы family.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::FamilyNotFound`], если family не зарегистрирована
    /// или не объявляет такую группу.
    pub fn multicast_group(&mut self, family: &str, group: &str) -> Result<u32> {
        let info = self.get_family(family)?;
        info.groups
            .iter()
            .find(|candidate| candidate.name == group)
            .map(|candidate| candidate.id)
            .ok_or_else(|| Error::FamilyNotFound(format!("{family}/{group}")))
    }

    /// Запрашивает описание family у generic netlink controller.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::FamilyNotFound`] или ошибку обмена с ядром.
    pub fn get_family(&mut self, name: &str) -> Result<GenlFamily> {
        trace!(name, "generic netlink get_family");
        let seq = self.socket.next_seq();
        let ctrl_id = to_u16(libc::GENL_ID_CTRL)?;
        let cmd = to_u8(libc::CTRL_CMD_GETFAMILY)?;
        let name_attr = to_u16(libc::CTRL_ATTR_FAMILY_NAME)?;

        let mut attrs = AttrWriter::new();
        attrs.str(name_attr, name);

        let msg = MessageBuilder::genl(seq, ctrl_id, NLM_F_REQUEST, cmd, CTRL_VERSION)
            .attrs(&attrs)
            .finish()?;
        let responses = self.socket.request(&msg, seq)?;

        for response in &responses {
            if let Some(family) = parse_family(response)? {
                return Ok(family);
            }
        }
        Err(Error::FamilyNotFound(name.to_string()))
    }

    /// Выполняет dump-запрос к family.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку сборки сообщения, ошибку ядра или ошибку сокета.
    pub fn dump(
        &mut self,
        family_id: u16,
        cmd: u8,
        version: u8,
        attrs: &AttrWriter,
    ) -> Result<Vec<NlMessage>> {
        trace!(family_id, cmd, "generic netlink dump");
        let seq = self.socket.next_seq();
        let msg = MessageBuilder::genl(seq, family_id, NLM_F_REQUEST | NLM_F_DUMP, cmd, version)
            .attrs(attrs)
            .finish()?;
        self.socket.request(&msg, seq)
    }

    /// Выполняет dump-запрос и передаёт каждое сообщение в `on_message`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку сборки сообщения, ошибку ядра, ошибку сокета или
    /// ошибку из `on_message`.
    pub fn dump_each<F>(
        &mut self,
        family_id: u16,
        cmd: u8,
        version: u8,
        attrs: &AttrWriter,
        on_message: F,
    ) -> Result<()>
    where
        F: FnMut(NlMessage) -> Result<()>,
    {
        trace!(family_id, cmd, "generic netlink dump_each");
        let seq = self.socket.next_seq();
        let msg = MessageBuilder::genl(seq, family_id, NLM_F_REQUEST | NLM_F_DUMP, cmd, version)
            .attrs(attrs)
            .finish()?;
        self.socket.request_each(&msg, seq, on_message)
    }

    /// Выполняет команду и ждёт ACK.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку сборки сообщения, ошибку ядра или ошибку сокета.
    pub fn execute(
        &mut self,
        family_id: u16,
        cmd: u8,
        version: u8,
        attrs: &AttrWriter,
    ) -> Result<()> {
        trace!(family_id, cmd, "generic netlink execute");
        let seq = self.socket.next_seq();
        let msg = MessageBuilder::genl(seq, family_id, NLM_F_REQUEST | NLM_F_ACK, cmd, version)
            .attrs(attrs)
            .finish()?;
        self.socket.request_ack(&msg, seq)
    }
}

/// Приводит константу `libc` к `u16`.
fn to_u16(value: i32) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::ValueOutOfRange(i64::from(value)))
}

/// Приводит константу `libc` к `u8`.
fn to_u8(value: i32) -> Result<u8> {
    u8::try_from(value).map_err(|_| Error::ValueOutOfRange(i64::from(value)))
}

fn parse_family(msg: &NlMessage) -> Result<Option<GenlFamily>> {
    let mut family = GenlFamily {
        id: 0,
        name: None,
        version: None,
        hdrsize: None,
        maxattr: None,
        groups: Vec::new(),
    };
    let mut found_id = false;

    for (attr_type, data) in msg.attrs() {
        match i32::from(attr_type) {
            libc::CTRL_ATTR_FAMILY_ID => {
                let Some(id) = data
                    .get(0..2)
                    .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
                    .map(u16::from_ne_bytes)
                else {
                    return Err(Error::MalformedMessage);
                };
                family.id = id;
                found_id = true;
            }
            libc::CTRL_ATTR_FAMILY_NAME => family.name = read_str(data),
            libc::CTRL_ATTR_VERSION => family.version = read_u32(data),
            libc::CTRL_ATTR_HDRSIZE => family.hdrsize = read_u32(data),
            libc::CTRL_ATTR_MAXATTR => family.maxattr = read_u32(data),
            libc::CTRL_ATTR_MCAST_GROUPS => family.groups = parse_groups(data),
            _ => {}
        }
    }

    Ok(found_id.then_some(family))
}

/// Разбирает вложенный список multicast-групп.
fn parse_groups(data: &[u8]) -> Vec<MulticastGroup> {
    let mut groups = Vec::new();
    for (_, entry) in AttrIter::new(data) {
        let mut name = None;
        let mut id = None;
        for (kind, value) in AttrIter::new(entry) {
            match i32::from(kind) {
                libc::CTRL_ATTR_MCAST_GRP_NAME => name = read_str(value),
                libc::CTRL_ATTR_MCAST_GRP_ID => id = read_u32(value),
                _ => {}
            }
        }
        if let (Some(name), Some(id)) = (name, id) {
            groups.push(MulticastGroup { name, id });
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::{parse_family, to_u8, to_u16};
    use crate::attr::AttrWriter;
    use crate::error::Error;
    use crate::message::{MessageBuilder, NLM_F_MULTI, NlMessage};

    fn family_message() -> NlMessage {
        let mut attrs = AttrWriter::new();
        attrs.u16(u16::try_from(libc::CTRL_ATTR_FAMILY_ID).unwrap(), 0x13);
        attrs.str(
            u16::try_from(libc::CTRL_ATTR_FAMILY_NAME).unwrap(),
            "nl80211",
        );
        attrs.u32(u16::try_from(libc::CTRL_ATTR_VERSION).unwrap(), 1);
        attrs.u32(u16::try_from(libc::CTRL_ATTR_HDRSIZE).unwrap(), 0);
        attrs.u32(u16::try_from(libc::CTRL_ATTR_MAXATTR).unwrap(), 300);

        let raw = MessageBuilder::genl(
            1,
            0x10,
            libc::NLM_F_REQUEST | NLM_F_MULTI,
            u8::try_from(libc::CTRL_CMD_GETFAMILY).unwrap(),
            1,
        )
        .attrs(&attrs)
        .finish()
        .unwrap();
        NlMessage::parse(raw).unwrap()
    }

    #[test]
    fn parses_family_attributes() {
        let family = parse_family(&family_message()).unwrap().unwrap();
        assert_eq!(family.id, 0x13);
        assert_eq!(family.name.as_deref(), Some("nl80211"));
        assert_eq!(family.version, Some(1));
        assert_eq!(family.hdrsize, Some(0));
        assert_eq!(family.maxattr, Some(300));
    }

    #[test]
    fn ignores_messages_without_family_id() {
        let raw = MessageBuilder::genl(1, 0x10, libc::NLM_F_REQUEST, 3, 1)
            .attr_str(2, "nl80211")
            .finish()
            .unwrap();
        let msg = NlMessage::parse(raw).unwrap();
        assert!(parse_family(&msg).unwrap().is_none());
    }

    #[test]
    fn rejects_truncated_family_id() {
        let mut attrs = AttrWriter::new();
        attrs.u8(u16::try_from(libc::CTRL_ATTR_FAMILY_ID).unwrap(), 1);
        let raw = MessageBuilder::genl(1, 0x10, libc::NLM_F_REQUEST, 3, 1)
            .attrs(&attrs)
            .finish()
            .unwrap();
        let msg = NlMessage::parse(raw).unwrap();
        assert!(matches!(parse_family(&msg), Err(Error::MalformedMessage)));
    }

    #[test]
    fn converts_libc_constants() {
        assert_eq!(to_u16(libc::CTRL_ATTR_FAMILY_ID).unwrap(), 1);
        assert_eq!(to_u8(libc::CTRL_CMD_GETFAMILY).unwrap(), 3);
        assert!(matches!(to_u8(i32::MAX), Err(Error::ValueOutOfRange(_))));
    }
}
