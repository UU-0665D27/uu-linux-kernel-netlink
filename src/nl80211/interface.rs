//! Интерфейсы nl80211: список, режимы и флаги `IFF_*`.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{
    IfType, NL80211_ATTR_IFINDEX, NL80211_ATTR_IFNAME, NL80211_ATTR_IFTYPE, NL80211_ATTR_MAC,
    NL80211_ATTR_WIPHY, NL80211_ATTR_WIPHY_NAME, Nl80211, Nl80211Cmd,
};
use crate::attr::{AttrWriter, read_mac, read_str, read_u32};
use crate::error::{Error, Result};
use crate::message::NlMessage;
use crate::socket::io_error;

/// Описание Wi-Fi-интерфейса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiInterface {
    /// Индекс интерфейса (`ifindex`).
    pub index: u32,
    /// Имя интерфейса.
    pub name: String,
    /// Режим работы.
    pub if_type: IfType,
    /// Индекс wiphy.
    pub wiphy: u32,
    /// Имя wiphy (`phy0`, ...).
    pub wiphy_name: Option<String>,
    /// MAC-адрес.
    pub mac: [u8; 6],
}

impl WifiInterface {
    /// MAC-адрес в формате `aa:bb:cc:dd:ee:ff`.
    #[must_use]
    pub fn mac_str(&self) -> String {
        let [b0, b1, b2, b3, b4, b5] = self.mac;
        format!("{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }

    /// Возвращает `true`, если интерфейс в monitor-режиме.
    #[must_use]
    pub const fn is_monitor(&self) -> bool {
        matches!(self.if_type, IfType::Monitor)
    }
}

impl std::fmt::Display for WifiInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<12} phy{}  {}  [{}]",
            self.name,
            self.wiphy,
            self.mac_str(),
            self.if_type.as_str(),
        )
    }
}

impl Nl80211 {
    /// Возвращает все nl80211-интерфейсы системы.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку dump-запроса.
    pub fn interfaces(&mut self) -> Result<Vec<WifiInterface>> {
        let messages = self.dump(Nl80211Cmd::GetInterface, &AttrWriter::new())?;
        Ok(messages.iter().filter_map(parse_interface).collect())
    }

    /// Находит интерфейс по имени.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::InterfaceNotFound`], если интерфейс отсутствует,
    /// или ошибку dump-запроса.
    pub fn interface_by_name(&mut self, name: &str) -> Result<WifiInterface> {
        self.interfaces()?
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| Error::InterfaceNotFound(name.to_string()))
    }

    /// Переключает интерфейс в заданный режим.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ядра с контекстом `ifindex` и режима.
    pub fn set_interface_type(&mut self, ifindex: u32, if_type: IfType) -> Result<()> {
        trace!(
            ifindex,
            if_type = if_type.as_str(),
            "nl80211 set_interface_type"
        );
        let mut attrs = AttrWriter::new();
        attrs.u32(NL80211_ATTR_IFINDEX, ifindex);
        attrs.u32(NL80211_ATTR_IFTYPE, if_type.into());

        self.execute(Nl80211Cmd::SetInterface, &attrs)
            .map_err(|error| {
                Error::Netlink(format!(
                    "set interface type ifindex={ifindex} -> {}: {error}",
                    if_type.as_str()
                ))
            })
    }

    /// Переключает интерфейс: down → `SET_INTERFACE` → up.
    ///
    /// `promisc`: `None` — не трогать `IFF_PROMISC`; `Some(true/false)` —
    /// включить или выключить его после поднятия интерфейса.
    ///
    /// При ошибке смены режима библиотека пытается вернуть предыдущий режим.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку переключения режима или флагов интерфейса.
    pub fn change_mode(
        &mut self,
        iface: &WifiInterface,
        target: IfType,
        promisc: Option<bool>,
    ) -> Result<()> {
        if iface.if_type == target && promisc.is_none() {
            info!("{} is already in {} mode", iface.name, target.as_str());
            return Ok(());
        }

        let previous = iface.if_type;
        info!("Bringing {} down", iface.name);
        set_if_up(&iface.name, false)?;

        if let Err(error) = self.apply_mode(iface.index, &iface.name, target, promisc) {
            warn!("failed to switch {}: {error}; rolling back", iface.name);
            let rollback = self
                .apply_mode(iface.index, &iface.name, previous, None)
                .err()
                .map_or_else(String::new, |rollback_error| {
                    format!("; rollback failed: {rollback_error}")
                });
            return Err(Error::Netlink(format!(
                "failed to switch {} to {}: {error}{rollback}",
                iface.name,
                target.as_str()
            )));
        }

        info!("{} is now in {} mode", iface.name, target.as_str());
        Ok(())
    }

    /// Переключает интерфейс в monitor-режим.
    ///
    /// # Errors
    ///
    /// См. [`Nl80211::change_mode`].
    pub fn enable_monitor_mode(&mut self, iface: &WifiInterface) -> Result<()> {
        self.change_mode(iface, IfType::Monitor, None)
    }

    fn apply_mode(
        &mut self,
        ifindex: u32,
        ifname: &str,
        target: IfType,
        promisc: Option<bool>,
    ) -> Result<()> {
        info!("Setting {ifname} to {} mode", target.as_str());
        self.set_interface_type(ifindex, target)?;

        info!("Bringing {ifname} up");
        set_if_up(ifname, true)?;

        if let Some(enabled) = promisc {
            info!(
                "{} promiscuous mode on {ifname}",
                if enabled { "Enabling" } else { "Disabling" }
            );
            set_if_promisc(ifname, enabled)?;
        }
        Ok(())
    }
}

/// Поднимает или опускает интерфейс через `SIOCSIFFLAGS`.
///
/// # Errors
///
/// Возвращает [`Error::InterfaceNotFound`] для имени с NUL-байтом и
/// [`Error::Io`] при ошибке `ioctl(2)`.
pub fn set_if_up(ifname: &str, up: bool) -> Result<()> {
    update_if_flags(ifname, |flags| {
        if up {
            flags | libc::IFF_UP
        } else {
            flags & !libc::IFF_UP
        }
    })
}

/// Включает или выключает `IFF_PROMISC`.
///
/// # Errors
///
/// См. [`set_if_up`].
pub fn set_if_promisc(ifname: &str, enabled: bool) -> Result<()> {
    update_if_flags(ifname, |flags| {
        if enabled {
            flags | libc::IFF_PROMISC
        } else {
            flags & !libc::IFF_PROMISC
        }
    })
}

fn update_if_flags<F>(ifname: &str, update: F) -> Result<()>
where
    F: FnOnce(i32) -> i32,
{
    // SAFETY: создаём сокет, дескриптор сразу переходит во владение OwnedFd.
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(io_error());
    }
    // SAFETY: raw_fd только что успешно создан.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let cname = CString::new(ifname).map_err(|_| Error::InterfaceNotFound(ifname.to_string()))?;
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = cname.as_bytes_with_nul();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
    // SAFETY: копируем не больше IFNAMSIZ байт в поле ifr_name.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            req.ifr_name.as_mut_ptr().cast::<u8>(),
            copy_len,
        );
    }

    // SAFETY: req содержит корректное имя интерфейса.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFFLAGS, &raw mut req) } < 0 {
        return Err(io_error());
    }

    let current = i32::from(unsafe { req.ifr_ifru.ifru_flags });
    let updated = update(current);
    let updated = i16::try_from(updated).map_err(|_| Error::ValueOutOfRange(i64::from(updated)))?;
    req.ifr_ifru.ifru_flags = updated;

    // SAFETY: req содержит валидные имя и флаги.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCSIFFLAGS, &raw mut req) } < 0 {
        return Err(io_error());
    }
    Ok(())
}

/// Разбирает сообщение `NL80211_CMD_NEW_INTERFACE` / `GET_INTERFACE`.
#[must_use]
pub fn parse_interface(msg: &NlMessage) -> Option<WifiInterface> {
    let mut index = None::<u32>;
    let mut name = None::<String>;
    let mut if_type = None::<IfType>;
    let mut wiphy = None::<u32>;
    let mut wiphy_name = None::<String>;
    let mut mac = [0u8; 6];

    for (attr_type, data) in msg.attrs() {
        match attr_type {
            NL80211_ATTR_IFINDEX => index = read_u32(data),
            NL80211_ATTR_IFNAME => name = read_str(data),
            NL80211_ATTR_IFTYPE => if_type = read_u32(data).and_then(IfType::from_u32),
            NL80211_ATTR_WIPHY => wiphy = read_u32(data),
            NL80211_ATTR_WIPHY_NAME => wiphy_name = read_str(data),
            NL80211_ATTR_MAC => {
                if let Some(address) = read_mac(data) {
                    mac = address;
                }
            }
            _ => {}
        }
    }

    Some(WifiInterface {
        index: index?,
        name: name?,
        if_type: if_type.unwrap_or(IfType::Unspecified),
        wiphy: wiphy.unwrap_or(0),
        wiphy_name,
        mac,
    })
}

#[cfg(test)]
mod tests {
    use super::{WifiInterface, parse_interface};
    use crate::attr::AttrWriter;
    use crate::message::{MessageBuilder, NLM_F_MULTI, NlMessage};
    use crate::nl80211::{
        NL80211_ATTR_IFINDEX, NL80211_ATTR_IFNAME, NL80211_ATTR_IFTYPE, NL80211_ATTR_MAC,
        NL80211_ATTR_WIPHY, NL80211_ATTR_WIPHY_NAME, Nl80211Cmd,
    };

    fn interface_message() -> NlMessage {
        let mut attrs = AttrWriter::new();
        attrs.u32(NL80211_ATTR_IFINDEX, 3);
        attrs.str(NL80211_ATTR_IFNAME, "wlan0");
        attrs.u32(
            NL80211_ATTR_IFTYPE,
            u32::from(crate::nl80211::IfType::Monitor),
        );
        attrs.u32(NL80211_ATTR_WIPHY, 0);
        attrs.str(NL80211_ATTR_WIPHY_NAME, "phy0");
        attrs.bytes(NL80211_ATTR_MAC, &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let raw = MessageBuilder::genl(
            1,
            0x13,
            libc::NLM_F_REQUEST | NLM_F_MULTI,
            u8::from(Nl80211Cmd::GetInterface),
            0,
        )
        .attrs(&attrs)
        .finish()
        .unwrap();
        NlMessage::parse(raw).unwrap()
    }

    #[test]
    fn parses_interface_message() {
        let iface = parse_interface(&interface_message()).unwrap();
        assert_eq!(iface.index, 3);
        assert_eq!(iface.name, "wlan0");
        assert!(iface.is_monitor());
        assert_eq!(iface.wiphy, 0);
        assert_eq!(iface.wiphy_name.as_deref(), Some("phy0"));
        assert_eq!(iface.mac_str(), "02:11:22:33:44:55");
    }

    #[test]
    fn requires_index_and_name() {
        let raw = MessageBuilder::genl(1, 0x13, libc::NLM_F_REQUEST, 5, 0)
            .attr_u32(NL80211_ATTR_IFINDEX, 1)
            .finish()
            .unwrap();
        assert!(parse_interface(&NlMessage::parse(raw).unwrap()).is_none());
    }

    #[test]
    fn formats_interface() {
        let iface = WifiInterface {
            index: 1,
            name: "wlan0".into(),
            if_type: crate::nl80211::IfType::Station,
            wiphy: 0,
            wiphy_name: None,
            mac: [0; 6],
        };
        assert_eq!(
            iface.to_string(),
            "wlan0        phy0  00:00:00:00:00:00  [managed]"
        );
    }
}
