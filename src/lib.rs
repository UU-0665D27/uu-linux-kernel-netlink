//! Работа с Linux netlink без внешних runtime-зависимостей.
//!
//! Библиотека состоит из трёх уровней:
//!
//! * [`NetlinkSocket`] — сырой `AF_NETLINK`-сокет, отправка запросов и разбор
//!   ответов (`ACK`, `NLMSG_DONE`, dump-серии);
//! * [`GenlSocket`] — generic netlink: поиск family по имени, dump и команды
//!   с ACK;
//! * [`Nl80211`] — nl80211: список интерфейсов, смена режима, promisc и каналы.
//!
//! Значения ABI-констант берутся из `libc`, чтобы не дублировать
//! заголовочные файлы ядра. Библиотека работает только на Linux.
//!
//! # Логирование
//!
//! `tracing` — опциональная фича и по умолчанию выключена. Без неё макросы
//! логирования раскрываются в пустоту, а зависимость не компилируется.
//! Включить: `features = ["tracing"]`.
//!
//! # Пример
//!
//! ```no_run
//! # use uu_linux_kernel_netlink::{Error, IfType, Nl80211};
//! # fn main() -> Result<(), Error> {
//! let mut nl = Nl80211::open()?;
//! let iface = nl.interface_by_name("wlan0")?;
//! println!("{iface}");
//!
//! nl.change_mode(&iface, IfType::Monitor, Some(true))?;
//! nl.set_channel(iface.index, 6)?;
//! # Ok(())
//! # }
//! ```
//!
//! Netlink и nl80211 требуют `root` или `CAP_NET_ADMIN`.

#[cfg(not(target_os = "linux"))]
compile_error!("uu-linux-kernel-netlink supports Linux only");

#[cfg(target_os = "linux")]
#[macro_use]
mod telemetry;

#[cfg(target_os = "linux")]
mod attr;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod genl;
#[cfg(target_os = "linux")]
mod message;
#[cfg(target_os = "linux")]
mod nl80211;
#[cfg(target_os = "linux")]
mod socket;

#[cfg(target_os = "linux")]
pub use crate::attr::{
    AttrIter, AttrWriter, NLA_F_NESTED_BIT, NLA_HDRLEN, nla_align, read_mac, read_str, read_u8,
    read_u16, read_u32, read_u64,
};
#[cfg(target_os = "linux")]
pub use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
pub use crate::genl::{CTRL_VERSION, GenlFamily, GenlSocket};
#[cfg(target_os = "linux")]
pub use crate::message::{
    GENL_HDRLEN, GenlHeader, MessageBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_DUMP_FILTERED,
    NLM_F_DUMP_INTR, NLM_F_ECHO, NLM_F_MATCH, NLM_F_MULTI, NLM_F_REQUEST, NLM_F_ROOT, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_HDRLEN, NLMSG_NOOP, NLMSG_OVERRUN, NetlinkHeader, NlMessage, nlmsg_align,
};
#[cfg(target_os = "linux")]
pub use crate::nl80211::{
    CHANNELS_2GHZ, CHANNELS_5GHZ, IfType, NL80211_ATTR_IFINDEX, NL80211_ATTR_IFNAME,
    NL80211_ATTR_IFTYPE, NL80211_ATTR_MAC, NL80211_ATTR_WIPHY, NL80211_ATTR_WIPHY_CHANNEL_TYPE,
    NL80211_ATTR_WIPHY_FREQ, NL80211_ATTR_WIPHY_NAME, NL80211_CHAN_NO_HT, NL80211_FAMILY,
    NL80211_VERSION, Nl80211, Nl80211Cmd, WifiInterface, all_channels, channel_to_freq,
    parse_interface, set_if_promisc, set_if_up,
};
#[cfg(target_os = "linux")]
pub use crate::socket::{NETLINK_GENERIC, NETLINK_ROUTE, NetlinkSocket};
