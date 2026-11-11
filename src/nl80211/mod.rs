//! nl80211: интерфейсы, режимы и каналы.
//!
//! Значения команд и атрибутов взяты из `include/uapi/linux/nl80211.h`.

mod channel;
mod interface;

pub use channel::{CHANNELS_2GHZ, CHANNELS_5GHZ, all_channels, channel_to_freq};
pub use interface::{WifiInterface, parse_interface, set_if_promisc, set_if_up};

use crate::attr::AttrWriter;
use crate::error::Result;
use crate::genl::GenlSocket;
use crate::message::NlMessage;

/// Версия nl80211, которую использует библиотека.
pub const NL80211_VERSION: u8 = 0;

/// Имя generic netlink family.
pub const NL80211_FAMILY: &str = "nl80211";

// ─── nl80211 атрибуты ────────────────────────────────────────────────────────

/// Индекс сетевого интерфейса.
pub const NL80211_ATTR_IFINDEX: u16 = 3;
/// Имя сетевого интерфейса.
pub const NL80211_ATTR_IFNAME: u16 = 4;
/// Режим работы интерфейса (`nl80211_iftype`).
pub const NL80211_ATTR_IFTYPE: u16 = 5;
/// Индекс `wiphy`.
pub const NL80211_ATTR_WIPHY: u16 = 1;
/// Имя wiphy (`phy0`, ...).
pub const NL80211_ATTR_WIPHY_NAME: u16 = 2;
/// MAC-адрес интерфейса.
pub const NL80211_ATTR_MAC: u16 = 6;
/// Частота в `МГц`.
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
/// Тип канала (`nl80211_channel_type`).
pub const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;

/// `NL80211_CHAN_NO_HT`: без HT40.
pub const NL80211_CHAN_NO_HT: u32 = 0;

// ─── nl80211 команды ─────────────────────────────────────────────────────────

/// Команды nl80211, используемые библиотекой.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nl80211Cmd {
    /// Получить информацию о wiphy.
    GetWiphy,
    /// Изменить параметры wiphy.
    SetWiphy,
    /// Получить список интерфейсов.
    GetInterface,
    /// Изменить интерфейс.
    SetInterface,
    /// Получить информацию о станции.
    GetStation,
    /// Получить regulatory domain.
    GetReg,
    /// Получить результаты сканирования.
    GetScan,
    /// Запустить сканирование.
    TriggerScan,
    /// Переключить канал.
    SetChannel,
}

impl From<Nl80211Cmd> for u8 {
    fn from(cmd: Nl80211Cmd) -> Self {
        match cmd {
            Nl80211Cmd::GetWiphy => 1,
            Nl80211Cmd::SetWiphy => 2,
            Nl80211Cmd::GetInterface => 5,
            Nl80211Cmd::SetInterface => 6,
            Nl80211Cmd::GetStation => 17,
            Nl80211Cmd::GetReg => 31,
            Nl80211Cmd::GetScan => 32,
            Nl80211Cmd::TriggerScan => 33,
            Nl80211Cmd::SetChannel => 65,
        }
    }
}

// ─── Режимы интерфейса ───────────────────────────────────────────────────────

/// Режим работы интерфейса (`enum nl80211_iftype`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfType {
    /// Не задан.
    Unspecified,
    /// IBSS (ad-hoc).
    Adhoc,
    /// Managed (station).
    Station,
    /// Точка доступа.
    Ap,
    /// AP VLAN.
    ApVlan,
    /// WDS.
    Wds,
    /// Monitor.
    Monitor,
    /// Mesh point.
    MeshPoint,
    /// P2P client.
    P2pClient,
    /// P2P GO.
    P2pGo,
    /// P2P device.
    P2pDevice,
    /// OCB.
    Ocb,
    /// NAN.
    Nan,
}

impl From<IfType> for u32 {
    fn from(if_type: IfType) -> Self {
        match if_type {
            IfType::Unspecified => 0,
            IfType::Adhoc => 1,
            IfType::Station => 2,
            IfType::Ap => 3,
            IfType::ApVlan => 4,
            IfType::Wds => 5,
            IfType::Monitor => 6,
            IfType::MeshPoint => 7,
            IfType::P2pClient => 8,
            IfType::P2pGo => 9,
            IfType::P2pDevice => 10,
            IfType::Ocb => 11,
            IfType::Nan => 12,
        }
    }
}

impl IfType {
    /// Канонические имена для CLI и справки.
    pub const MODE_NAMES: &[&str] = &[
        "managed",
        "monitor",
        "ap",
        "ibss",
        "mesh",
        "p2p-client",
        "p2p-go",
        "p2p-device",
        "ocb",
        "nan",
        "wds",
        "ap-vlan",
        "unspecified",
    ];

    /// Разбирает режим по имени или псевдониму.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.to_ascii_lowercase().replace('_', "-");
        match name.as_str() {
            "managed" | "station" => Some(Self::Station),
            "monitor" => Some(Self::Monitor),
            "ap" => Some(Self::Ap),
            "ibss" | "adhoc" => Some(Self::Adhoc),
            "mesh" | "mesh-point" => Some(Self::MeshPoint),
            "p2p-client" => Some(Self::P2pClient),
            "p2p-go" => Some(Self::P2pGo),
            "p2p-device" => Some(Self::P2pDevice),
            "ocb" => Some(Self::Ocb),
            "nan" => Some(Self::Nan),
            "wds" => Some(Self::Wds),
            "ap-vlan" => Some(Self::ApVlan),
            "unspecified" => Some(Self::Unspecified),
            _ => None,
        }
    }

    /// Преобразует значение из `NL80211_ATTR_IFTYPE`.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::Adhoc),
            2 => Some(Self::Station),
            3 => Some(Self::Ap),
            4 => Some(Self::ApVlan),
            5 => Some(Self::Wds),
            6 => Some(Self::Monitor),
            7 => Some(Self::MeshPoint),
            8 => Some(Self::P2pClient),
            9 => Some(Self::P2pGo),
            10 => Some(Self::P2pDevice),
            11 => Some(Self::Ocb),
            12 => Some(Self::Nan),
            _ => None,
        }
    }

    /// Каноническое имя режима.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Adhoc => "ibss",
            Self::Station => "managed",
            Self::Ap => "ap",
            Self::ApVlan => "ap-vlan",
            Self::Wds => "wds",
            Self::Monitor => "monitor",
            Self::MeshPoint => "mesh",
            Self::P2pClient => "p2p-client",
            Self::P2pGo => "p2p-go",
            Self::P2pDevice => "p2p-device",
            Self::Ocb => "ocb",
            Self::Nan => "nan",
        }
    }
}

impl std::str::FromStr for IfType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_name(s).ok_or_else(|| {
            format!(
                "unknown interface mode '{s}'; expected one of: {}",
                Self::MODE_NAMES.join(", ")
            )
        })
    }
}

// ─── Высокоуровневый сокет ───────────────────────────────────────────────────

/// nl80211-сокет: generic netlink с уже найденной family.
#[derive(Debug)]
pub struct Nl80211 {
    genl: GenlSocket,
    family_id: u16,
}

impl Nl80211 {
    /// Открывает сокет и находит family `nl80211`.
    ///
    /// # Errors
    ///
    /// Возвращает [`crate::Error::FamilyNotFound`], если модуль `cfg80211`
    /// не загружен, или ошибку сокета.
    pub fn open() -> Result<Self> {
        let mut genl = GenlSocket::open()?;
        let family_id = genl.family_id(NL80211_FAMILY)?;
        Ok(Self { genl, family_id })
    }

    /// Идентификатор family `nl80211`.
    #[must_use]
    pub const fn family_id(&self) -> u16 {
        self.family_id
    }

    /// Ссылка на generic netlink-сокет.
    #[must_use]
    pub const fn genl(&self) -> &GenlSocket {
        &self.genl
    }

    /// Изменяемая ссылка на generic netlink-сокет.
    #[must_use]
    pub const fn genl_mut(&mut self) -> &mut GenlSocket {
        &mut self.genl
    }

    pub(crate) fn dump(&mut self, cmd: Nl80211Cmd, attrs: &AttrWriter) -> Result<Vec<NlMessage>> {
        trace!(cmd = ?cmd, "nl80211 dump");
        self.genl
            .dump(self.family_id, cmd.into(), NL80211_VERSION, attrs)
    }

    pub(crate) fn execute(&mut self, cmd: Nl80211Cmd, attrs: &AttrWriter) -> Result<()> {
        trace!(cmd = ?cmd, "nl80211 execute");
        self.genl
            .execute(self.family_id, cmd.into(), NL80211_VERSION, attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::{IfType, Nl80211Cmd};

    #[test]
    fn parses_names_and_aliases() {
        assert_eq!("managed".parse::<IfType>().unwrap(), IfType::Station);
        assert_eq!("station".parse::<IfType>().unwrap(), IfType::Station);
        assert_eq!("monitor".parse::<IfType>().unwrap(), IfType::Monitor);
        assert_eq!("adhoc".parse::<IfType>().unwrap(), IfType::Adhoc);
        assert_eq!("mesh_point".parse::<IfType>().unwrap(), IfType::MeshPoint);
        assert!("bogus".parse::<IfType>().is_err());
    }

    #[test]
    fn canonical_names_roundtrip() {
        for name in IfType::MODE_NAMES {
            let parsed: IfType = name.parse().unwrap();
            assert_eq!(parsed.as_str(), *name);
        }
    }

    #[test]
    fn converts_modes_to_u32() {
        for value in 0..=12 {
            let mode = IfType::from_u32(value).unwrap();
            assert_eq!(u32::from(mode), value);
        }
        assert!(IfType::from_u32(13).is_none());
    }

    #[test]
    fn exposes_nl80211_command_ids() {
        assert_eq!(u8::from(Nl80211Cmd::GetInterface), 5);
        assert_eq!(u8::from(Nl80211Cmd::SetInterface), 6);
        assert_eq!(u8::from(Nl80211Cmd::TriggerScan), 33);
        assert_eq!(u8::from(Nl80211Cmd::SetChannel), 65);
    }
}
