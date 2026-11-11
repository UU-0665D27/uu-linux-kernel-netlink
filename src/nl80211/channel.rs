//! Переключение каналов nl80211.

use super::{
    NL80211_ATTR_IFINDEX, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_ATTR_WIPHY_FREQ,
    NL80211_CHAN_NO_HT, Nl80211, Nl80211Cmd,
};
use crate::attr::AttrWriter;
use crate::error::{Error, Result};

/// Каналы диапазона `2.4 ГГц` → частоты в `МГц`.
pub const CHANNELS_2GHZ: &[(u8, u32)] = &[
    (1, 2412),
    (2, 2417),
    (3, 2422),
    (4, 2427),
    (5, 2432),
    (6, 2437),
    (7, 2442),
    (8, 2447),
    (9, 2452),
    (10, 2457),
    (11, 2462),
    (12, 2467),
    (13, 2472),
    (14, 2484),
];

/// Основные каналы `5 ГГц` (без DFS) → частоты в `МГц`.
pub const CHANNELS_5GHZ: &[(u8, u32)] = &[
    (36, 5180),
    (40, 5200),
    (44, 5220),
    (48, 5240),
    (52, 5260),
    (56, 5280),
    (60, 5300),
    (64, 5320),
    (100, 5500),
    (104, 5520),
    (108, 5540),
    (112, 5560),
    (116, 5580),
    (120, 5600),
    (124, 5620),
    (128, 5640),
    (132, 5660),
    (136, 5680),
    (140, 5700),
    (149, 5745),
    (153, 5765),
    (157, 5785),
    (161, 5805),
    (165, 5825),
];

impl Nl80211 {
    /// Переключает интерфейс на частоту в `МГц`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ядра с указанием частоты.
    pub fn set_frequency(&mut self, ifindex: u32, freq_mhz: u32) -> Result<()> {
        trace!(ifindex, freq_mhz, "nl80211 set_frequency");
        let mut attrs = AttrWriter::new();
        attrs.u32(NL80211_ATTR_IFINDEX, ifindex);
        attrs.u32(NL80211_ATTR_WIPHY_FREQ, freq_mhz);
        attrs.u32(NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);

        self.execute(Nl80211Cmd::SetChannel, &attrs)
            .map_err(|error| Error::Netlink(format!("set frequency {freq_mhz} MHz: {error}")))
    }

    /// Переключает интерфейс на канал диапазонов `2.4` или `5 ГГц`.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::UnknownChannel`] для неизвестного номера канала
    /// или ошибку ядра.
    pub fn set_channel(&mut self, ifindex: u32, channel: u8) -> Result<()> {
        let freq = channel_to_freq(channel).ok_or(Error::UnknownChannel(channel))?;
        self.set_frequency(ifindex, freq)
    }
}

/// Возвращает частоту канала в `МГц`.
#[must_use]
pub fn channel_to_freq(channel: u8) -> Option<u32> {
    CHANNELS_2GHZ
        .iter()
        .chain(CHANNELS_5GHZ.iter())
        .find(|(number, _)| *number == channel)
        .map(|(_, freq)| *freq)
}

/// Возвращает все известные пары `(канал, частота)`.
#[must_use]
pub fn all_channels() -> Vec<(u8, u32)> {
    CHANNELS_2GHZ
        .iter()
        .chain(CHANNELS_5GHZ.iter())
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{all_channels, channel_to_freq};

    #[test]
    fn maps_known_channels() {
        assert_eq!(channel_to_freq(1), Some(2412));
        assert_eq!(channel_to_freq(6), Some(2437));
        assert_eq!(channel_to_freq(14), Some(2484));
        assert_eq!(channel_to_freq(36), Some(5180));
        assert_eq!(channel_to_freq(165), Some(5825));
        assert_eq!(channel_to_freq(0), None);
        assert_eq!(channel_to_freq(200), None);
    }

    #[test]
    fn all_channels_are_unique() {
        let channels = all_channels();
        let mut numbers: Vec<u8> = channels.iter().map(|(channel, _)| *channel).collect();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), channels.len());
        assert!(channels.len() >= 38);
    }
}
