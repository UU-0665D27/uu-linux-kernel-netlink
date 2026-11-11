//! Ошибки библиотеки.

use thiserror::Error;

/// Ошибка при работе с netlink или nl80211.
#[derive(Debug, Error)]
pub enum Error {
    /// Ядро или демон вернули ошибку.
    #[error("netlink: {0}")]
    Netlink(String),

    /// Ошибка ввода-вывода при работе с сокетом.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Generic netlink family не зарегистрирована в ядре.
    #[error("generic netlink family '{0}' not found (module not loaded?)")]
    FamilyNotFound(String),

    /// Интерфейс с таким именем отсутствует.
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),

    /// Неизвестный номер Wi-Fi-канала.
    #[error("unknown Wi-Fi channel {0}")]
    UnknownChannel(u8),

    /// Сообщение или атрибут netlink обрезаны либо имеют неверный формат.
    #[error("netlink: malformed message or attribute")]
    MalformedMessage,

    /// Значение не помещается в поле протокола.
    #[error("netlink: value {0} does not fit into the protocol field")]
    ValueOutOfRange(i64),

    /// Длина сообщения или атрибута превышает допустимую.
    #[error("netlink: message or attribute is too long")]
    MessageTooLong,

    /// Не хватает прав (`root` или `CAP_NET_ADMIN`).
    #[error("operation requires root or CAP_NET_ADMIN")]
    PermissionDenied,
}

/// Результат операций библиотеки.
pub type Result<T> = std::result::Result<T, Error>;
