//! Netlink-сокет: открытие, отправка запроса и разбор ответов.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{
    AF_NETLINK, MSG_PEEK, MSG_TRUNC, SOCK_CLOEXEC, SOCK_RAW, bind, getsockname, recvfrom, sendto,
    sockaddr_nl, socklen_t,
};

pub use libc::{NETLINK_GENERIC, NETLINK_ROUTE};

use crate::error::{Error, Result};
use crate::message::{
    NLM_F_MULTI, NLMSG_DONE, NLMSG_ERROR, NLMSG_HDRLEN, NLMSG_NOOP, NLMSG_OVERRUN, NetlinkHeader,
    NlMessage, nlmsg_align,
};

/// Размер буфера, в который читается длина сообщения через `MSG_PEEK`.
const PEEK_LEN: usize = 1;

fn socklen(len: usize) -> socklen_t {
    socklen_t::try_from(len).unwrap_or(socklen_t::MAX)
}

fn nl_family() -> Result<u16> {
    u16::try_from(AF_NETLINK)
        .map_err(|_| Error::Netlink("AF_NETLINK does not fit into sa_family_t".into()))
}

/// Netlink-сокет.
///
/// Сокет привязан к ядру и получает `nl_pid` автоматически.
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: OwnedFd,
    seq: u32,
    pid: u32,
}

impl NetlinkSocket {
    /// Открывает generic netlink-сокет.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::PermissionDenied`] при нехватке прав и
    /// [`Error::Io`] при любой другой ошибке `socket(2)`/`bind(2)`.
    pub fn open() -> Result<Self> {
        Self::open_protocol(NETLINK_GENERIC)
    }

    /// Открывает netlink-сокет для указанного протокола (`NETLINK_*`).
    ///
    /// # Errors
    ///
    /// См. [`NetlinkSocket::open`].
    pub fn open_protocol(protocol: i32) -> Result<Self> {
        // SAFETY: создаём сокет, дескриптор сразу переходит во владение OwnedFd.
        let raw_fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol) };
        if raw_fd < 0 {
            return Err(io_error());
        }
        // SAFETY: raw_fd только что успешно создан и больше нигде не используется.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = nl_family()?;
        // nl_pid = 0 → ядро назначит pid сокета.
        // SAFETY: addr указывает на корректно инициализированную sockaddr_nl.
        let rc = unsafe {
            bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                socklen(std::mem::size_of::<sockaddr_nl>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }

        let mut bound: sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut bound_len = socklen(std::mem::size_of::<sockaddr_nl>());
        // SAFETY: bound/bound_len указывают на корректную память.
        let rc =
            unsafe { getsockname(fd.as_raw_fd(), (&raw mut bound).cast(), &raw mut bound_len) };
        if rc < 0 {
            return Err(io_error());
        }

        trace!(protocol, pid = bound.nl_pid, "netlink socket ready");
        Ok(Self {
            fd,
            seq: 1,
            pid: bound.nl_pid,
        })
    }

    /// Дескриптор сокета.
    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Порт (`nl_pid`), назначенный ядром.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Выдаёт следующий номер запроса.
    pub const fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        seq
    }

    /// Устанавливает таймаут чтения (`SO_RCVTIMEO`).
    ///
    /// `None` сбрасывает таймаут: чтение снова блокирующее.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `setsockopt(2)` и
    /// [`Error::ValueOutOfRange`], если длительность не помещается в `timeval`.
    pub fn set_recv_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        // SAFETY: `timeval` состоит из целых чисел, нулевое значение валидно
        // и означает отсутствие таймаута.
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        if let Some(duration) = timeout {
            tv.tv_sec = duration
                .as_secs()
                .try_into()
                .map_err(|_| Error::ValueOutOfRange(i64::MAX))?;
            let usecs = i32::try_from(duration.subsec_micros())
                .map_err(|_| Error::ValueOutOfRange(i64::MAX))?;
            tv.tv_usec = usecs.into();
        }
        // SAFETY: tv живёт до конца вызова, длина соответствует типу.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                socklen(std::mem::size_of::<libc::timeval>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        Ok(())
    }

    /// Отправляет сообщение ядру.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`], если `sendto(2)` завершился ошибкой или
    /// отправил не всё сообщение.
    pub fn send(&self, msg: &[u8]) -> Result<()> {
        trace!(len = msg.len(), "netlink send");
        let mut dest: sockaddr_nl = unsafe { std::mem::zeroed() };
        dest.nl_family = nl_family()?;
        // nl_pid = 0 → ядро.
        // SAFETY: указатели и длины соответствуют буферам.
        let rc = unsafe {
            sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&raw const dest).cast(),
                socklen(std::mem::size_of::<sockaddr_nl>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        if usize::try_from(rc).unwrap_or(0) != msg.len() {
            return Err(Error::Netlink("short sendto".into()));
        }
        Ok(())
    }

    /// Читает одну дейтаграмму.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `recvfrom(2)`.
    pub fn recv(&self) -> Result<Vec<u8>> {
        let len = self.pending_len()?;
        let mut buf = vec![0u8; len.max(PEEK_LEN)];
        // SAFETY: buf выделен под len байт, указатели валидны.
        let rc = unsafe {
            recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        let read = usize::try_from(rc).unwrap_or(0);
        trace!(len = read, "netlink recv");
        buf.truncate(read);
        Ok(buf)
    }

    fn pending_len(&self) -> Result<usize> {
        let mut peek = [0u8; PEEK_LEN];
        // SAFETY: буфер валиден; MSG_PEEK не забирает сообщение из очереди.
        let rc = unsafe {
            recvfrom(
                self.fd.as_raw_fd(),
                peek.as_mut_ptr().cast(),
                peek.len(),
                MSG_PEEK | MSG_TRUNC,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        Ok(usize::try_from(rc).unwrap_or(0))
    }

    /// Отправляет запрос и собирает все ответы с тем же `seq`.
    ///
    /// ACK (`NLMSG_ERROR` с `error == 0`) не попадает в результат.
    /// `NLMSG_ERROR` с ненулевым кодом превращается в [`Error::Netlink`].
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ядра, [`Error::MalformedMessage`] для битого
    /// сообщения или [`Error::Io`] при сбое сокета.
    pub fn request(&mut self, msg: &[u8], seq: u32) -> Result<Vec<NlMessage>> {
        let mut result = Vec::new();
        self.request_each(msg, seq, |message| {
            result.push(message);
            Ok(())
        })?;
        Ok(result)
    }

    /// Отправляет запрос и передаёт каждое ответное сообщение в `on_message`.
    ///
    /// В отличие от [`NetlinkSocket::request`] не накапливает ответы, что
    /// важно на устройствах с малым объёмом памяти.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ядра, [`Error::MalformedMessage`] для битого
    /// сообщения, [`Error::Io`] при сбое сокета или ошибку из `on_message`.
    pub fn request_each<F>(&mut self, msg: &[u8], seq: u32, mut on_message: F) -> Result<()>
    where
        F: FnMut(NlMessage) -> Result<()>,
    {
        trace!(seq, len = msg.len(), "netlink request");
        self.send(msg)?;

        loop {
            let raw = self.recv()?;
            let mut offset = 0usize;
            let mut multi = false;

            while let Some(header_end) = offset.checked_add(NLMSG_HDRLEN) {
                if header_end > raw.len() {
                    break;
                }
                let header = NetlinkHeader::parse(&raw[offset..]).ok_or(Error::MalformedMessage)?;
                let msg_len =
                    usize::try_from(header.nlmsg_len).map_err(|_| Error::MalformedMessage)?;
                let Some(msg_end) = offset.checked_add(msg_len) else {
                    break;
                };
                if msg_len < NLMSG_HDRLEN || msg_end > raw.len() {
                    break;
                }
                let chunk = &raw[offset..msg_end];

                // Чужие сообщения (старые ACK, multicast) пропускаем.
                if header.nlmsg_seq != seq {
                    offset = offset.saturating_add(nlmsg_align(msg_len));
                    continue;
                }

                match i32::from(header.nlmsg_type) {
                    NLMSG_DONE => {
                        check_errno(chunk)?;
                        return Ok(());
                    }
                    NLMSG_ERROR => {
                        // error == 0 → ACK, данных нет.
                        check_errno(chunk)?;
                        return Ok(());
                    }
                    NLMSG_OVERRUN => {
                        return Err(Error::Netlink("receive buffer overrun".into()));
                    }
                    NLMSG_NOOP => {}
                    _ => {
                        if i32::from(header.nlmsg_flags) & NLM_F_MULTI != 0 {
                            multi = true;
                        }
                        on_message(NlMessage::parse(chunk.to_vec())?)?;
                    }
                }

                offset = offset.saturating_add(nlmsg_align(msg_len));
            }

            // Ответ не был частью серии — он уже целиком в этом чтении.
            if !multi {
                return Ok(());
            }
        }
    }

    /// Отправляет запрос и требует успешный ACK, отбрасывая данные.
    ///
    /// # Errors
    ///
    /// См. [`NetlinkSocket::request`].
    pub fn request_ack(&mut self, msg: &[u8], seq: u32) -> Result<()> {
        self.request(msg, seq).map(|_| ())
    }
}

/// Преобразует `errno` из `nlmsgerr` в ошибку библиотеки.
fn check_errno(chunk: &[u8]) -> Result<()> {
    let Some(raw) = chunk.get(NLMSG_HDRLEN..NLMSG_HDRLEN + 4) else {
        return Ok(());
    };
    let code = i32::from_ne_bytes(raw.try_into().map_err(|_| Error::MalformedMessage)?);
    if code == 0 {
        return Ok(());
    }
    let errno = code.unsigned_abs();
    Err(Error::Netlink(format!(
        "errno {errno}: {}",
        std::io::Error::from_raw_os_error(i32::try_from(errno).unwrap_or(libc::EIO))
    )))
}

/// Ошибка сокета с отдельной обработкой нехватки прав.
pub fn io_error() -> Error {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => Error::PermissionDenied,
        _ => Error::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{check_errno, nlmsg_align};
    use crate::error::Error;

    #[test]
    fn accepts_zero_errno_as_ack() {
        let mut msg = vec![0u8; 20];
        msg[0..4].copy_from_slice(&20u32.to_ne_bytes());
        assert!(check_errno(&msg).is_ok());
    }

    #[test]
    fn converts_negative_errno_to_error() {
        let mut msg = vec![0u8; 20];
        msg[16..20].copy_from_slice(&(-13i32).to_ne_bytes());
        match check_errno(&msg) {
            Err(Error::Netlink(text)) => assert!(text.contains("errno 13"), "{text}"),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn ignores_short_errno_payload() {
        assert!(check_errno(&[0u8; 16]).is_ok());
        assert!(check_errno(&[0u8; 18]).is_ok());
    }

    #[test]
    fn aligns_lengths() {
        assert_eq!(nlmsg_align(17), 20);
    }
}
