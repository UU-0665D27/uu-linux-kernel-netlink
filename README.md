# uu-linux-kernel-netlink

Небольшая библиотека для работы с Linux netlink и nl80211 без внешних
runtime-зависимостей (только `libc`).

Код вырос из `uu_besside-ng` и разделён на три уровня:

| Уровень | Тип | Назначение |
| --- | --- | --- |
| Сырой netlink | `NetlinkSocket` | `AF_NETLINK`-сокет, отправка запроса, разбор ACK/`NLMSG_DONE`/dump-серий |
| Generic netlink | `GenlSocket` | поиск family по имени, dump-запросы, команды с ACK |
| nl80211 | `Nl80211` | интерфейсы, смена режима, promisc, каналы |

## Требования

- Linux;
- `root` или `CAP_NET_ADMIN` для изменения интерфейсов;
- загруженный модуль `cfg80211`/драйвер Wi-Fi для nl80211.

## Пример

```rust
use uu_linux_kernel_netlink::{Error, IfType, Nl80211};

fn main() -> Result<(), Error> {
    let mut nl = Nl80211::open()?;

    for iface in nl.interfaces()? {
        println!("{iface}");
    }

    let iface = nl.interface_by_name("wlan0")?;
    nl.change_mode(&iface, IfType::Monitor, Some(true))?;
    nl.set_channel(iface.index, 6)?;
    Ok(())
}
```

Список интерфейсов без изменения состояния:

```bash
cargo run --example list_interfaces
```

## Сырой netlink

```rust
use uu_linux_kernel_netlink::{
    AttrWriter, Error, MessageBuilder, NLM_F_REQUEST, NetlinkSocket,
};

fn main() -> Result<(), Error> {
    let mut socket = NetlinkSocket::open()?; // NETLINK_GENERIC
    let seq = socket.next_seq();

    let mut attrs = AttrWriter::new();
    attrs.u32(3, 42);

    let msg = MessageBuilder::genl(seq, 0x10, NLM_F_REQUEST, 3, 1)
        .attrs(&attrs)
        .finish()?;

    let responses = socket.request(&msg, seq)?;
    for response in responses {
        for (attr_type, payload) in response.attrs() {
            println!("attr {attr_type}: {payload:?}");
        }
    }
    Ok(())
}
```

`AttrWriter` умеет `u8/u16/u32/u64`, строки с NUL, произвольные байты и
вложенные атрибуты (`nested`). `AttrIter` возвращает тип без флагов
`NLA_F_NESTED`/`NLA_F_NET_BYTEORDER`.

## Generic netlink

```rust
use uu_linux_kernel_netlink::{AttrWriter, Error, GenlSocket};

fn main() -> Result<(), Error> {
    let mut genl = GenlSocket::open()?;
    let family = genl.get_family("nl80211")?;
    println!("{} -> id {}", family.name.as_deref().unwrap_or("?"), family.id);

    // dump: genl.dump(family.id, cmd, 0, &attrs)?;
    // команда с ACK: genl.execute(family.id, cmd, 0, &attrs)?;
    Ok(())
}
```

## Логирование

`tracing` — опциональная фича и по умолчанию выключена. Без неё макросы
логирования раскрываются в пустоту, а зависимость не компилируется:

```toml
uu-linux-kernel-netlink = { path = "...", features = ["tracing"] }
```

## Особенности реализации

- Значения ABI-констант (`NLM_F_*`, `NLMSG_*`, `CTRL_*`, `NETLINK_*`,
  `NLA_*`) берутся из `libc`.
- Длины и выравнивание заголовков вычисляются из ABI-структур
  (`size_of::<nlmsghdr>()` и т.п.).
- Нет `unwrap`/`expect`/`panic!` в библиотечном коде: ошибки возвращаются
  через `Error`.
- Ошибки ядра из `NLMSG_ERROR` превращаются в `Error::Netlink` с текстом
  `errno`.
- Смена режима делает `down → SET_INTERFACE → up` и откатывает предыдущий
  режим при ошибке.

## Лицензия

MIT OR Apache-2.0.
