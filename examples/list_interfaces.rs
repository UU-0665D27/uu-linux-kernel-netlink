//! Печатает список Wi-Fi-интерфейсов через nl80211.
//!
//! Запуск: `cargo run --example list_interfaces` (нужен root).

use uu_linux_kernel_netlink::{Error, Nl80211};

fn main() -> Result<(), Error> {
    let mut nl = Nl80211::open()?;
    println!("nl80211 family id: {}", nl.family_id());

    let interfaces = nl.interfaces()?;
    if interfaces.is_empty() {
        println!("no nl80211 interfaces");
    }
    for iface in interfaces {
        println!("{iface}");
    }
    Ok(())
}
