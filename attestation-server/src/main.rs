mod response;

mod nonce;
#[cfg(feature = "nvidia")]
mod nvidia_api;
#[cfg(feature = "sev")]
mod sev_api;

use log::LevelFilter;
use rocket::routes;
use tokio::sync::Mutex;

use anyhow::Context;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let rocket = rocket::build();

    #[cfg(feature = "sev")]
    let rocket = {
        use sev::firmware::guest::Firmware;

        let firmware: Mutex<Firmware> = Firmware::open()
            .context("failed to open sev-snp firmware")?
            .into();

        rocket
            .manage(firmware)
            .mount("/attestation", routes![sev_api::cpu_attestation])
    };

    #[cfg(feature = "nvidia")]
    let rocket = {
        use nvat::SdkHandle;

        let sdk = SdkHandle::get_handle()?;

        rocket
            .manage(sdk)
            .mount("/attestation", routes![nvidia_api::nvidia_attestation])
    };

    rocket.launch().await?;

    #[cfg(feature = "nvidia")]
    nvat::SdkHandle::get_handle()?.shutdown();

    // // graceful shutdown
    Ok(())
}
