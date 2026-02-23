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
    let mut routes = routes![];

    #[cfg(feature = "sev")]
    let rocket = {
        use sev::firmware::guest::Firmware;

        let firmware: Mutex<Firmware> = Firmware::open()
            .context("failed to open sev-snp firmware")?
            .into();

        routes.extend(routes![sev_api::cpu_attestation]);
        rocket
            .manage(firmware)
    };

    #[cfg(feature = "nvidia")]
    let rocket = {
        use nvat::SdkHandle;

        let sdk = SdkHandle::get_handle()?;
        
        routes.extend(routes![nvidia_api::nvidia_attestation]);
        rocket
            .manage(sdk)
    };

    rocket
        .mount("/attestation", routes)
        .launch().await?;

    #[cfg(feature = "nvidia")]
    nvat::SdkHandle::get_handle()?.shutdown();

    // // graceful shutdown
    Ok(())
}
