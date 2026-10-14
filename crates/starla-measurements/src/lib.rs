//! Measurement implementations for Starla

pub mod dns;
pub mod http;
pub mod ntp;
pub mod ping;
pub mod target;
pub mod tls;
pub mod traceroute;
pub mod traits;

pub use dns::Dns;
pub use http::Http;
pub use ntp::Ntp;
pub use ping::Ping;
pub use tls::Tls;
pub use traceroute::Traceroute;
pub use traits::Measurement;

/// Why the scamper backend cannot run in this build: off Linux it is never
/// compiled in, and on Linux only with the `scamper` feature (a default
/// one). Selecting it is then an error at run time, not at build time.
#[cfg(not(all(target_os = "linux", feature = "scamper")))]
pub(crate) fn scamper_unavailable() -> anyhow::Error {
    if cfg!(target_os = "linux") {
        anyhow::anyhow!(
            "scamper backend is not compiled in: starla-measurements was built without \
             its `scamper` feature"
        )
    } else {
        anyhow::anyhow!("scamper backend is only available on Linux")
    }
}
