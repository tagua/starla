# starla-measurements

Network measurement implementations compatible with the RIPE Atlas result format.

## Supported Measurements

| Type | Description |
|------|-------------|
| **Ping** | ICMP echo request/reply with RTT measurement |
| **Traceroute** | Path discovery via ICMP, UDP, or TCP |
| **DNS** | DNS queries with timing and response capture |
| **HTTP** | HTTP requests with timing breakdown |
| **TLS** | TLS certificate retrieval |
| **NTP** | NTP time synchronization measurement |

## Usage

Every measurement implements the `Measurement` trait. A measurement is built
by the scheduler, which resolves the target and fills `dst_name`:

```rust
use starla_measurements::{Measurement, Ping, PingConfig};

let ping = Ping {
    config: PingConfig {
        target: "8.8.8.8".parse()?,
        count: 3,
        size: 64,
        ttl: 64,
        interval_ms: 1000,
        backend: Default::default(),
        kept: Default::default(),
    },
    probe_id,
    msm_id,
    dst_name, // how the result names the target (starla_measurements::target)
};

let result = ping.execute().await?;
```

## Result Format

Results are formatted to match the RIPE Atlas JSON schema, ensuring compatibility with existing analysis tools and the RIPE Atlas API.

## Features

| Feature | Default | What it adds |
|---------|---------|--------------|
| `scamper` | yes | The scamper backend for ping and traceroute (`PingBackend::Scamper`, `TracerouteBackend::Scamper`). On Linux it links [rscamper](https://crates.io/crates/rscamper), and through it CAIDA's libscamperfile and libscamperctrl as static libraries (`SCAMPER_LIB_DIR`); on other platforms it adds nothing. |

The Starla probe keeps the default. A library that only uses the native
backends can leave scamper out, and with it the C libraries, the
`-Wl,--allow-multiple-definition` link argument (Starla's
`.cargo/config.toml`) and the GPL-2.0-only scamper code:

```toml
starla-measurements = { version = "1", default-features = false }
```

Selecting the scamper backend in such a build is an error when the
measurement runs, as it is on any platform other than Linux.
