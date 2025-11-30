/// Centralized tunables for buffers, pooling, and protocol limits.
/// Values here mirror prior hard-coded defaults so behavior is unchanged.
pub struct BufferConfig {
    /// Per-connection in/out slabs (bytes).
    pub io_cap: usize,
    /// Per-H1 session header buffer (bytes).
    pub h1_headers_cap: usize,
    /// Maximum body allocation for small buffered bodies (bytes).
    pub h1_body_max: usize,
}

pub struct UpstreamConfig {
    /// Maximum pooled upstream entries per connection.
    pub pool_limit: usize,
}

pub struct H2Config {
    /// Maximum allowed HTTP/2 frame payload size (bytes).
    pub max_frame_size: usize,
}

pub struct ConnectConfig {
    /// When true, CONNECT requests stay as raw tunnels (current behavior). When false,
    /// we MITM and parse HTTP inside the tunnel.
    pub passthrough_tunnel: bool,
}

pub struct Config {
    pub buffers: BufferConfig,
    pub upstream: UpstreamConfig,
    pub h2: H2Config,
    pub connect: ConnectConfig,
}

impl Config {
    pub const fn new() -> Self {
        Self {
            buffers: BufferConfig {
                io_cap: 64 * 1024,
                h1_headers_cap: 64 * 1024,
                h1_body_max: 64 * 1024,
            },
            upstream: UpstreamConfig { pool_limit: 32 },
            h2: H2Config {
                max_frame_size: 16_384,
            },
            connect: ConnectConfig {
                passthrough_tunnel: false,
            },
        }
    }
}

/// Global read-only configuration.
pub const CONFIG: Config = Config::new();
