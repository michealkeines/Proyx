use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub address: String,
    pub cache_capacity: u64,
    pub ca_dir: String,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8080".into(),
            cache_capacity: 1024,
            ca_dir: "./proxy-ca".into(),
            log_level: "info".into(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let config: Config = toml::from_str(&contents)?;
                Ok(config)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let config = Config::default();
                let contents = toml::to_string_pretty(&config)?;
                fs::write(path, contents)?;
                Ok(config)
            }
            Err(err) => Err(err.into()),
        }
        .map(|mut config| {
            config.normalize_paths(path);
            config
        })
    }

    fn normalize_paths(&mut self, config_path: &Path) {
        let base_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        if Path::new(&self.ca_dir).is_absolute() {
            return;
        }
        let resolved = base_dir.join(&self.ca_dir);
        self.ca_dir = resolved.to_string_lossy().into_owned();
    }
}
