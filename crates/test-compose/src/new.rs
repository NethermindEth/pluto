//! Creation of a fresh compose config.

use std::path::Path;

use tracing::info;

use crate::{
    Result,
    config::{Config, Step, write_config},
    define::clean,
};

/// Cleans `dir` and writes `conf` as a new (`step: new`) `config.json`.
pub fn new(dir: impl AsRef<Path>, mut conf: Config) -> Result<()> {
    let dir = dir.as_ref();

    clean(dir)?;

    conf.step = Step::New;

    info!(dir = %dir.display(), config = ?conf, "Writing config to compose dir");

    write_config(dir, &conf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config;

    #[test]
    fn new_resets_step_and_writes_config() {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut conf = Config::new_default();
        conf.step = Step::Locked;

        new(dir.path(), conf.clone()).expect("new");

        conf.step = Step::New;
        assert_eq!(load_config(dir.path()).expect("load"), conf);
    }
}
