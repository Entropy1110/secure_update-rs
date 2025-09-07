use optee_utee_build::{TaConfig, RustEdition, Error};
use proto;

fn main() -> Result<(), Error> {
    // Trim newline in UUID include to avoid parse errors
    let uuid = proto::UUID.trim();
    let config = TaConfig::new_default_with_cargo_env(uuid)?;
    optee_utee_build::build(RustEdition::Before2024, config)
}
