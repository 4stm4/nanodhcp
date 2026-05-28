//! Configuration: model, `key=value` parser, semantic validation.

pub mod model;
pub mod parser;
pub mod validate;

pub use model::DhcpConfig;

/// Read, parse and validate a config file in one step.
pub fn load(path: &str) -> Result<DhcpConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config '{}': {}", path, e))?;
    let cfg = parser::parse_config(&text)?;
    validate::validate(&cfg)?;
    Ok(cfg)
}
