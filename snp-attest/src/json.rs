use anyhow::anyhow;

pub fn extract_as_string(
    json: &serde_json::Value,
    key: &str,
) -> anyhow::Result<std::string::String> {
    if let Some(value) = json.get(key) {
        return Ok(std::string::String::from(
            value.as_str().expect("invalid string"),
        ));
    }

    Err(anyhow!("key not found"))
}
