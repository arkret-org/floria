use std::str::FromStr;

use anyhow::{Result, anyhow, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlTableName {
    sql: String,
}

impl SqlTableName {
    pub fn parse(raw: &str, field: &str) -> Result<Self> {
        let value = raw.trim();
        if value.is_empty() {
            bail!("{field} must not be empty");
        }
        let parts = value.split('.').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 2 {
            bail!("{field} must be `table` or `schema.table`; got `{raw}`");
        }
        for part in &parts {
            validate_identifier(part, field)?;
        }
        Ok(Self {
            sql: parts
                .iter()
                .map(|part| format!("\"{part}\""))
                .collect::<Vec<_>>()
                .join("."),
        })
    }

    pub fn as_sql(&self) -> &str {
        &self.sql
    }
}

pub fn validate_identifier(raw: &str, field: &str) -> Result<()> {
    let mut chars = raw.chars();
    let Some(first) = chars.next() else {
        bail!("{field} contains an empty identifier");
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        bail!("{field} identifier `{raw}` must start with ASCII letter or `_`");
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        bail!("{field} identifier `{raw}` must contain only ASCII letters, digits, or `_`");
    }
    Ok(())
}

pub fn validate_postgres_url(raw: &str, field: &str) -> Result<()> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    postgres::Config::from_str(value)
        .map(|_| ())
        .map_err(|error| anyhow!("{field} must be a valid PostgreSQL connection URL: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_name_accepts_schema_table() {
        let table = SqlTableName::parse("floria.push_contact_cache", "storage.table").unwrap();
        assert_eq!(table.as_sql(), "\"floria\".\"push_contact_cache\"");
    }

    #[test]
    fn table_name_rejects_unsafe_identifiers() {
        let error =
            SqlTableName::parse("floria.push_contact_cache;drop", "storage.table").unwrap_err();
        assert!(error.to_string().contains("must contain only ASCII"));
    }
}
