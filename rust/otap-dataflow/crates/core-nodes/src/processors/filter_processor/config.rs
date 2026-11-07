// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Configuration of the filter processor.
//!
//! The types in this module mirror the user-facing JSON/YAML config shape and
//! are `Deserialize`-able. They are compiled into the precompiled filter types
//! in [`otel_arrow_dfe_pdata::otap::filter`] via [`Config::compile`], which
//! compiles every regex pattern once (rejecting invalid patterns) instead of
//! recompiling on each batch.
//!
//! Every config struct in this module uses `#[serde(deny_unknown_fields)]` so
//! typos are rejected during config validation instead of being silently
//! ignored. New config structs must do the same.

use otel_arrow_dfe_config::error::Error as ConfigError;
use otel_arrow_dfe_pdata::otap::filter::{
    AttrMatcher, Pattern, ValueMatcher,
    logs::{LogFilter, LogMatchProperties, LogSeverityNumberMatchProperties},
    metrics::{MetricFilter, MetricMatchProperties},
    traces::{TraceFilter, TraceMatchProperties},
};
use regex::Regex;
use serde::Deserialize;

/// Top-level filter processor configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub metrics: MetricFilterConfig,
    #[serde(default)]
    pub logs: LogFilterConfig,
    #[serde(default)]
    pub traces: TraceFilterConfig,
}

impl Config {
    /// Compile the config into the precompiled filter types, compiling every
    /// regex pattern once. Returns a [`ConfigError`] if any pattern is invalid.
    pub fn compile(&self) -> Result<Filters, ConfigError> {
        Ok(Filters {
            metrics: self.metrics.compile()?,
            logs: self.logs.compile()?,
            traces: self.traces.compile()?,
        })
    }
}

/// The compiled filters for each signal.
#[derive(Debug, Clone)]
pub struct Filters {
    /// Compiled metrics filter.
    pub metrics: MetricFilter,
    /// Compiled logs filter.
    pub logs: LogFilter,
    /// Compiled traces filter.
    pub traces: TraceFilter,
}

/// How to match string values.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    /// Match the string values exactly.
    #[default]
    Strict,
    /// Apply the string values as regular expressions.
    Regexp,
}

impl MatchType {
    /// Compile a single pattern string against this match type.
    fn compile(&self, value: &str) -> Result<Pattern, ConfigError> {
        match self {
            MatchType::Strict => Ok(Pattern::Exact(value.to_string())),
            MatchType::Regexp => {
                let regex = Regex::new(value).map_err(|e| ConfigError::InvalidUserConfig {
                    error: format!("invalid regex '{value}': {e}"),
                })?;
                Ok(Pattern::Regex(regex))
            }
        }
    }
}

/// A value that may be any supported scalar type.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum AnyValueConfig {
    /// String value.
    String(String),
    /// Int value.
    Int(i64),
    /// Double value.
    Double(f64),
    /// Boolean value.
    Boolean(bool),
}

impl AnyValueConfig {
    /// Compile this value into a [`ValueMatcher`]. Array and nested key-value
    /// attributes are not supported.
    fn compile(&self, match_type: &MatchType) -> Result<ValueMatcher, ConfigError> {
        Ok(match self {
            AnyValueConfig::String(value) => ValueMatcher::String(match_type.compile(value)?),
            AnyValueConfig::Int(value) => ValueMatcher::Int(*value),
            AnyValueConfig::Double(value) => ValueMatcher::Double(*value),
            AnyValueConfig::Boolean(value) => ValueMatcher::Bool(*value),
        })
    }
}

/// An attribute key paired with a value to match.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyValueConfig {
    /// Attribute key.
    pub key: String,
    /// Attribute value.
    pub value: AnyValueConfig,
}

impl KeyValueConfig {
    /// Create a new key value pair.
    #[must_use]
    pub const fn new(key: String, value: AnyValueConfig) -> Self {
        Self { key, value }
    }

    fn compile(&self, match_type: &MatchType) -> Result<AttrMatcher, ConfigError> {
        Ok(AttrMatcher {
            key: self.key.clone(),
            value: self.value.compile(match_type)?,
        })
    }
}

fn compile_attrs(
    attrs: &[KeyValueConfig],
    match_type: &MatchType,
) -> Result<Vec<AttrMatcher>, ConfigError> {
    attrs.iter().map(|kv| kv.compile(match_type)).collect()
}

fn compile_patterns(
    values: &[String],
    match_type: &MatchType,
) -> Result<Vec<Pattern>, ConfigError> {
    values.iter().map(|v| match_type.compile(v)).collect()
}

fn compile_values(
    values: &[AnyValueConfig],
    match_type: &MatchType,
) -> Result<Vec<ValueMatcher>, ConfigError> {
    values.iter().map(|v| v.compile(match_type)).collect()
}

// --- Logs ---------------------------------------------------------------------

/// Log filter configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogFilterConfig {
    include: Option<LogMatchPropertiesConfig>,
    exclude: Option<LogMatchPropertiesConfig>,
    // ToDo: Add OTTL Support and accept OTTL expressions
}

impl LogFilterConfig {
    /// Create a new log filter config.
    #[must_use]
    pub const fn new(
        include: Option<LogMatchPropertiesConfig>,
        exclude: Option<LogMatchPropertiesConfig>,
    ) -> Self {
        Self { include, exclude }
    }

    fn compile(&self) -> Result<LogFilter, ConfigError> {
        Ok(LogFilter::new(
            self.include.as_ref().map(|p| p.compile()).transpose()?,
            self.exclude.as_ref().map(|p| p.compile()).transpose()?,
        ))
    }
}

/// Log match properties configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogMatchPropertiesConfig {
    #[serde(default)]
    match_type: MatchType,
    #[serde(default)]
    resource_attributes: Vec<KeyValueConfig>,
    #[serde(default)]
    record_attributes: Vec<KeyValueConfig>,
    #[serde(default)]
    severity_texts: Vec<String>,
    severity_number: Option<LogSeverityNumberConfig>,
    #[serde(default)]
    bodies: Vec<AnyValueConfig>,
}

impl LogMatchPropertiesConfig {
    /// Create a new log match properties config.
    #[must_use]
    pub const fn new(
        match_type: MatchType,
        resource_attributes: Vec<KeyValueConfig>,
        record_attributes: Vec<KeyValueConfig>,
        severity_texts: Vec<String>,
        severity_number: Option<LogSeverityNumberConfig>,
        bodies: Vec<AnyValueConfig>,
    ) -> Self {
        Self {
            match_type,
            resource_attributes,
            record_attributes,
            severity_texts,
            severity_number,
            bodies,
        }
    }

    fn compile(&self) -> Result<LogMatchProperties, ConfigError> {
        Ok(LogMatchProperties::new(
            compile_attrs(&self.resource_attributes, &self.match_type)?,
            compile_attrs(&self.record_attributes, &self.match_type)?,
            compile_patterns(&self.severity_texts, &self.match_type)?,
            self.severity_number.as_ref().map(|s| s.compile()),
            compile_values(&self.bodies, &self.match_type)?,
        ))
    }
}

/// Log severity number match properties configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSeverityNumberConfig {
    min: i32,
    match_undefined: bool,
}

impl LogSeverityNumberConfig {
    /// Create a new log severity number config.
    #[must_use]
    pub const fn new(min: i32, match_undefined: bool) -> Self {
        Self {
            min,
            match_undefined,
        }
    }

    fn compile(&self) -> LogSeverityNumberMatchProperties {
        LogSeverityNumberMatchProperties::new(self.min, self.match_undefined)
    }
}

// --- Metrics ------------------------------------------------------------------

/// Metric filter configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricFilterConfig {
    include: Option<MetricMatchPropertiesConfig>,
    exclude: Option<MetricMatchPropertiesConfig>,
}

impl MetricFilterConfig {
    /// Create a new metric filter config.
    #[must_use]
    pub const fn new(
        include: Option<MetricMatchPropertiesConfig>,
        exclude: Option<MetricMatchPropertiesConfig>,
    ) -> Self {
        Self { include, exclude }
    }

    fn compile(&self) -> Result<MetricFilter, ConfigError> {
        Ok(MetricFilter::new(
            self.include.as_ref().map(|p| p.compile()).transpose()?,
            self.exclude.as_ref().map(|p| p.compile()).transpose()?,
        ))
    }
}

/// Metric match properties configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricMatchPropertiesConfig {
    #[serde(default)]
    match_type: MatchType,
    #[serde(default)]
    metric_names: Vec<String>,
}

impl MetricMatchPropertiesConfig {
    /// Create a new metric match properties config.
    #[must_use]
    pub const fn new(match_type: MatchType, metric_names: Vec<String>) -> Self {
        Self {
            match_type,
            metric_names,
        }
    }

    fn compile(&self) -> Result<MetricMatchProperties, ConfigError> {
        Ok(MetricMatchProperties::new(compile_patterns(
            &self.metric_names,
            &self.match_type,
        )?))
    }
}

// --- Traces -------------------------------------------------------------------

/// Trace filter configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceFilterConfig {
    include: Option<TraceMatchPropertiesConfig>,
    exclude: Option<TraceMatchPropertiesConfig>,
}

impl TraceFilterConfig {
    /// Create a new trace filter config.
    #[must_use]
    pub const fn new(
        include: Option<TraceMatchPropertiesConfig>,
        exclude: Option<TraceMatchPropertiesConfig>,
    ) -> Self {
        Self { include, exclude }
    }

    fn compile(&self) -> Result<TraceFilter, ConfigError> {
        Ok(TraceFilter::new(
            self.include.as_ref().map(|p| p.compile()).transpose()?,
            self.exclude.as_ref().map(|p| p.compile()).transpose()?,
        ))
    }
}

/// Trace match properties configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceMatchPropertiesConfig {
    #[serde(default)]
    match_type: MatchType,
    #[serde(default)]
    resource_attributes: Vec<KeyValueConfig>,
    #[serde(default)]
    span_attributes: Vec<KeyValueConfig>,
    #[serde(default)]
    span_names: Vec<String>,
    #[serde(default)]
    event_names: Vec<String>,
    #[serde(default)]
    event_attributes: Vec<KeyValueConfig>,
    #[serde(default)]
    link_attributes: Vec<KeyValueConfig>,
}

impl TraceMatchPropertiesConfig {
    /// Create a new trace match properties config.
    #[must_use]
    pub const fn new(
        match_type: MatchType,
        resource_attributes: Vec<KeyValueConfig>,
        span_attributes: Vec<KeyValueConfig>,
        span_names: Vec<String>,
        event_names: Vec<String>,
        event_attributes: Vec<KeyValueConfig>,
        link_attributes: Vec<KeyValueConfig>,
    ) -> Self {
        Self {
            match_type,
            resource_attributes,
            span_attributes,
            span_names,
            event_names,
            event_attributes,
            link_attributes,
        }
    }

    fn compile(&self) -> Result<TraceMatchProperties, ConfigError> {
        Ok(TraceMatchProperties::new(
            compile_attrs(&self.resource_attributes, &self.match_type)?,
            compile_attrs(&self.span_attributes, &self.match_type)?,
            compile_patterns(&self.span_names, &self.match_type)?,
            compile_patterns(&self.event_names, &self.match_type)?,
            compile_attrs(&self.event_attributes, &self.match_type)?,
            compile_attrs(&self.link_attributes, &self.match_type)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Scenario: each filter config struct receives an otherwise valid object with an unknown key.
    /// Guarantees: all nine config structs reject unknown fields and name the unexpected key.
    #[test]
    fn test_deserialize_rejects_unknown_fields() {
        let cases = [
            ("Config", "__bogus__", json!({"__bogus__": 1})),
            (
                "LogFilterConfig",
                "log_record",
                json!({"logs": {"log_record": ["x"]}}),
            ),
            (
                "LogMatchPropertiesConfig",
                "record_attribtues",
                json!({"logs": {"include": {"record_attribtues": []}}}),
            ),
            (
                "LogSeverityNumberConfig",
                "max",
                json!({
                    "logs": {
                        "include": {
                            "severity_number": {"min": 9, "match_undefined": false, "max": 21}
                        }
                    }
                }),
            ),
            (
                "KeyValueConfig",
                "match_type",
                json!({
                    "logs": {
                        "include": {
                            "record_attributes": [{"key": "k", "value": "v", "match_type": "regexp"}]
                        }
                    }
                }),
            ),
            (
                "MetricFilterConfig",
                "includes",
                json!({"metrics": {"includes": {}}}),
            ),
            (
                "MetricMatchPropertiesConfig",
                "metric_name",
                json!({"metrics": {"include": {"metric_name": ["a"]}}}),
            ),
            (
                "TraceFilterConfig",
                "error_mode",
                json!({"traces": {"error_mode": "ignore"}}),
            ),
            (
                "TraceMatchPropertiesConfig",
                "span_name",
                json!({"traces": {"include": {"span_name": ["a"]}}}),
            ),
        ];

        for (case_name, field, value) in cases {
            let error = serde_json::from_value::<Config>(value).expect_err(case_name);
            let message = error.to_string();
            assert!(
                message.contains(&format!("unknown field `{field}`")),
                "{case_name}: expected unknown field `{field}`, got {message}"
            );
        }
    }

    /// Scenario: a config with a syntactically invalid regex pattern is compiled.
    /// Guarantees: compilation fails with InvalidUserConfig rather than deferring
    /// the error to the first batch (where it would previously panic).
    #[test]
    fn test_compile_rejects_invalid_regex() {
        let config = Config {
            metrics: MetricFilterConfig::new(
                Some(MetricMatchPropertiesConfig::new(
                    MatchType::Regexp,
                    vec!["(".to_string()],
                )),
                None,
            ),
            ..Default::default()
        };
        let err = config
            .compile()
            .expect_err("invalid regex should be rejected");
        assert!(matches!(err, ConfigError::InvalidUserConfig { .. }));
    }

    /// Scenario: a strict (non-regex) pattern that is not valid regex syntax is
    /// compiled.
    /// Guarantees: strict patterns are treated as literals and never fail to
    /// compile, even when they contain regex metacharacters.
    #[test]
    fn test_compile_strict_pattern_is_literal() {
        let config = Config {
            metrics: MetricFilterConfig::new(
                Some(MetricMatchPropertiesConfig::new(
                    MatchType::Strict,
                    vec!["(".to_string()],
                )),
                None,
            ),
            ..Default::default()
        };
        let _ = config.compile().expect("strict patterns always compile");
    }

    /// Scenario: the complete README filter config example is deserialized and compiled.
    /// Guarantees: all documented fields remain accepted under strict deserialization
    /// and compile without error.
    #[test]
    fn test_deserialize_and_compile_roundtrip() {
        let value = json!({
            "metrics": {
                "include": {
                    "match_type": "strict",
                    "metric_names": ["http.server.request.count", "process.cpu.utilization"]
                },
                "exclude": {
                    "match_type": "regexp",
                    "metric_names": ["^internal\\..*$"]
                }
            },
            "logs": {
                "include": {
                    "match_type": "strict",
                    "resource_attributes": [{"key": "deployment.environment", "value": "prod"}],
                    "record_attributes": [],
                    "severity_texts": ["WARN", "ERROR"],
                    "severity_number": {"min": 13, "match_undefined": false},
                    "bodies": ["checkout started", "failed to write to socket"]
                },
                "exclude": {
                    "match_type": "strict",
                    "resource_attributes": [{"key": "deployment.environment", "value": "staging"}],
                    "record_attributes": [
                        {"key": "component", "value": "db"},
                        {"key": "retryable", "value": true}
                    ],
                    "severity_texts": ["WARN"],
                    "severity_number": null,
                    "bodies": ["checkout started"]
                }
            },
            "traces": {
                "include": {
                    "match_type": "strict",
                    "resource_attributes": [{"key": "deployment.environment", "value": "prod"}],
                    "span_attributes": [],
                    "span_names": ["checkout-warn", "checkout-error"],
                    "event_names": ["checkout-event"],
                    "event_attributes": [],
                    "link_attributes": []
                },
                "exclude": {
                    "match_type": "strict",
                    "resource_attributes": [{"key": "deployment.environment", "value": "staging"}],
                    "span_attributes": [{"key": "component", "value": "db"}],
                    "span_names": ["payment-warn", "payment-error"],
                    "event_names": ["payment-event"],
                    "event_attributes": [{"key": "success", "value": false}],
                    "link_attributes": [{"key": "correlation", "value": false}]
                }
            }
        });
        let config: Config = serde_json::from_value(value).expect("valid config");
        let _ = config.compile().expect("compiles");
    }
}
