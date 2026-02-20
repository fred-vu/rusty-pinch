use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tokio::runtime::Runtime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";
const OTLP_ENDPOINT_OVERRIDE_ENV: &str = "RUSTY_PINCH_OTEL_EXPORTER_OTLP_ENDPOINT";
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const DEFAULT_SERVICE_NAME: &str = "rusty-pinch";
const DEFAULT_METRIC_EXPORT_INTERVAL_SECS: u64 = 15;

static TOKENS_USED_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
static PROVIDER_LATENCY_SECONDS_HISTOGRAM: OnceLock<Histogram<f64>> = OnceLock::new();
static TOOL_EXECUTIONS_COUNTER: OnceLock<Counter<u64>> = OnceLock::new();

pub struct ObservabilityGuard {
    _tracer_provider: Option<SdkTracerProvider>,
    _meter_provider: Option<SdkMeterProvider>,
    _tokio_runtime: Option<Runtime>,
}

impl ObservabilityGuard {
    pub fn init() -> Self {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        match setup_otel_pipeline() {
            Ok(pipeline) => {
                let tracer = pipeline.tracer_provider.tracer("rusty-pinch-observability");
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                let _ = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_target(false))
                    .with(otel_layer)
                    .try_init();

                init_instruments();

                eprintln!(
                    "{{\"event\":\"observability_init\",\"status\":\"ok\",\"otlp_endpoint\":\"{}\"}}",
                    pipeline.endpoint
                );

                Self {
                    _tracer_provider: Some(pipeline.tracer_provider),
                    _meter_provider: Some(pipeline.meter_provider),
                    _tokio_runtime: Some(pipeline.runtime),
                }
            }
            Err(err) => {
                let _ = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_target(false))
                    .try_init();
                eprintln!(
                    "{{\"event\":\"observability_init\",\"status\":\"degraded\",\"message\":{}}}",
                    serde_json::to_string(&err.to_string())
                        .unwrap_or_else(|_| "\"failed to encode observability error\"".to_string())
                );
                Self {
                    _tracer_provider: None,
                    _meter_provider: None,
                    _tokio_runtime: None,
                }
            }
        }
    }
}

impl Drop for ObservabilityGuard {
    fn drop(&mut self) {
        if let Some(meter_provider) = self._meter_provider.as_ref() {
            if let Err(err) = meter_provider.force_flush() {
                eprintln!(
                    "{{\"event\":\"observability_shutdown\",\"component\":\"metrics\",\"status\":\"flush_error\",\"message\":{}}}",
                    serde_json::to_string(&err.to_string())
                        .unwrap_or_else(|_| "\"failed to encode metrics flush error\"".to_string())
                );
            }
            if let Err(err) = meter_provider.shutdown() {
                eprintln!(
                    "{{\"event\":\"observability_shutdown\",\"component\":\"metrics\",\"status\":\"shutdown_error\",\"message\":{}}}",
                    serde_json::to_string(&err.to_string()).unwrap_or_else(|_| {
                        "\"failed to encode metrics shutdown error\"".to_string()
                    })
                );
            }
        }

        if let Some(tracer_provider) = self._tracer_provider.as_ref() {
            let flush_errors = tracer_provider
                .force_flush()
                .into_iter()
                .filter_map(|result| result.err().map(|err| err.to_string()))
                .collect::<Vec<_>>();
            if !flush_errors.is_empty() {
                eprintln!(
                    "{{\"event\":\"observability_shutdown\",\"component\":\"traces\",\"status\":\"flush_error\",\"message\":{}}}",
                    serde_json::to_string(&flush_errors.join("; "))
                        .unwrap_or_else(|_| "\"failed to encode traces flush error\"".to_string())
                );
            }
            if let Err(err) = tracer_provider.shutdown() {
                eprintln!(
                    "{{\"event\":\"observability_shutdown\",\"component\":\"traces\",\"status\":\"shutdown_error\",\"message\":{}}}",
                    serde_json::to_string(&err.to_string())
                        .unwrap_or_else(|_| "\"failed to encode traces shutdown error\"".to_string())
                );
            }
        }
    }
}

struct PipelineState {
    runtime: Runtime,
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    endpoint: String,
}

fn setup_otel_pipeline() -> Result<PipelineState> {
    let endpoint = env::var(OTLP_ENDPOINT_OVERRIDE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env::var(OTLP_ENDPOINT_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string());
    let service_name = env::var("OTEL_SERVICE_NAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
    let export_interval_secs = env::var("OTEL_METRIC_EXPORT_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_METRIC_EXPORT_INTERVAL_SECS);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rusty-pinch-otel")
        .build()
        .context("failed building tokio runtime for OpenTelemetry")?;
    let _runtime_guard = runtime.enter();

    let resource = Resource::new(vec![KeyValue::new("service.name", service_name)]);

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()
        .context("failed building OTLP span exporter")?;

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter, opentelemetry_sdk::runtime::Tokio)
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()
        .context("failed building OTLP metric exporter")?;

    let periodic_reader =
        PeriodicReader::builder(metric_exporter, opentelemetry_sdk::runtime::Tokio)
            .with_interval(Duration::from_secs(export_interval_secs))
            .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(periodic_reader)
        .build();
    global::set_meter_provider(meter_provider.clone());

    Ok(PipelineState {
        runtime,
        tracer_provider,
        meter_provider,
        endpoint,
    })
}

fn init_instruments() {
    let meter = global::meter("rusty-pinch");

    let _ = TOKENS_USED_COUNTER.get_or_init(|| {
        meter
            .u64_counter("tokens_used")
            .with_description("Total LLM tokens reported by provider usage fields.")
            .build()
    });
    let _ = PROVIDER_LATENCY_SECONDS_HISTOGRAM.get_or_init(|| {
        meter
            .f64_histogram("provider_latency_seconds")
            .with_description("Provider response latency in seconds.")
            .build()
    });
    let _ = TOOL_EXECUTIONS_COUNTER.get_or_init(|| {
        meter
            .u64_counter("tool_executions_total")
            .with_description("Count of deterministic tool invocations by tool name.")
            .build()
    });
}

pub fn record_provider_metrics(
    provider: &str,
    model: &str,
    status: &str,
    attempts: u32,
    latency_ms: u64,
    tokens_used: u64,
) {
    let attrs = vec![
        KeyValue::new("provider", provider.to_string()),
        KeyValue::new("model", model.to_string()),
        KeyValue::new("status", status.to_string()),
        KeyValue::new("attempts", i64::from(attempts)),
    ];

    if let Some(histogram) = PROVIDER_LATENCY_SECONDS_HISTOGRAM.get() {
        histogram.record((latency_ms as f64) / 1000.0, &attrs);
    }
    if let Some(counter) = TOKENS_USED_COUNTER.get() {
        counter.add(tokens_used, &attrs);
    }
}

pub fn record_tool_execution(tool_name: &str, source: &str, status: &str) {
    let tool = tool_name.trim();
    if tool.is_empty() {
        return;
    }

    let attrs = vec![
        KeyValue::new("tool_name", tool.to_string()),
        KeyValue::new("source", source.to_string()),
        KeyValue::new("status", status.to_string()),
    ];
    if let Some(counter) = TOOL_EXECUTIONS_COUNTER.get() {
        counter.add(1, &attrs);
    }
}
