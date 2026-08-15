# Time Quality Model

`NormalizedEvent` may carry `event_time_source`, `time_quality`, `time_inferred`, and `timezone_name`. Prefer source timestamps; mark inferred receive-time explicitly so timeline correlation does not overclaim clock accuracy.
