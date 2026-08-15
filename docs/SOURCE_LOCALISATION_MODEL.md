# Source Localisation Model

Service: `remediation_source_locator_service.locate_source_evidence`.

## Rule

If exact source location is not established from SAST/secret/scanner/CI changed-file evidence:

`exact_source_location_known = false`

Do **not** invent filenames, functions, configuration keys, or line numbers.

## When known

Return repository reference, source location type, file path, function/class only if established, configuration section if established, line range if genuinely present, evidence references, localisation confidence, limitations.

## UI copy when unknown

Affected component: (likely component)  
Exact source location: Not established  
Next evidence required: Repository mapping or source-level scanner evidence.
