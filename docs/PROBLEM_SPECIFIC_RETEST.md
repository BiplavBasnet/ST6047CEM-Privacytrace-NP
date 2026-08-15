# Problem-Specific Retest

Retest should match the original sensitive-data exposure condition where feasible:

- same service
- same endpoint
- same exposure location
- same sensitive-data category
- synthetic sensitive value only

## Synthetic example

`Authorization: Bearer SYNTHETIC_TEST_TOKEN_123`

Expect: raw synthetic token absent from logs/reports; masked representation may appear; non-sensitive metadata may remain.

Raw-value leakage count must equal **0**.
