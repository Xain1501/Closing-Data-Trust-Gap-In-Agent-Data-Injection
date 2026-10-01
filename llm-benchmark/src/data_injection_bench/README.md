# data_injection_bench

This package builds the Data Injection Benchmark: it loads seed tool outputs,
generates tasks, injects attacks, and evaluates model responses.

## Layout

- `attacks/`: Payload generators for syntactic and semantic attacks.
- `bench_types.py`: Shared enums and pydantic types for instances, attacks, and metrics.
- `categories/`: Category-specific task generation and attack planning (GitHub, reference JSON).
- `cli.py`: CLI entry points for dataset generation and evaluation.
- `eval/`: Scoring, reporting, and model runner utilities.
- `field_utils.py`: Path parsing helpers for nested fields and list indices.
- `generator/`: Dataset generation and attack injection pipeline.
- `parsers/`: JSON parsing and format transformers (markdown/csv/text).
- `tasks/`: Task definitions and prompt generation logic.
- `templates/`: Format conversion templates.

## Attack injection rules


### Syntactic attacks

- Injection field selection: choose the first `injectable_fields` path that
  exists in the seed data; if it contains `[]`, resolve it to an index.

#### OBJECT_INSERTION (insert_complete)

- List index resolution: let `target_field.pos` be the list index of the target
  field and `injectable_field.pos` the list index of the injection field (when
  both are in the same list).
  - If `target_field.pos <= injectable_field.pos`, the evaluated target becomes
    `target_field.pos + 1`.
  - If `target_field.pos > injectable_field.pos`, the evaluated target stays at
    `target_field.pos`.
- Payload construction: clone the parent object at the injection field from the
  seed data and replace the target leaf with a fake value.
- Output formatting: JSON payloads are injected as string breakouts (escaped),
  and then re-rendered to other formats (markdown/csv/text) if requested.

#### FIELD_OVERRIDE (override_pre / override_post)

- Injection field selection: same as above, but uses the same resolved list
  index as the target element when both are in the same list.
- Relationship constraint: `parent(target_field) == parent(injectable_field)`.
- Effective type rule:
  - If `target_field.pos < injectable_field.pos`, the effective attack is
    `override_pre`.
  - If `target_field.pos > injectable_field.pos`, the effective attack is
    `override_post`.
- Effective type: the final override direction is determined by the target key
  position in its parent object (pre vs post) and must match the requested type.
- Payload construction: clone the parent object at the injection field, set the
  target leaf to the fake value, then return only the duplicated key's value as
  the payload (so the breakout duplicates that key).

#### FIELD_ADDITION (TODO)

- Insert nonexistent field to the data structure

#### CROSS_TOOL_OVERRIDE (TODO)

- Insert cross-tool results


### Semantic attacks (`error`, `contextual`):

- Payloads are drawn from category configs and optionally templated with
  attacker data (e.g., fake field values).
- The payload is appended into the selected injection field without changing the
  target field or its groundtruth.
