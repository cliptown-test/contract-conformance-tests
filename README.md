# cliptown-test/contract-conformance-tests

Deterministic state-model, idempotency, serialization, and protocol contract conformance tests.

This repository is the `contract` deep-test suite for `cliptown`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

## MCP server evidence

`.github/workflows/mcp-server-conformance.yml` independently checks out the
immutable production revision recorded in that workflow and proves the real
`cliptown-mcp-server` process on Rust 1.95.0 and 1.97.0. The lower bound is a
clean build of the provider-complete AWS SDK graph. The matrix verifies
formatting, runs every target—including the stdio MCP 2025-11-25 wire test—and
rejects all Clippy warnings. The checkout action and production commit are both
pinned by full SHA; the suite never consumes a moving production branch or
production credentials.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
