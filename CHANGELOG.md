# Changelog

## Unreleased - 2026-09-25

- Added sender-constrained lease fields for tool and destination binding, plus requester-authority checks.
- Strengthened benchmark defense with opaque lease-reference enforcement, user-originated secret grants, privileged-tool grants, parser hardening, and independent encoded-secret detection.
- Added no-label regression, literal-guard, mutation-style, and Hypothesis tests for the new controls.
- Updated benchmark artifacts: test block rate 92.8%, false-positive rate 1.8%, leaks 0.
- Renamed project to **Ephemeral Agent Secret Leasing**; Python package and CLI renamed to descriptive names; GitHub home moved to the matching organization.
- Renamed labels in result files; measured values unchanged.

## 0.1.0
- Initial local implementation.
