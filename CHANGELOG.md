# Changelog

## [1.1.0] - 2026-02-01

### Added
- LLM-based audit prompt (`prompts/audit-prompt.md`) for deep security analysis
- Peer review prompt (`prompts/review-prompt.md`) for finding verification
- CHANGELOG.md

### Fixed
- Input sanitization: agent name validated with regex before use in JSON
- API key no longer printed to stdout on registration (saved to file only)
- Dependency check: scripts now verify `curl` and `jq` are installed before running
- Registry URL override documented in upload.sh
- Credentials file permissions set to 600 after creation

### Security
- JSON payload built with `jq -n` instead of string interpolation (prevents injection)
- Credentials file restricted to owner-only read/write

## [1.0.0] - 2026-02-01

### Added
- Initial release
- Regex-based security scanner (`scripts/scout.sh`)
- Report upload (`scripts/upload.sh`)
- Self-service registration (`scripts/register.sh`)
- 50+ vulnerability patterns across critical/high/medium/low severity
