# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning.

---

## [Unreleased]

### Added

CHANGELOG.md

### Changed

- Added Forgejo workflows:
  - `.forgejo/workflows/publish-on-main.yml`
  - `.forgejo/workflows/publish-on-tag.yml`
- Cleaned documentation formatting according to Clippy.

### Fixed

- Resolved proc-macro ABI mismatch issues by cleaning and rebuilding.
- Corrected `bincode` dependency to a 2.x version (`2.0.0`) with `derive` feature.
- Removed unused `lzss` dependency from `Cargo.toml`.

---

## [0.1.0] - 2026-03-12

Initial release of `sigil` as an internal / non-commercial crate.

- First public API for LoRa communication, initialization, and key management.
- Basic tests and doctests for crypto, events, init flows, and models.
