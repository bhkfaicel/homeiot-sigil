# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to semantic versioning.

---

## [0.2.1-rc.6] - 2026-03-08

### Changed

- `lora` mis à jour sur `0.2.0-rc.3` (compilation locale via `path` pendant la préparation/reproductibilité).
- Ajustement de la taille de sérialisation des messages `Event` de `serialize::<256>` vers `serialize::<255>` pour respecter la contrainte `lora` (1 octet réservé au flag de compression).
- Alignement des tests de handshake avec la logique réelle de retransmission/rebroadcast (confirm retries, périodes de renvoi).

### Fixed

- Corrections des attentes `embedded-hal-mock` (mode SPI et séquences d’accès) liées aux changements de comportement induits par `lora 0.2.0-rc.3`.
- Vérification que `cargo test -p sigil --offline` passe pour la suite de tests du crate.

---

## [0.2.1-rc.5]

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
