# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2024-10-09
### Added
- Command to emulate an Unlock Client

### Fixed
- Log message when an unlock request is not authenticated should now display the ip and port

## [0.3.0] - 2024-09-23
### Added
- Async support for all components
- CLI commands  and
- CLI commands `pair-client` and `unlock-server`

### Fixed
- Improper unbinding in TCPUnlockServerBase, causing port to be unusable when restarting

## [0.2.0] - 2024-09-18
### Added
- Command to emulate a Pairing Server

### Changed
- Bump cryptography dependency

### Fixed
- Protocol error with newer app versions

## [0.1.7] - 2024-09-12
### Added
- Allow async listen for TCP unlock server

## [0.1.6] - 2024-09-12
### Added
- Allow tweaking pairing timeout

## [0.1.5] - 2024-09-06
### Changed
- Release using different gh action

## [0.1.4] - 2024-09-06
### Added
- Publish to PyPI

## [0.1.3] - 2024-09-06
### Changed
- Fixed release CI

## [0.1.1] - 2024-09-06
### Added
- Initial release!

[Unreleased]: https://github.com/lmgarret/py-pcbu/compare/0.4.0...HEAD
[0.4.0]: https://github.com/lmgarret/py-pcbu/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/lmgarret/py-pcbu/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/lmgarret/py-pcbu/compare/0.1.7...0.2.0
[0.1.7]: https://github.com/lmgarret/py-pcbu/compare/0.1.6...0.1.7
[0.1.6]: https://github.com/lmgarret/py-pcbu/compare/0.1.5...0.1.6
[0.1.5]: https://github.com/lmgarret/py-pcbu/compare/0.1.4...0.1.5
[0.1.4]: https://github.com/lmgarret/py-pcbu/compare/0.1.3...0.1.4
[0.1.3]: https://github.com/lmgarret/py-pcbu/compare/0.1.1...0.1.3
[0.1.1]: https://github.com/lmgarret/py-pcbu/compare/7072a13019d0054e81e7d8d2ed249a9498bd4ddd...0.1.1
