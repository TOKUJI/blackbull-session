# Changelog

All notable changes to `blackbull-session` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [ZeroVer](https://0ver.org/) prior to a 1.0
commitment.

## [Unreleased]

## [0.1.0a1] — 2026-06-14

### Added

- Initial release.  `SessionExtension` ported from BlackBull's in-tree
  `blackbull.middleware.Session` (last shipped in BlackBull 0.37.0).
- Follows the [`init_app(app)`](https://github.com/TOKUJI/BlackBull/blob/master/docs/guide/extensions.md)
  extension convention; registers itself at `app.extensions['session']`.
- Eager (`SessionExtension(app, ...)`) and deferred
  (`ext = SessionExtension(...); ext.init_app(app)`) construction styles both
  supported.
