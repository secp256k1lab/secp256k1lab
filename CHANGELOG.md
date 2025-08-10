# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

#### Added

 - Added a new method `GE.from_bytes_compressed_with_infinity` to parse a compressed
   public key (33 bytes) to a group element, where the all-zeros bytestring maps to the
   point at infinity. This is the counterpart to the already existing serialization
   method `GE.to_bytes_compressed_with_infinity`.

## [1.0.0] - 2025-03-31

Initial release.
