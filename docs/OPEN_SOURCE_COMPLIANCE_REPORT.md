# Final Open-Source Compliance Report

**Status**: OPEN-SOURCE READY WITH DISCLOSED EXTERNAL DEPENDENCIES
**Date**: 2026-09-11

This document certifies the compliance of the Hybrid Forensics Framework with open-source redistribution requirements.

## 1. Project License
The framework is originally authored and licensed under the **MIT License**.

## 2. Dependency Inventory
All direct dependencies have been identified, and their versions strictly pinned in `requirements.txt`:
- `rich` (13.7.0)
- `questionary` (2.0.1)
- `prompt_toolkit` (3.0.43)
- `pytest` (7.4.4)
- `jsonschema` (4.21.1)

## 3. License Compatibility
All identified dependencies are available under the MIT or BSD-3-Clause licenses. These are permissive, compatible with the project's MIT License, and safe for redistribution.

## 4. Third-Party Components
The project uses original HTML, CSS, and Markdown. No third-party HTML templates, proprietary icon sets, or external CDN dependencies are included. The application runs completely offline.

## 5. External Tools
The framework natively interfaces with advanced forensic tools. These are **not** bundled as source code:
- **Volatility 3** (VSL License)

## 6. Bundled Binaries
- **Removed**: `winpmem.exe` (Apache 2.0 / GPL). It was bundled in the root but has been deleted to comply with the prohibition on bundled binaries. Users must acquire it externally.

## 7. Removed Components
- `winpmem.exe`

## 8. Replaced Components
None were required to be replaced. `requirements.txt` was strictly pinned.

## 9. Attribution Requirements
All open-source dependencies have their full license texts reproduced in `LICENSES/THIRD_PARTY_NOTICES.md` to satisfy the attribution requirements of the MIT and BSD licenses.

## 10. Remaining Risks
None. The repository has been scrubbed of unauthorized third-party code and binaries. A continuous compliance gate (`python src/main.py --license-check`) has been established to protect against proprietary drift.

## 11. Final Compliance Status
**OPEN-SOURCE READY WITH DISCLOSED EXTERNAL DEPENDENCIES**
