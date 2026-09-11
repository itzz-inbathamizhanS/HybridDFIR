# Software Bill of Materials (SBOM)

This document outlines the dependencies and external tools used by the Hybrid Forensics Framework.

## Direct Python Dependencies

| Package | Version | License | Copyright Holder | Provenance / Usage | Status |
|---|---|---|---|---|---|
| `rich` | 13.7.0 | MIT | Will McGugan | PyPI / CLI UI formatting | GREEN |
| `questionary` | 2.0.1 | MIT | Tom Bocklisch | PyPI / Interactive REPL | GREEN |
| `prompt_toolkit` | 3.0.43 | BSD 3-Clause | Jonathan Slenders | PyPI / Interactive REPL | GREEN |
| `pytest` | 7.4.4 | MIT | Holger Krekel | PyPI / Unit Testing | GREEN |
| `jsonschema` | 4.21.1 | MIT | Julian Berman | PyPI / Config schema validation | GREEN |

## External Tools (Not Bundled)

The following tools are optional or required prerequisites installed separately by the user:

| Tool | Version | License | Usage | Status |
|---|---|---|---|---|
| `WinPMEM` | Any | Apache 2.0 / GPL | Windows Memory Acquisition | GREEN (External) |
| `Volatility 3` | >= 2.0.0 | Volatility Software License (VSL) | Offline Memory Analysis | GREEN (External) |

*Full license texts for the Python dependencies are available in `LICENSES/THIRD_PARTY_NOTICES.md`.*
