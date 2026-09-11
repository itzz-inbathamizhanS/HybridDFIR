I want this ENTIRE Hybrid Forensics Framework to be legally distributable as an open-source project.

Do NOT assume that something is open source merely because it is free to download.

Perform a complete OPEN-SOURCE / LICENSE / PROVENANCE audit of the repository before adding new functionality.

==================================================
1. CORE REQUIREMENT
==================================================

The final repository must contain:

- only code that we are legally permitted to redistribute
- only dependencies whose licenses permit our intended redistribution
- no proprietary SDKs
- no commercial-only libraries
- no leaked/copied source code
- no reverse-engineered proprietary source code
- no unlicensed third-party source
- no copied code from random GitHub repositories
- no copyrighted assets copied without redistribution permission
- no proprietary fonts, icons, images, JavaScript, CSS or templates

The project should be suitable for publication as a genuine open-source repository.

Do NOT claim "100% open source" until the audit has actually been completed.

==================================================
2. INVENTORY EVERYTHING
==================================================

Scan the complete repository.

Inspect:

- *.py
- *.js
- *.ts
- *.html
- *.css
- *.json
- *.yaml
- *.yml
- *.toml
- requirements.txt
- pyproject.toml
- package.json
- package-lock.json
- README
- LICENSE
- docs/
- tests/
- assets/
- fonts/
- icons/
- binaries
- DLLs
- EXEs
- SYS drivers
- downloaded tools
- bundled libraries
- generated code
- copied snippets
- third-party templates

Create:

docs/OPEN_SOURCE_AUDIT.md

==================================================
3. CLASSIFY EVERY COMPONENT
==================================================

For every dependency/component determine:

Name
Version
Purpose
License
Copyright holder
Source URL
Whether source code is included
Whether redistribution is permitted
Whether modification is permitted
Whether commercial use is permitted
Whether attribution is required
Whether a NOTICE file is required
Whether source disclosure is required
Whether it is compatible with the project's chosen license

Use these classifications:

GREEN
= compatible and safe to redistribute under the project's licensing strategy

YELLOW
= potentially usable but requires attribution/NOTICE/compliance action

RED
= proprietary, incompatible, unclear provenance, or redistribution rights cannot be established

UNKNOWN
= license/provenance cannot be verified

Do NOT silently classify UNKNOWN as GREEN.

==================================================
4. CHOOSE THE PROJECT LICENSE
==================================================

Do NOT automatically choose a license without checking the dependency situation.

First inspect the current LICENSE.

Then determine whether the project can remain under its current license.

If the repository currently uses MIT, verify that every included dependency and copied component is compatible with the intended distribution.

If another license is more appropriate, explain why BEFORE changing it.

Do not remove or modify third-party copyright notices.

==================================================
5. PYTHON DEPENDENCIES
==================================================

Inspect every Python dependency.

For each package determine:

- exact version
- license
- whether the license is compatible
- whether it is required
- whether it can be removed
- whether an equivalent standard-library implementation is practical

Do NOT blindly replace every dependency.

The existing project documentation describes a zero-dependency philosophy using Python standard library and ctypes.

Preserve that philosophy where technically reasonable.

==================================================
6. VOLATILITY
==================================================

The existing architecture uses Volatility 3 for offline memory analysis.

Do NOT copy Volatility source code into this repository.

Do NOT bundle proprietary components.

Determine:

- Volatility 3 license
- exact version
- redistribution requirements
- attribution requirements
- whether it should remain an external dependency
- how to document installation and licensing correctly

The framework should invoke an externally installed permitted tool where appropriate rather than copying third-party source into this repository.

Update documentation accordingly.

==================================================
7. WINPMEM / MEMORY ACQUISITION
==================================================

The existing documentation references WinPMEM for memory acquisition.

Do NOT bundle a binary unless redistribution rights have been verified.

Do NOT copy or modify third-party driver source without verifying its license.

Determine whether the project should:

A. Use a permitted external acquisition tool

OR

B. Provide an open-source implementation

OR

C. Support multiple externally supplied acquisition mechanisms

The repository must clearly distinguish:

FRAMEWORK CODE
from
EXTERNAL TOOL

Document the license and redistribution status of each external tool.

==================================================
8. NATIVE WINDOWS API CODE
==================================================

Code using documented Windows APIs through Python `ctypes` is different from copying Microsoft's implementation/source code.

Keep original framework code independently authored.

Do NOT copy Microsoft source code.

Do NOT include proprietary SDK source files.

If headers, constants or API definitions are required, verify their redistribution status and include only what is legally appropriate.

Prefer minimal declarations written independently where possible.

==================================================
9. FRONTEND / HTML / CSS / JAVASCRIPT
==================================================

Audit every frontend component.

Remove:

- copied website templates
- proprietary dashboards
- commercial UI kits
- copyrighted images
- proprietary icon sets
- unlicensed JavaScript
- unlicensed fonts
- CDN dependencies whose licensing/provenance is unclear

The dashboard must work offline.

The existing architecture already requires standalone HTML without external CDN dependencies.

Prefer:

- original HTML
- original CSS
- original JavaScript
- browser-native APIs
- self-created SVG icons
- system fonts or properly licensed open fonts

==================================================
10. NO COPIED CODE
==================================================

Search for suspicious copied code patterns.

Inspect:

- comments containing original project names
- copied copyright headers
- GitHub URLs
- Stack Overflow URLs
- source attribution comments
- code blocks that appear copied
- unusual license headers

Do NOT delete attribution simply to make the repository appear original.

If code is legitimately reused under a compatible license:

retain attribution and license requirements.

If provenance cannot be established:

mark it UNKNOWN and replace it with independently authored implementation where appropriate.

==================================================
11. THIRD-PARTY LICENSE DIRECTORY
==================================================

Create:

LICENSES/

Inside it create appropriate attribution/license files for every third-party dependency that requires them.

Example:

LICENSES/
├── THIRD_PARTY_NOTICES.md
├── dependency-A.txt
├── dependency-B.txt
└── ...

Do not include unnecessary copies of licenses where the dependency's distribution method already satisfies the relevant requirement; document the reasoning.

==================================================
12. SOFTWARE BILL OF MATERIALS
==================================================

Generate:

docs/SBOM.md

Include:

- direct dependencies
- transitive dependencies where practical
- versions
- licenses
- provenance
- usage
- distribution status

If an automated SBOM format is practical, also generate:

sbom.json

Use a standard format where possible.

==================================================
13. REMOVE PROPRIETARY DEPENDENCIES
==================================================

If any RED dependency is discovered:

DO NOT simply hide it.

For each RED dependency:

1. Explain why it is incompatible.
2. Determine whether it is actually required.
3. Search the existing architecture for an open alternative.
4. Replace it if practical.
5. Test the replacement.
6. Update documentation.
7. Update requirements.
8. Update license documentation.

Do not replace a dependency with another dependency whose license is unknown.

==================================================
14. AIR-GAPPED REQUIREMENT
==================================================

The framework must continue to operate offline.

No mandatory:

- cloud API
- telemetry service
- online threat intelligence
- external CDN
- remote JavaScript
- online authentication
- SaaS dependency

If optional online integrations exist, they must remain optional and clearly separated from the offline core.

==================================================
15. ORIGINAL IMPLEMENTATION
==================================================

Where functionality must be rewritten, implement it independently.

Do NOT ask another model to reproduce proprietary source code.

Do NOT paste code from commercial forensic products.

Do NOT clone proprietary implementations.

Implement functionality from:

- public specifications
- documented APIs
- openly licensed references
- independently designed algorithms
- official documentation

Maintain a clean provenance record.

==================================================
16. COPYRIGHT HEADERS
==================================================

Add an appropriate copyright header to ORIGINAL project source files.

Do not claim copyright ownership over third-party code.

Example structure:

Copyright (c) [PROJECT YEAR] [PROJECT OWNER]

Licensed under the project's selected open-source license.

Use the actual project owner information supplied in the repository.

==================================================
17. README OPEN-SOURCE SECTION
==================================================

Update README with:

- project license
- third-party dependencies
- third-party licenses
- optional external forensic tools
- build/install requirements
- redistribution notes
- contribution requirements
- attribution requirements

Clearly state what is:

INCLUDED
EXTERNAL
OPTIONAL
REQUIRED

==================================================
18. CONTRIBUTOR SAFETY
==================================================

Create:

CONTRIBUTING.md

Define:

- contribution rules
- code provenance requirements
- dependency licensing requirements
- no copied proprietary code
- no unlicensed assets
- testing requirements
- documentation requirements

Add a simple dependency/provenance checklist.

==================================================
19. AUTOMATED LICENSE CHECK
==================================================

Create a command:

python src/main.py --license-check

It should scan the repository and report:

GREEN
YELLOW
RED
UNKNOWN

It should exit with a non-zero code if a RED item is found.

Do NOT treat an unknown license as automatically safe.

==================================================
20. REPOSITORY CLEANUP
==================================================

Remove only files that are:

- proprietary
- unlicensed
- unnecessary
- generated
- duplicated

Do NOT remove legitimate third-party attribution.

Do NOT remove evidence or source files simply because their origin is unclear.

Flag uncertain files first.

==================================================
21. FINAL OPEN-SOURCE GATE
==================================================

Before declaring completion, verify:

[ ] Project license exists
[ ] All source provenance is understood
[ ] All dependencies are inventoried
[ ] All dependency licenses are identified
[ ] Third-party notices exist where required
[ ] No proprietary binaries are unintentionally bundled
[ ] No proprietary SDK source is bundled
[ ] No unlicensed fonts/assets are bundled
[ ] No copied proprietary code exists
[ ] Offline operation remains functional
[ ] Tests pass
[ ] License-check command passes
[ ] README contains licensing information
[ ] SBOM is generated
[ ] Third-party notices are complete

If ANY item cannot be verified:

DO NOT claim "fully open source."

Report the unresolved item.

==================================================
22. IMPORTANT
==================================================

Do not confuse:

FREE TO USE
with
OPEN SOURCE.

Do not confuse:

PUBLICLY AVAILABLE
with
REDISTRIBUTABLE.

Do not confuse:

SOURCE AVAILABLE
with
OPEN-SOURCE LICENSED.

Every dependency must have a verifiable license/provenance decision.

==================================================
23. FINAL REPORT
==================================================

Create:

docs/OPEN_SOURCE_COMPLIANCE_REPORT.md

Include:

1. Project license
2. Dependency inventory
3. License compatibility
4. Third-party components
5. External tools
6. Bundled binaries
7. Removed components
8. Replaced components
9. Attribution requirements
10. Remaining risks
11. Final compliance status

Use exactly one final status:

OPEN-SOURCE READY

or

OPEN-SOURCE READY WITH DISCLOSED EXTERNAL DEPENDENCIES

or

NOT READY

Do not select the first status unless the audit supports it.

START NOW.

First audit the actual repository.

Then fix licensing/provenance problems.

Then test the project.

Then produce the compliance report.