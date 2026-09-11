# Contributing to Hybrid Forensics Framework

Thank you for considering contributing to the Hybrid Forensics Framework! 

As this is a security and forensics framework, we hold code provenance and open-source compliance to the highest standards.

## Code Provenance & Licensing Rules

1. **No Proprietary Code**: Do not submit code copied from commercial forensic products or reverse-engineered proprietary SDKs.
2. **Original Implementation**: Where functionality must be rewritten or added, implement it independently using public specifications or documented APIs.
3. **Dependency Licensing**: Any new dependency must have a permissive open-source license (e.g., MIT, BSD, Apache 2.0). GPL dependencies must be approved individually to ensure compatibility.
4. **No Unlicensed Assets**: Do not include copyrighted images, proprietary fonts, or commercial UI kits.

## Dependency Checklist

If your pull request introduces a new dependency, you must ensure the following:

- [ ] The dependency is absolutely necessary (can it be done with the standard library?)
- [ ] The license is compatible with MIT.
- [ ] You have updated `docs/SBOM.md` and `sbom.json`.
- [ ] You have added the full license text to `LICENSES/THIRD_PARTY_NOTICES.md`.
- [ ] `python src/main.py --license-check` passes successfully.

## Offline Operation Guarantee

The framework must operate completely offline in air-gapped environments. 

Do not introduce mandatory:
- Cloud APIs or telemetry services
- External CDNs or remote JavaScript
- Online Threat Intelligence feeds (unless fully optional and isolated)

## Testing

All new features must be accompanied by unit tests. You can run the entire pipeline test locally using:
```powershell
python src/main.py --self-test
```
