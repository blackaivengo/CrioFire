# Releasing CrioFire

Releases are built, signed and drafted by `.github/workflows/release.yml`. Signing waits for the
maintainer's approval in GitHub, and only that approved job can get an Azure token.

## Release flow

1. Merge everything for the release into `main`.
2. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`
3. The workflow checks the tag is on `main`, tests and publishes x64 and ARM64 builds.
4. The **Sign** job pauses: GitHub shows "Review deployments". Approve it (web or mobile app).
5. The job signs CrioFire's own binaries, verifies every signature names CrioSoft LLC,
   zips each architecture, writes `SHA256SUMS.txt` and creates a **draft** GitHub Release.
6. Check the draft, then publish it.

## One-time setup

### Azure Artifact Signing (CrioSoft LLC)

1. Create an Azure subscription billed to CrioSoft LLC.
2. Create an **Artifact Signing account** in a supported region. Note its endpoint
   (for example `https://eus.codesigning.azure.net/`) and account name.
3. Submit an **organization identity validation** for CrioSoft LLC (legal name, website,
   D-U-N-S number if available). Approval can take 1-20 business days.
4. Create a **Public Trust certificate profile** using that validation. Note its name.
5. In Microsoft Entra ID, create an **app registration** (for example `criofire-github-signing`).
6. On it, add a **federated credential** for GitHub Actions:
   - Organization / repository: `<owner>/criofire`
   - Entity type: **Environment**, name: `release`
   - This produces the subject `repo:<owner>/criofire:environment:release`, so no other
     branch, fork, pull request or workflow can obtain a token.
7. Give the app registration the **Artifact Signing Certificate Profile Signer** role on the
   certificate profile, and nothing else.

### GitHub

1. Settings -> Environments -> **New environment** named `release`.
2. **Required reviewers**: add yourself. Leave "Prevent self-review" off while you are the only maintainer.
3. **Deployment branches and tags**: "Selected branches and tags", add the tag rule `v*`.
4. Environment **secrets**: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`.
5. Environment **variables**:
   - `ARTIFACT_SIGNING_ENDPOINT` (from step 2 above)
   - `ARTIFACT_SIGNING_ACCOUNT`
   - `ARTIFACT_SIGNING_PROFILE`
   - `EXPECTED_PUBLISHER` (optional; defaults to `CrioSoft LLC`; set it to the exact organization
     name on the certificate if it differs, for example `CrioSoft, LLC`)
6. Protect `main` (Settings -> Rules): require pull requests and passing CI, block force pushes.
7. Protect tags `v*` so only maintainers can create them.
8. Require two-factor authentication for everyone with write access.

## Notes

- Azure signing certificates are short-lived and timestamped, so signatures stay valid after
  the certificate itself expires.
- A newly signed publisher still has little SmartScreen reputation; warnings fade as downloads grow.
- The MSI installer (WiX) is planned for Phase 1; Phase 0 releases ship signed zip files.
