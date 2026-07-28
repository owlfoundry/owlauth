# Maintainer setup TODO

## Initial registry publishing

- [x] Create or verify the `owlauth` npm organization and publish `@owlauth/client@0.0.1`.
- [x] Publish `owlauth-client==0.0.1` to PyPI with an account-scoped token.
- [x] Publish `owlauth-client@0.0.1` to crates.io with a scoped API token.
- [x] Publish Server, TypeScript, Python, and Rust `0.0.1` releases one at a time and verify every registry, tag, and GitHub Release.
- [x] Configure npm trusted publishing, remove `NPM_TOKEN`, and update the TypeScript workflow to use OIDC.
- [x] Retain token publishing for PyPI and crates.io by maintainer decision; rotate the least-privileged tokens when required.

## Documentation deployment

- [x] Create a Cloudflare API token with permission to deploy Workers for the target account.
- [x] Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub environment secrets for the `docs` environment.
- [ ] Let the first successful `main` deployment create the `owlauth-docs` Worker.
- [ ] Bind the desired custom domain to the `owlauth-docs` Worker in Cloudflare and add that URL to the GitHub repository metadata.
- [ ] Add environment protection or a deployment branch rule limiting `docs` deployments to `main`.

## Repository administration

- [x] Enable private vulnerability reporting in GitHub repository security settings.
- [x] Enable Dependabot alerts, security updates, and secret scanning with push protection where available.
- [ ] Add another organization owner before the project becomes operational to avoid a single-owner recovery risk.
- [ ] Review the rulesets after the first pull request and release to confirm required check names and bypass behavior.
- [ ] Decide the public package and command names for the future Rust CLI before adding its crate.
- [ ] Define and threat-model the server-side MCP transport before adding it to plugin manifests.
