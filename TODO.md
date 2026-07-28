# Maintainer setup TODO

## Required before the first `0.0.1` SDK releases

- [ ] Create or verify the `owlauth` npm organization and grant package publishing access for `@owlauth/client`.
- [ ] Create a short-lived npm automation or granular access token with permission to publish `@owlauth/client`.
- [ ] Create a PyPI account-scoped API token for the first upload of `owlauth-client`.
- [ ] Create a crates.io API token allowed to publish `owlauth-client`.
- [x] Add repository Actions secrets with `gh secret set NPM_TOKEN`, `gh secret set PYPI_API_TOKEN`, and `gh secret set CARGO_REGISTRY_TOKEN`. Enter values only at the secure prompt.
- [ ] Create the four `0.0.1` release branches from the latest `main`, one at a time, and verify each registry and GitHub Release before continuing.
- [ ] Configure npm trusted publishing for `@owlauth/client`, then remove `NPM_TOKEN` and update the workflow.
- [ ] Configure PyPI trusted publishing for `owlauth-client`, then remove `PYPI_API_TOKEN` and update the workflow.
- [ ] Adopt crates.io trusted publishing if it is available for the project; otherwise rotate and retain the least-privileged token.

## Documentation deployment

- [ ] Create a Cloudflare API token with permission to deploy Workers for the target account.
- [ ] Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub environment secrets for the `docs` environment.
- [ ] Let the first successful `main` deployment create the `owlauth-docs` Worker.
- [ ] Bind the desired custom domain to the `owlauth-docs` Worker in Cloudflare and add that URL to the GitHub repository metadata.
- [ ] Add environment protection or a deployment branch rule limiting `docs` deployments to `main`.

## Repository administration

- [ ] Enable private vulnerability reporting in GitHub repository security settings.
- [ ] Enable Dependabot alerts, security updates, and secret scanning with push protection where available.
- [ ] Add another organization owner before the project becomes operational to avoid a single-owner recovery risk.
- [ ] Review the rulesets after the first pull request and release to confirm required check names and bypass behavior.
- [ ] Decide the public package and command names for the future Rust CLI before adding its crate.
- [ ] Define and threat-model the server-side MCP transport before adding it to plugin manifests.
