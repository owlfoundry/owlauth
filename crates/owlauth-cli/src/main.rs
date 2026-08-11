#![forbid(unsafe_code)]

mod control;
mod remote;
mod update;

use std::{error::Error, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "owlauth",
    version,
    about = "Command-line interface for OwlAuth"
)]
struct Cli {
    /// Saved endpoint profile used by remote commands.
    #[arg(long, global = true)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover, pin, and select remote endpoint profiles.
    Profile(ProfileArgs),
    /// Read authenticated self-hosted system capabilities.
    System,
    /// Manage self-hosted Projects and Project policy.
    Project(control::ProjectArgs),
    /// Manage Project-scoped customer-backend server keys.
    ServerKey(control::ServerKeyArgs),
    /// Manage self-hosted Applications.
    Application(control::ApplicationArgs),
    /// Manage self-hosted upstream providers.
    Provider(control::ProviderArgs),
    /// Manage self-hosted Project signing keys.
    SigningKey(control::SigningKeyArgs),
    /// Manage webhook endpoints and inspect deliveries.
    Webhook(control::WebhookArgs),
    /// Update this CLI from an `OwlAuth` GitHub Release.
    Update(update::UpdateArgs),
}

#[derive(Debug, Args)]
struct ProfileArgs {
    #[command(subcommand)]
    command: ProfileCommand,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Discover an endpoint and save its confirmed identity pin.
    Add {
        name: String,
        #[arg(long)]
        endpoint: String,
        /// Environment variable that will provide the credential, never the credential itself.
        #[arg(long)]
        credential_env: Option<String>,
        /// Confirm the displayed discovery result.
        #[arg(long)]
        yes: bool,
    },
    /// Show a saved profile without reading its credential.
    Inspect {
        /// Profile name; defaults to the selected profile.
        name: Option<String>,
    },
    /// Validate current discovery against a saved identity pin.
    Check {
        /// Profile name; defaults to the selected profile.
        name: Option<String>,
    },
    /// Validate and select a saved profile as the default.
    Use { name: String },
    /// Explicitly replace an endpoint identity pin and credential reference.
    Rebind {
        name: String,
        #[arg(long)]
        endpoint: String,
        /// New environment-variable reference; it must differ from the old reference.
        #[arg(long)]
        credential_env: String,
        /// Confirm the displayed old and new identities.
        #[arg(long)]
        yes: bool,
    },
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Some(Command::Profile(arguments)) => match arguments.command {
            ProfileCommand::Add {
                name,
                endpoint,
                credential_env,
                yes,
            } => remote::add_profile(&name, &endpoint, credential_env.as_deref(), yes)?,
            ProfileCommand::Inspect { name } => {
                remote::inspect_profile(name.as_deref().or(cli.profile.as_deref()))?;
            }
            ProfileCommand::Check { name } => {
                remote::check_profile(name.as_deref().or(cli.profile.as_deref()))?;
            }
            ProfileCommand::Use { name } => remote::use_profile(&name)?,
            ProfileCommand::Rebind {
                name,
                endpoint,
                credential_env,
                yes,
            } => remote::rebind_profile(&name, &endpoint, &credential_env, yes)?,
        },
        Some(Command::System) => remote::system(cli.profile.as_deref())?,
        Some(Command::Project(args)) => control::run_project(cli.profile.as_deref(), args)?,
        Some(Command::ServerKey(args)) => {
            control::run_server_key(cli.profile.as_deref(), args)?;
        }
        Some(Command::Application(args)) => {
            control::run_application(cli.profile.as_deref(), args)?;
        }
        Some(Command::Provider(args)) => control::run_provider(cli.profile.as_deref(), args)?,
        Some(Command::SigningKey(args)) => {
            control::run_signing_key(cli.profile.as_deref(), args)?;
        }
        Some(Command::Webhook(args)) => control::run_webhook(cli.profile.as_deref(), args)?,
        Some(Command::Update(args)) => update::run(&args)?,
        None => {
            Cli::command().print_help()?;
            println!();
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("owlauth: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_key_commands_require_complete_lifecycle_arguments() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        const KEY: &str = "22222222-2222-4222-8222-222222222222";
        assert!(Cli::try_parse_from(["owlauth", "server-key", "list", PROJECT]).is_ok());
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "server-key",
                "create",
                PROJECT,
                "--label",
                "customer-backend",
                "--idempotency-key",
                "server_key_create_1",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "server-key",
                "acknowledge",
                PROJECT,
                KEY,
                "--expected-revision",
                "1",
                "--idempotency-key",
                "server_key_acknowledge_1",
                "--yes",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "server-key",
                "revoke",
                PROJECT,
                KEY,
                "--expected-revision",
                "1",
                "--idempotency-key",
                "server_key_revoke_1",
                "--yes",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "server-key",
                "revoke",
                PROJECT,
                KEY,
                "--expected-revision",
                "0",
                "--idempotency-key",
                "server_key_revoke_1",
                "--yes",
            ])
            .is_err()
        );
    }

    #[test]
    fn project_lifecycle_commands_require_security_revisions() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        for transition in ["disable", "enable", "delete"] {
            assert!(
                Cli::try_parse_from([
                    "owlauth",
                    "project",
                    transition,
                    PROJECT,
                    "--expected-security-revision",
                    "2",
                    "--yes",
                ])
                .is_ok()
            );
            assert!(
                Cli::try_parse_from(["owlauth", "project", transition, PROJECT, "--yes",]).is_err()
            );
        }
    }

    #[test]
    fn project_user_directory_commands_parse_closed_arguments() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        const USER: &str = "22222222-2222-4222-8222-222222222222";
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "project",
                "user",
                "list",
                PROJECT,
                "--status",
                "disabled",
                "--search",
                "Ada Lovelace",
                "--identity",
                "provider",
                "--provider-key",
                "workforce",
                "--sort",
                "created-oldest",
                "--cursor",
                USER,
                "--limit",
                "25",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "project",
                "user",
                "lookup-email",
                PROJECT,
                "--email",
                "User@EXAMPLE.COM",
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "project",
                "user",
                "list",
                PROJECT,
                "--provider-key",
                "workforce",
            ])
            .is_err()
        );
        for (option, value) in [
            ("--status", "unknown"),
            ("--identity", "subject"),
            ("--sort", "display-name"),
        ] {
            assert!(
                Cli::try_parse_from(
                    ["owlauth", "project", "user", "list", PROJECT, option, value,]
                )
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from(["owlauth", "project", "user", "lookup-email", PROJECT]).is_err()
        );
    }

    #[test]
    fn server_key_acknowledgement_refuses_before_profile_or_credential_access() {
        let cli = Cli::try_parse_from([
            "owlauth",
            "server-key",
            "acknowledge",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "--expected-revision",
            "1",
            "--idempotency-key",
            "server_key_acknowledge_1",
        ])
        .expect("valid command shape");
        let error = run(cli).expect_err("missing confirmation must fail first");
        assert!(error.to_string().contains("explicit --yes confirmation"));
    }

    #[test]
    fn rebind_requires_an_explicit_new_credential_reference() {
        assert!(
            Cli::try_parse_from([
                "owlauth",
                "profile",
                "rebind",
                "local",
                "--endpoint",
                "https://admin.example.com",
                "--yes",
            ])
            .is_err()
        );
    }

    #[test]
    fn high_impact_commands_refuse_before_profile_or_credential_access() {
        let cli = Cli::try_parse_from([
            "owlauth",
            "project",
            "policy",
            "set",
            "11111111-1111-4111-8111-111111111111",
            "--access-token-lifetime-seconds",
            "900",
            "--browser-session-reuse",
            "false",
            "--expected-claims-revision",
            "1",
            "--expected-session-revision",
            "1",
        ])
        .unwrap();
        let error = run(cli).unwrap_err();
        assert!(error.to_string().contains("explicit --yes confirmation"));
    }

    #[test]
    fn replacement_policy_booleans_require_explicit_true_or_false_values() {
        let project_policy = |value: Option<&str>| {
            let mut arguments = vec![
                "owlauth",
                "project",
                "policy",
                "set",
                "11111111-1111-4111-8111-111111111111",
                "--access-token-lifetime-seconds",
                "900",
            ];
            if let Some(value) = value {
                arguments.extend(["--browser-session-reuse", value]);
            }
            arguments.extend([
                "--expected-claims-revision",
                "1",
                "--expected-session-revision",
                "1",
                "--yes",
            ]);
            Cli::try_parse_from(arguments)
        };
        assert!(project_policy(None).is_err());
        assert!(project_policy(Some("true")).is_ok());
        assert!(project_policy(Some("false")).is_ok());
    }

    #[test]
    fn new_high_impact_commands_refuse_before_profile_or_credential_access() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        const APPLICATION: &str = "22222222-2222-4222-8222-222222222222";
        const TARGET: &str = "33333333-3333-4333-8333-333333333333";
        let commands = [
            vec![
                "owlauth",
                "project",
                "user",
                "disable",
                PROJECT,
                TARGET,
                "--expected-security-revision",
                "1",
            ],
            vec![
                "owlauth",
                "project",
                "user",
                "revoke-application-session",
                PROJECT,
                TARGET,
                APPLICATION,
                "--expected-session-revision",
                "1",
            ],
            vec![
                "owlauth",
                "webhook",
                "endpoint",
                "update",
                PROJECT,
                APPLICATION,
                TARGET,
                "--event",
                "created",
                "--expected-revision",
                "1",
            ],
            vec![
                "owlauth",
                "webhook",
                "endpoint",
                "activate-secret-rotation",
                PROJECT,
                APPLICATION,
                TARGET,
                "2",
                "--expected-revision",
                "1",
                "--overlap-seconds",
                "600",
            ],
            vec![
                "owlauth",
                "webhook",
                "delivery",
                "replay",
                PROJECT,
                APPLICATION,
                TARGET,
            ],
            vec![
                "owlauth",
                "provider",
                "egress-set",
                PROJECT,
                "--mode",
                "allow-all",
                "--expected-revision",
                "1",
            ],
        ];
        for arguments in commands {
            let error = run(Cli::try_parse_from(arguments).unwrap()).unwrap_err();
            assert!(error.to_string().contains("explicit --yes confirmation"));
        }
    }

    #[test]
    fn provider_onboarding_commands_parse_closed_variants_and_reject_before_credentials() {
        const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
        for arguments in [
            vec!["owlauth", "provider", "egress-get", PROJECT],
            vec![
                "owlauth",
                "provider",
                "egress-set",
                PROJECT,
                "--mode",
                "exact-origins",
                "--exact-origin",
                "https://identity.example",
                "--expected-revision",
                "1",
                "--yes",
            ],
            vec![
                "owlauth",
                "provider",
                "preflight",
                PROJECT,
                "--provider-key",
                "workforce",
                "--issuer",
                "https://identity.example",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }

        let provider = |kind: &'static str, issuer: Option<&'static str>| {
            let mut arguments = vec![
                "owlauth",
                "provider",
                "create",
                PROJECT,
                "--kind",
                kind,
                "--provider-key",
                kind,
                "--display-name",
                "Provider",
                "--client-id",
                "client",
                "--client-secret-env",
                "OWLAUTH_TEST_PROVIDER_SECRET",
                "--expected-project-revision",
                "1",
                "--idempotency-key",
                "provider_create_1",
            ];
            if let Some(issuer) = issuer {
                arguments.extend(["--issuer", issuer]);
            }
            Cli::try_parse_from(arguments).expect("provider command should parse")
        };

        let _google_without_issuer = provider("google", None);
        for invalid in [
            provider("google", Some("https://accounts.google.com")),
            provider("oidc", None),
        ] {
            let error = run(invalid).unwrap_err();
            assert!(
                error.to_string().contains(
                    "Custom OIDC requires --issuer; named provider presets forbid --issuer"
                )
            );
        }
    }

    #[test]
    fn write_only_secrets_accept_only_environment_references() {
        let provider = [
            "owlauth",
            "provider",
            "create",
            "11111111-1111-4111-8111-111111111111",
            "--kind",
            "github",
            "--provider-key",
            "github",
            "--display-name",
            "GitHub",
            "--issuer",
            "https://github.com",
            "--client-id",
            "client",
            "--client-secret",
            "must-not-be-argv",
            "--expected-project-revision",
            "1",
            "--idempotency-key",
            "provider_create_1",
        ];
        assert!(Cli::try_parse_from(provider).is_err());

        let webhook_rotation = [
            "owlauth",
            "webhook",
            "endpoint",
            "prepare-secret-rotation",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "--secret",
            "must-not-be-argv",
            "--expected-revision",
            "1",
            "--idempotency-key",
            "webhook_rotate_1",
        ];
        assert!(Cli::try_parse_from(webhook_rotation).is_err());
    }
}
