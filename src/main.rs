mod arch;
mod cli;
mod container;
mod exec;
mod image;
mod lifecycle;
mod network;
mod options;
mod runtime;
mod spec;
mod state;
mod supervisor;

use anyhow::Result;
use clap::Parser;

fn main() {
    let code = match real_main() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("miko: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn real_main() -> Result<i32> {
    let cli = cli::Cli::parse();
    let state_root = state::root(cli.state_dir.as_deref());
    let concurrency = cli.concurrency;
    match cli.command {
        cli::Command::Run(args) => container::run(&args, &state_root, concurrency),
        cli::Command::Pull(a) => image::store::pull_cmd(
            &state_root,
            &a.image,
            a.insecure_registry,
            a.platform.as_deref(),
            concurrency,
        ),
        cli::Command::Images(a) => image::store::images_cmd(
            &state_root,
            &image::store::ImagesOpts {
                quiet: a.quiet,
                digests: a.digests,
                no_trunc: a.no_trunc,
                filters: a.filters,
                format: a.format,
            },
        ),
        cli::Command::Rmi(a) => image::store::rmi_cmd(&state_root, &a.images, a.force),
        cli::Command::Tag(a) => image::store::tag_cmd(&state_root, &a.source, &a.target),
        cli::Command::Inspect(a) => image::store::inspect_cmd(&state_root, &a.images),
        cli::Command::Save(a) => {
            image::store::save_cmd(&state_root, &a.images, a.output.as_deref())
        }
        cli::Command::Load(a) => image::store::load_cmd(&state_root, a.input.as_deref(), &a.tags),
        cli::Command::Image(a) => match a.command {
            cli::ImageCommand::Prune(p) => {
                image::store::image_prune_cmd(&state_root, p.all, p.force, &p.filters)
            }
        },
        cli::Command::Network(a) => match a.command {
            cli::NetworkCommand::Create(c) => network::commands::create(&state_root, &c),
            cli::NetworkCommand::Ls(c) => network::commands::ls(&state_root, &c),
            cli::NetworkCommand::Inspect(c) => network::commands::inspect(&state_root, &c.networks),
            cli::NetworkCommand::Rm(c) => network::commands::rm(&state_root, &c.networks, c.force),
            cli::NetworkCommand::Prune(c) => {
                network::commands::prune(&state_root, c.force, &c.filters)
            }
            cli::NetworkCommand::Connect(c) => network::commands::connect(&state_root, &c),
            cli::NetworkCommand::Disconnect(c) => network::commands::disconnect(&state_root, &c),
        },
        cli::Command::Init(args) => {
            runtime::init_main(&args)?;
            Ok(0)
        }
        cli::Command::Ps(a) => lifecycle::ps(&state_root, a.all),
        cli::Command::Kill(a) => lifecycle::kill(&state_root, &a.id, a.signal.as_deref()),
        cli::Command::Rm(a) => lifecycle::rm(&state_root, &a.ids, a.force),
        cli::Command::Logs(a) => lifecycle::logs(&state_root, &a.id),
        cli::Command::Exec(a) => exec::exec(&state_root, &a),
        cli::Command::System(a) => match a.command {
            cli::SystemCommand::Prune => lifecycle::prune(&state_root),
        },
    }
}
