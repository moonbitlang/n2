extern crate getopts;

use anyhow::anyhow;
use n2::load;
use n2::progress;
use n2::trace;
use n2::work;
use std::path::Path;

fn run() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optopt("C", "", "chdir", "DIR");
    opts.optopt("d", "debug", "debug", "TOOL");
    opts.optflag("h", "help", "help");
    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        anyhow::bail!("TODO: help");
    }

    if let Some(debug) = matches.opt_str("d") {
        match debug.as_str() {
            "trace" => trace::open("trace.json")?,
            _ => anyhow::bail!("unknown -d {:?}", debug),
        }
    }

    if let Some(dir) = matches.opt_str("C") {
        let dir = Path::new(&dir);
        std::env::set_current_dir(dir).map_err(|err| anyhow!("chdir {:?}: {}", dir, err))?;
    }

    let load::State {
        mut graph,
        mut db,
        default,
        hashes: last_hashes,
        pools,
    } = trace::scope("load::read", load::read)?;

    let mut targets = Vec::new();
    for free in matches.free {
        let id = match graph.get_file_id(&free) {
            None => anyhow::bail!("unknown path requested: {:?}", free),
            Some(id) => id,
        };
        targets.push(id);
    }
    if targets.is_empty() {
        targets = default;
    }
    if targets.is_empty() {
        // TODO: build all?
        anyhow::bail!("no path specified and no default");
    }

    let mut progress = progress::RcProgress::new(progress::ConsoleProgress::new());

    let mut work = work::Work::new(&mut graph, &last_hashes, &mut db, &mut progress, pools);
    for target in targets {
        work.want_file(target);
    }
    trace::scope("work.run", || work.run())
}

fn main() {
    match run() {
        Ok(_) => {}
        Err(err) => {
            // The escape code here clears any leftover progress state,
            // see progress.rs.
            // TODO: clearing here should be handled by progress.rs (?)
            println!("\x1b[Jn2: error: {}", err);
        }
    }
    trace::close().unwrap();
}
