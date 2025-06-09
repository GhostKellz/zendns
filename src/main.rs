mod config;
mod blocklist;
mod resolver;

fn main() {
    // Load config
    let config = config::Config::load();
    // Initialize blocklist (async)
    let blocklist_sources = config.blocklist_sources.clone().unwrap_or_default();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let blocklist = rt.block_on(blocklist::Blocklist::load(&blocklist_sources));
    // Start resolver
    resolver::start(&config, &blocklist);
}
