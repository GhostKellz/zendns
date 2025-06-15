mod config;
mod blocklist;
mod resolver;

#[tokio::main]
async fn main() {
    // Load config
    let config = config::Config::load();
    // Initialize blocklist (async)
    let blocklist_sources = config.blocklist_sources.clone().unwrap_or_default();
    let blocklist = blocklist::Blocklist::load(&blocklist_sources).await;
    // Start resolver
    resolver::start(&config, &blocklist).await;
}
