mod config;
mod blocklist;
mod resolver;

fn main() {
    // Load config
    let config = config::Config::load();
    // Initialize blocklist
    let blocklist = blocklist::Blocklist::load(&[config.blocklist_file.clone()]);
    // Start resolver
    resolver::start(&config, &blocklist);
}
