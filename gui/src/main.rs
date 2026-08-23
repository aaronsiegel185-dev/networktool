//! nettool-gui - a desktop front end for the nettool network diagnostics CLI.
//!
//! The GUI never re-implements the diagnostics: it runs `nettool ... --json` on worker
//! threads and renders the results, so both interfaces always agree.
// A release build must not open a console window behind the GUI on Windows.
// Debug builds keep one, because --screenshot and the other CLI flags print
// there and losing that output would make the app harder to work on.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]


use eframe::egui;
use nettool_gui::app::Startup;
use nettool_gui::ui::analyze::View as AnalyzeView;
use nettool_gui::ui::wifi::View as WifiView;
use nettool_gui::{app, runner, ui};
use ui::Tab;

struct Options {
    tab: Tab,
    open_file: Option<String>,
    analyze_view: Option<AnalyzeView>,
    wifi_view: Option<WifiView>,
    screenshot: Option<String>,
    screenshot_delay: f32,
    autorun: bool,
    nettool: Option<String>,
    sudo: bool,
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        tab: Tab::Overview,
        open_file: None,
        analyze_view: None,
        wifi_view: None,
        screenshot: None,
        screenshot_delay: 3.0,
        autorun: false,
        nettool: None,
        sudo: false,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "nettool-gui - desktop GUI for nettool\n\n\
                     Options:\n  \
                     --tab <name>        open on a tab: overview, discover, scan, lldp, capture, mirror, analyze, wifi\n  \
                     --nettool <cmd>     how to run nettool (default: autodetect, e.g. \"python3 -m nettool\")\n  \
                     --sudo              run nettool through `sudo -n`\n  \
                     --wifi-view <name>  wifi sub-view: analyze, networks, link, monitor\n  \
                     --open <file.pcap>  open a capture in the analysis tab\n  \
                     --analyze-view <v>  conversations, endpoints, protocols, tcp, dns, throughput\n  \
                     --autorun           run the opening tab's action immediately\n  \
                     --screenshot <png>  render, save a PNG and exit (for docs/CI)\n  \
                     --screenshot-delay <seconds>  how long to let results load first\n"
                );
                std::process::exit(0);
            }
            "--tab" => {
                let value = argv.next().ok_or("--tab needs a value")?;
                options.tab = match value.to_ascii_lowercase().as_str() {
                    "overview" | "diag" => Tab::Overview,
                    "discover" => Tab::Discover,
                    "scan" => Tab::Scan,
                    "lldp" | "cdp" => Tab::Lldp,
                    "capture" => Tab::Capture,
                    "mirror" | "vlan" | "span" => Tab::Mirror,
                    "analyze" | "analyse" | "stats" => Tab::Analyze,
                    "wifi" | "wireless" => Tab::Wifi,
                    other => return Err(format!("unknown tab: {other}")),
                };
            }
            "--screenshot" => {
                options.screenshot = Some(argv.next().ok_or("--screenshot needs a path")?);
            }
            "--screenshot-delay" => {
                options.screenshot_delay = argv
                    .next()
                    .ok_or("--screenshot-delay needs a number")?
                    .parse()
                    .map_err(|_| "--screenshot-delay must be a number of seconds")?;
            }
            "--wifi-view" => {
                let value = argv.next().ok_or("--wifi-view needs a value")?;
                options.wifi_view = Some(match value.to_ascii_lowercase().as_str() {
                    "map" => WifiView::Map,
                    "analyze" | "analyse" => WifiView::Analyze,
                    "networks" | "scan" => WifiView::Scan,
                    "link" => WifiView::Link,
                    "monitor" => WifiView::Monitor,
                    other => return Err(format!("unknown wifi view: {other}")),
                });
            }
            "--open" => {
                options.open_file = Some(argv.next().ok_or("--open needs a file path")?);
                options.tab = Tab::Analyze;
            }
            "--analyze-view" => {
                let value = argv.next().ok_or("--analyze-view needs a value")?;
                options.analyze_view = Some(match value.to_ascii_lowercase().as_str() {
                    "conversations" | "conv" => AnalyzeView::Conversations,
                    "endpoints" => AnalyzeView::Endpoints,
                    "protocols" | "hierarchy" => AnalyzeView::Protocols,
                    "tcp" => AnalyzeView::Tcp,
                    "dns" => AnalyzeView::Dns,
                    "throughput" | "io" => AnalyzeView::Throughput,
                    other => return Err(format!("unknown analysis view: {other}")),
                });
            }
            "--autorun" => options.autorun = true,
            "--nettool" => {
                options.nettool = Some(argv.next().ok_or("--nettool needs a command")?);
            }
            "--sudo" => options.sudo = true,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    Ok(options)
}

fn main() -> eframe::Result<()> {
    let options = match parse_options() {
        Ok(options) => options,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let mut settings = match &options.nettool {
        Some(command) => runner::Settings {
            base: command.split_whitespace().map(|s| s.to_string()).collect(),
            use_sudo: false,
            working_dir: None,
        },
        None => runner::Settings::detect(),
    };
    settings.use_sudo = options.sudo;

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("nettool"),
        ..Default::default()
    };

    let startup = Startup {
        tab: options.tab,
        open_file: options.open_file.clone(),
        analyze_view: options.analyze_view,
        wifi_view: options.wifi_view,
        autorun: options.autorun,
        screenshot: options
            .screenshot
            .clone()
            .map(|path| (path, options.screenshot_delay)),
    };
    eframe::run_native(
        "nettool",
        native_options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            cc.egui_ctx.all_styles_mut(|style| {
                style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            });
            Ok(Box::new(app::App::new(settings, startup.clone())))
        }),
    )
}
