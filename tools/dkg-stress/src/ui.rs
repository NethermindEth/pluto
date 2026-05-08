use ansi_to_tui::IntoText;
use anyhow::Result;
use ratatui::Frame;
use ratatui::crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEvent, MouseEventKind,
    },
    execute,
};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::logs::{enumerate_nodes, read_tail};
use crate::state::{ActivePane, App, Counts, RunState};
use crate::worker::{Killers, kill_all};

/// Maximum bytes read from the end of a log file per draw. 256KB gives
/// the user meaningful room to scroll back through a node's log while
/// bounding I/O regardless of total log size.
const LOG_TAIL_BYTES: u64 = 256 * 1024;

pub fn run_tui(
    config: Arc<Config>,
    app: Arc<Mutex<App>>,
    stop: Arc<AtomicBool>,
    killers: Killers,
    workers_done: impl Fn() -> bool,
) -> Result<()> {
    let mut terminal = ratatui::init();
    if let Err(err) = execute!(io::stdout(), EnableMouseCapture) {
        ratatui::restore();
        return Err(err.into());
    }
    let result = event_loop(&mut terminal, &config, &app, &stop, &killers, workers_done);
    let _ = execute!(io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    config: &Config,
    app: &Mutex<App>,
    stop: &AtomicBool,
    killers: &Killers,
    workers_done: impl Fn() -> bool,
) -> Result<()> {
    let tick = Duration::from_millis(config.tick_ms);
    let mut next_tick = Instant::now() + tick;
    let mut table_state = TableState::default();
    let mut completed = false;

    loop {
        // External shutdown (SIGINT/SIGTERM/SIGHUP from the signal handler
        // installed in main). Mirror the in-TUI quit path: SIGTERM the
        // in-flight ceremonies, then return so ratatui::restore() runs.
        if stop.load(Ordering::Relaxed) {
            kill_all(killers, Duration::from_secs(5));
            return Ok(());
        }

        terminal.draw(|frame| draw(frame, config, app, &mut table_state, completed))?;

        if workers_done() {
            completed = true;
            terminal.draw(|frame| draw(frame, config, app, &mut table_state, completed))?;
        }

        let now = Instant::now();
        let timeout = next_tick.saturating_duration_since(now);
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key)
                    if key.kind == KeyEventKind::Press
                        && handle_key(key.code, key.modifiers, config, app, stop, killers) =>
                {
                    return Ok(());
                }
                Event::Mouse(mouse) => handle_mouse(mouse, terminal, config, app)?,
                _ => {}
            }
        }
        if Instant::now() >= next_tick {
            next_tick = Instant::now() + tick;
        }
    }
}

/// Returns true if the caller should exit the event loop.
fn handle_key(
    code: KeyCode,
    mods: KeyModifiers,
    config: &Config,
    app: &Mutex<App>,
    stop: &AtomicBool,
    killers: &Killers,
) -> bool {
    let quit = matches!(code, KeyCode::Char('q') | KeyCode::Esc)
        || (code == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL));
    if quit {
        stop.store(true, Ordering::Relaxed);
        kill_all(killers, Duration::from_secs(5));
        return true;
    }

    let Ok(mut a) = app.lock() else {
        return false;
    };
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    match code {
        KeyCode::Tab | KeyCode::BackTab => a.toggle_pane(),
        KeyCode::Char('1') => a.focus_runs(),
        KeyCode::Char('2') => a.focus_logs(),
        KeyCode::Char('a') => a.follow_auto(),
        _ => match a.active_pane {
            ActivePane::Runs => handle_runs_key(code, &mut a),
            ActivePane::Logs => handle_logs_key(code, ctrl, config, &mut a),
        },
    }
    false
}

fn handle_runs_key(code: KeyCode, app: &mut App) {
    match code {
        KeyCode::Down | KeyCode::Char('j') => app.next_run(),
        KeyCode::Up | KeyCode::Char('k') => app.prev_run(),
        KeyCode::PageDown | KeyCode::Char('J') => app.next_run_page(10),
        KeyCode::PageUp | KeyCode::Char('K') => app.prev_run_page(10),
        KeyCode::Home => app.first_run(),
        KeyCode::End => app.last_run(),
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => app.focus_logs(),
        _ => {}
    }
}

fn handle_logs_key(code: KeyCode, ctrl: bool, config: &Config, app: &mut App) {
    match code {
        KeyCode::Left | KeyCode::Char('h') => {
            let tabs = tab_count_for(config, app, app.selected_run);
            app.prev_tab(tabs);
        }
        KeyCode::Right | KeyCode::Char('l') => {
            let tabs = tab_count_for(config, app, app.selected_run);
            app.next_tab(tabs);
        }
        KeyCode::Up | KeyCode::Char('k') => app.scroll_log_up(1),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_log_down(1),
        KeyCode::PageUp => app.scroll_log_up(20),
        KeyCode::PageDown => app.scroll_log_down(20),
        KeyCode::Char('u') if ctrl => app.scroll_log_up(10),
        KeyCode::Char('d') if ctrl => app.scroll_log_down(10),
        KeyCode::Char('b') if ctrl => app.scroll_log_up(20),
        KeyCode::Char('f') if ctrl => app.scroll_log_down(20),
        KeyCode::Home | KeyCode::Char('g') => app.scroll_log_to_top(),
        KeyCode::End | KeyCode::Char('G') => app.scroll_log_to_tail(),
        _ => {}
    }
}

fn handle_mouse(
    mouse: MouseEvent,
    terminal: &ratatui::DefaultTerminal,
    config: &Config,
    app: &Mutex<App>,
) -> Result<()> {
    let size = terminal.size()?;
    let areas = ui_areas(Rect::new(0, 0, size.width, size.height));
    let pos = Position {
        x: mouse.column,
        y: mouse.row,
    };

    let Ok(mut a) = app.lock() else {
        return Ok(());
    };
    let target = pane_at(areas, pos).unwrap_or(a.active_pane);
    match mouse.kind {
        MouseEventKind::Down(_) => match target {
            ActivePane::Runs => a.focus_runs(),
            ActivePane::Logs => a.focus_logs(),
        },
        MouseEventKind::ScrollUp => match target {
            ActivePane::Runs => {
                a.focus_runs();
                a.prev_run();
            }
            ActivePane::Logs => {
                a.focus_logs();
                a.scroll_log_up(3);
            }
        },
        MouseEventKind::ScrollDown => match target {
            ActivePane::Runs => {
                a.focus_runs();
                a.next_run();
            }
            ActivePane::Logs => {
                a.focus_logs();
                a.scroll_log_down(3);
            }
        },
        MouseEventKind::ScrollLeft if target == ActivePane::Logs => {
            a.focus_logs();
            let tabs = tab_count_for(config, &a, a.selected_run);
            a.prev_tab(tabs);
        }
        MouseEventKind::ScrollRight if target == ActivePane::Logs => {
            a.focus_logs();
            let tabs = tab_count_for(config, &a, a.selected_run);
            a.next_tab(tabs);
        }
        _ => {}
    }
    Ok(())
}

fn pane_at(areas: UiAreas, pos: Position) -> Option<ActivePane> {
    if areas.list.contains(pos) {
        Some(ActivePane::Runs)
    } else if areas.detail.contains(pos) {
        Some(ActivePane::Logs)
    } else {
        None
    }
}

fn tab_count_for(config: &Config, app: &App, run_idx: usize) -> usize {
    let Some(state) = app.runs.get(run_idx) else {
        return 1;
    };
    if matches!(state, RunState::Pending) {
        return 1; // run.log only (and it'll show "not started")
    }
    let run_dir = run_dir_for(config, run_idx);
    1 + enumerate_nodes(&run_dir).len()
}

fn run_dir_for(config: &Config, run_idx: usize) -> PathBuf {
    config
        .work_dir
        .join(format!("run-{:04}", run_idx.saturating_add(1)))
}

#[derive(Clone, Copy)]
struct UiAreas {
    header: Rect,
    list: Rect,
    detail: Rect,
    footer: Rect,
}

#[derive(Clone, Copy)]
struct DetailView {
    selected_run: usize,
    selected_tab: usize,
    active: bool,
    log_scroll: usize,
}

fn ui_areas(area: Rect) -> UiAreas {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(8),
        Constraint::Length(3),
    ])
    .areas(area);
    let [list, detail] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(body);
    UiAreas {
        header,
        list,
        detail,
        footer,
    }
}

fn draw(
    frame: &mut Frame,
    config: &Config,
    app: &Mutex<App>,
    table_state: &mut TableState,
    completed: bool,
) {
    // Take everything we need from app under a single short lock, then
    // release it before doing file I/O. That keeps worker threads from
    // stalling on the lock during draws.
    let (snapshot, counts, active_pane, selected_run, selected_tab, manual_select, log_scroll) = {
        let mut a = match app.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        a.auto_advance_selection();
        (
            a.runs.clone(),
            a.counts(),
            a.active_pane,
            a.selected_run,
            a.selected_tab,
            a.manual_select,
            a.log_scroll,
        )
    };
    let now = Instant::now();

    let areas = ui_areas(frame.area());

    frame.render_widget(header(config), areas.header);

    render_run_list(
        frame,
        areas.list,
        &snapshot,
        selected_run,
        active_pane == ActivePane::Runs,
        now,
        table_state,
    );
    let final_log_scroll = render_detail(
        frame,
        areas.detail,
        config,
        &snapshot,
        DetailView {
            selected_run,
            selected_tab,
            active: active_pane == ActivePane::Logs,
            log_scroll,
        },
    );

    // Clamp the stored scroll back to whatever the renderer ended up using
    // (lines available, screen height, etc.) so a future user keystroke
    // operates on the actual offset rather than usize::MAX/2.
    if final_log_scroll != log_scroll
        && let Ok(mut a) = app.lock()
    {
        a.log_scroll = final_log_scroll;
    }

    frame.render_widget(
        footer(counts, active_pane, manual_select, log_scroll, completed),
        areas.footer,
    );
}

fn header(config: &Config) -> Paragraph<'_> {
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled("DKG stress test", Style::new().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "   runs={}  workers={}  work_dir={}",
                config.runs,
                config.workers,
                config.work_dir.display()
            )),
        ]),
        Line::from(Span::styled(
            "Tab/click=focus · wheel=scroll active pane · a=auto · q=quit",
            Style::new().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "runs: j/k/Pg/Home/End · logs: j/k/Pg/Ctrl-u/d scroll, h/l tabs, g/G top/tail",
            Style::new().fg(Color::DarkGray),
        )),
    ])
    .block(Block::default().borders(Borders::ALL))
}

fn render_run_list(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    snapshot: &[RunState],
    selected: usize,
    active: bool,
    now: Instant,
    table_state: &mut TableState,
) {
    let rows: Vec<Row> = snapshot
        .iter()
        .enumerate()
        .map(|(i, state)| run_row(i + 1, *state, now))
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(7),
    ];

    let block = active_block(" runs ", active);
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec![
                Cell::from("run").style(Style::new().add_modifier(Modifier::BOLD)),
                Cell::from("status").style(Style::new().add_modifier(Modifier::BOLD)),
                Cell::from("time").style(Style::new().add_modifier(Modifier::BOLD)),
            ])
            .bottom_margin(0),
        )
        .block(block)
        .column_spacing(2)
        .row_highlight_style(Style::new().bg(Color::DarkGray));

    table_state.select(Some(selected.min(snapshot.len().saturating_sub(1))));
    frame.render_stateful_widget(table, area, table_state);
}

fn active_block(title: &'static str, active: bool) -> Block<'static> {
    let block = Block::default().borders(Borders::ALL).title(title);
    if active {
        block.border_style(active_border_style())
    } else {
        block
    }
}

fn active_border_style() -> Style {
    Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
}

/// Returns the clamped log_scroll value actually used for rendering, so
/// the caller can persist it back into App state.
fn render_detail(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    config: &Config,
    snapshot: &[RunState],
    view: DetailView,
) -> usize {
    let label = format!("run-{:04}", view.selected_run.saturating_add(1));
    let run_dir = run_dir_for(config, view.selected_run);
    let state = snapshot
        .get(view.selected_run)
        .copied()
        .unwrap_or(RunState::Pending);

    let nodes = enumerate_nodes(&run_dir);
    let mut tab_titles: Vec<String> = Vec::with_capacity(1 + nodes.len());
    tab_titles.push("run.log".into());
    for n in &nodes {
        if let Some(name) = n.file_name().and_then(|s| s.to_str()) {
            tab_titles.push(name.to_string());
        }
    }

    let tab_count = tab_titles.len();
    let active_tab = view.selected_tab.min(tab_count.saturating_sub(1));

    let scroll_suffix = if view.log_scroll == 0 {
        String::new()
    } else {
        format!("  [+{} lines]", view.log_scroll)
    };
    let block = Block::default().borders(Borders::ALL).title(format!(
        " {} — {}{} ",
        label,
        status_short(state),
        scroll_suffix
    ));
    let block = if view.active {
        block.border_style(active_border_style())
    } else {
        block
    };
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [tabs_area, content_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).areas(inner);

    let tabs = Tabs::new(
        tab_titles
            .iter()
            .map(|t| Line::from(t.as_str()))
            .collect::<Vec<_>>(),
    )
    .select(active_tab)
    .style(Style::new().fg(Color::Gray))
    .highlight_style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    .divider(" │ ");
    frame.render_widget(tabs, tabs_area);

    let log_path = if active_tab == 0 {
        run_dir.join("run.log")
    } else {
        let n = active_tab.saturating_sub(1);
        nodes
            .get(n)
            .cloned()
            .unwrap_or_else(|| run_dir.clone())
            .join("node.log")
    };

    let (body, used_scroll) = log_body(
        &log_path,
        state,
        content_area.width,
        content_area.height,
        view.log_scroll,
    );
    frame.render_widget(body, content_area);
    used_scroll
}

/// Renders the log pane body. Returns the actual scroll offset used
/// (clamped to available content) so the caller can persist it.
fn log_body(
    path: &std::path::Path,
    state: RunState,
    width: u16,
    height: u16,
    scroll: usize,
) -> (Paragraph<'static>, usize) {
    if matches!(state, RunState::Pending) {
        let p = Paragraph::new(Line::from(Span::styled(
            "(run not started yet)",
            Style::new().fg(Color::DarkGray),
        )));
        return (p, 0);
    }
    let raw = match read_tail(path, LOG_TAIL_BYTES) {
        Some(s) if !s.is_empty() => s,
        _ => {
            let msg = if path.exists() {
                "(log file is empty)"
            } else if matches!(state, RunState::Pass { .. }) {
                "(log pruned — passed run with KEEP_PASSED off)"
            } else {
                "(log file not found)"
            };
            let p = Paragraph::new(Line::from(Span::styled(
                msg,
                Style::new().fg(Color::DarkGray),
            )));
            return (p, 0);
        }
    };

    let window = height.max(1) as usize;
    let text = match raw.into_text() {
        Ok(text) => text,
        Err(_) => Text::from(raw),
    };

    // `scroll` is stored as "lines back from the tail" so 0 keeps live
    // output pinned to the bottom. Ratatui's paragraph scroll is top-based,
    // after wrapping, so convert the tail-relative value at render time.
    let total = wrapped_height(&text, width);
    let max_scroll = total.saturating_sub(window);
    let used_scroll = scroll.min(max_scroll);
    let top_offset = max_scroll.saturating_sub(used_scroll);
    let top_offset = u16::try_from(top_offset).unwrap_or(u16::MAX);

    (
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((top_offset, 0)),
        used_scroll,
    )
}

fn wrapped_height(text: &Text<'_>, width: u16) -> usize {
    let width = usize::from(width.max(1));
    text.lines
        .iter()
        .map(|line| {
            let rows = line.width().saturating_add(width.saturating_sub(1)) / width;
            rows.max(1)
        })
        .sum()
}

fn run_row(id: usize, state: RunState, now: Instant) -> Row<'static> {
    let label = format!("run-{:04}", id);
    let (status_span, time_text) = match state {
        RunState::Pending => (
            Span::styled("pending", Style::new().fg(Color::DarkGray)),
            String::new(),
        ),
        RunState::Running { started_at } => {
            let elapsed = now.saturating_duration_since(started_at).as_secs();
            (
                Span::styled("running", Style::new().fg(Color::Yellow)),
                format!("{:>4}s", elapsed),
            )
        }
        RunState::Pass { duration_s } => (
            Span::styled(
                "PASS",
                Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            format!("{:>4}s", duration_s),
        ),
        RunState::Fail { duration_s } => (
            Span::styled(
                "FAIL",
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            format!("{:>4}s", duration_s),
        ),
    };
    Row::new(vec![
        Cell::from(label),
        Cell::from(Line::from(status_span)),
        Cell::from(time_text),
    ])
}

fn status_short(state: RunState) -> &'static str {
    match state {
        RunState::Pending => "pending",
        RunState::Running { .. } => "running",
        RunState::Pass { .. } => "PASS",
        RunState::Fail { .. } => "FAIL",
    }
}

fn footer(
    counts: Counts,
    active_pane: ActivePane,
    manual: bool,
    log_scroll: usize,
    completed: bool,
) -> Paragraph<'static> {
    let pane = match active_pane {
        ActivePane::Runs => Span::styled("  pane:runs", Style::new().fg(Color::Cyan)),
        ActivePane::Logs => Span::styled("  pane:logs", Style::new().fg(Color::Cyan)),
    };
    let follow = if manual {
        Span::styled("  manual", Style::new().fg(Color::Magenta))
    } else {
        Span::styled("  auto", Style::new().fg(Color::DarkGray))
    };
    let scroll_hint = if log_scroll == 0 {
        Span::styled("  tail", Style::new().fg(Color::DarkGray))
    } else {
        Span::styled(
            format!("  log:+{log_scroll}"),
            Style::new().fg(Color::Magenta),
        )
    };
    let done_hint = if completed {
        Span::styled("  done q=exit", Style::new().fg(Color::Green))
    } else {
        Span::raw("")
    };
    let line = Line::from(vec![
        Span::styled(
            "PASS ",
            Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{}", counts.passed)),
        Span::raw("   "),
        Span::styled(
            "FAIL ",
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{}", counts.failed)),
        Span::raw("   "),
        Span::styled("run ", Style::new().fg(Color::Yellow)),
        Span::raw(format!("{}", counts.running)),
        Span::raw("   "),
        Span::styled("pend ", Style::new().fg(Color::DarkGray)),
        Span::raw(format!("{}", counts.pending)),
        Span::raw(format!("   {}/{}", counts.done(), counts.total())),
        pane,
        follow,
        scroll_hint,
        done_hint,
    ]);
    Paragraph::new(line).block(Block::default().borders(Borders::ALL).title(" summary "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_height_counts_empty_lines() {
        let text = Text::from("one\n\nthree");

        assert_eq!(wrapped_height(&text, 80), 3);
    }

    #[test]
    fn wrapped_height_counts_wrapped_rows() {
        let text = Text::from("1234567890\nabc");

        assert_eq!(wrapped_height(&text, 4), 4);
    }
}
