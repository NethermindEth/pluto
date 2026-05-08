use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum RunState {
    Pending,
    Running { started_at: Instant },
    Pass { duration_s: u64 },
    Fail { duration_s: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivePane {
    Runs,
    Logs,
}

pub struct App {
    pub runs: Vec<RunState>,
    /// Which pane receives navigation and scroll input.
    pub active_pane: ActivePane,
    /// 0-based index of the run currently displayed in the detail pane.
    pub selected_run: usize,
    /// 0 = run.log, 1..=N = node-(idx-1)/node.log.
    pub selected_tab: usize,
    /// True once the user has navigated manually; suppresses auto-follow so
    /// the table doesn't yank focus away from what they're inspecting.
    pub manual_select: bool,
    /// Number of lines scrolled back from the tail of the active log. 0
    /// means "stick to the tail" (live updates appear). Grows as the user
    /// scrolls up; clamped on render to the available content. Reset on
    /// run/tab switch and on `G` / End.
    pub log_scroll: usize,
}

impl App {
    pub fn new(total: usize) -> Self {
        Self {
            runs: vec![RunState::Pending; total],
            active_pane: ActivePane::Runs,
            selected_run: 0,
            selected_tab: 0,
            manual_select: false,
            log_scroll: 0,
        }
    }

    pub fn focus_runs(&mut self) {
        self.active_pane = ActivePane::Runs;
        self.manual_select = true;
    }

    pub fn focus_logs(&mut self) {
        self.active_pane = ActivePane::Logs;
        self.manual_select = true;
    }

    pub fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Runs => ActivePane::Logs,
            ActivePane::Logs => ActivePane::Runs,
        };
        self.manual_select = true;
    }

    pub fn next_run(&mut self) {
        if self.runs.is_empty() {
            return;
        }
        if self.selected_run + 1 < self.runs.len() {
            self.selected_run += 1;
        }
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn prev_run(&mut self) {
        self.selected_run = self.selected_run.saturating_sub(1);
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn next_run_page(&mut self, page: usize) {
        let last = self.runs.len().saturating_sub(1);
        self.selected_run = self.selected_run.saturating_add(page).min(last);
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn prev_run_page(&mut self, page: usize) {
        self.selected_run = self.selected_run.saturating_sub(page);
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn first_run(&mut self) {
        self.selected_run = 0;
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn last_run(&mut self) {
        self.selected_run = self.runs.len().saturating_sub(1);
        self.manual_select = true;
        self.log_scroll = 0;
    }

    pub fn next_tab(&mut self, tab_count: usize) {
        if tab_count == 0 {
            return;
        }
        self.selected_tab = (self.selected_tab + 1) % tab_count;
        self.log_scroll = 0;
    }

    pub fn prev_tab(&mut self, tab_count: usize) {
        if tab_count == 0 {
            return;
        }
        self.selected_tab = if self.selected_tab == 0 {
            tab_count - 1
        } else {
            self.selected_tab - 1
        };
        self.log_scroll = 0;
    }

    pub fn scroll_log_up(&mut self, lines: usize) {
        self.log_scroll = self.log_scroll.saturating_add(lines);
        // Pin the selected run while reading scrollback so auto_advance
        // doesn't yank us to a different ceremony mid-scroll. `a` / `G`
        // re-engage auto-follow.
        self.manual_select = true;
    }

    pub fn scroll_log_down(&mut self, lines: usize) {
        self.log_scroll = self.log_scroll.saturating_sub(lines);
        self.manual_select = true;
    }

    pub fn scroll_log_to_tail(&mut self) {
        self.log_scroll = 0;
    }

    /// "Go to top" — set scroll past any sane document length; render code
    /// clamps to the actual line count.
    pub fn scroll_log_to_top(&mut self) {
        self.log_scroll = usize::MAX / 2;
        self.manual_select = true;
    }

    /// Re-engage auto-follow (selection tracks the active frontier again).
    pub fn follow_auto(&mut self) {
        self.manual_select = false;
        self.log_scroll = 0;
        self.active_pane = ActivePane::Runs;
    }

    /// If the user hasn't taken manual control, keep the selection on the
    /// most-recent active run. Resets log scroll when the focus moves so
    /// the live tail kicks back in.
    pub fn auto_advance_selection(&mut self) {
        if self.manual_select {
            return;
        }
        if let Some(idx) = self.focus_idx()
            && self.selected_run != idx
        {
            self.selected_run = idx;
            self.log_scroll = 0;
        }
    }

    pub fn counts(&self) -> Counts {
        let mut c = Counts::default();
        for state in &self.runs {
            match state {
                RunState::Pending => c.pending += 1,
                RunState::Running { .. } => c.running += 1,
                RunState::Pass { .. } => c.passed += 1,
                RunState::Fail { .. } => c.failed += 1,
            }
        }
        c
    }

    /// The largest 1-based run index that is no longer Pending. Used by the
    /// UI as the auto-scroll focus so the table follows the active frontier.
    pub fn focus_idx(&self) -> Option<usize> {
        self.runs
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, s)| (!matches!(s, RunState::Pending)).then_some(i))
    }
}

#[derive(Default, Clone, Copy)]
pub struct Counts {
    pub passed: usize,
    pub failed: usize,
    pub running: usize,
    pub pending: usize,
}

impl Counts {
    pub fn done(&self) -> usize {
        self.passed.saturating_add(self.failed)
    }
    pub fn total(&self) -> usize {
        self.passed
            .saturating_add(self.failed)
            .saturating_add(self.running)
            .saturating_add(self.pending)
    }
}
