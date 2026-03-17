//! Terminal User Interface for ZeroClaw.
//!
//! Provides a rich terminal dashboard with tabs for status, channels,
//! chat, logs, and configuration. Enable with `--features tui`.

pub mod gateway_client;
pub mod tabs;
pub mod theme;

use anyhow::Result;

/// Which tab is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Dashboard,
    Channels,
    Chat,
    Logs,
    Config,
}

impl ActiveTab {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Channels => "Channels",
            Self::Chat => "Chat",
            Self::Logs => "Logs",
            Self::Config => "Config",
        }
    }

    pub fn all() -> &'static [ActiveTab] {
        &[
            Self::Dashboard,
            Self::Channels,
            Self::Chat,
            Self::Logs,
            Self::Config,
        ]
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Dashboard => Self::Channels,
            Self::Channels => Self::Chat,
            Self::Chat => Self::Logs,
            Self::Logs => Self::Config,
            Self::Config => Self::Dashboard,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Self::Dashboard => Self::Config,
            Self::Channels => Self::Dashboard,
            Self::Chat => Self::Channels,
            Self::Logs => Self::Chat,
            Self::Config => Self::Logs,
        }
    }
}

/// Main TUI application state.
pub struct TuiApp {
    active_tab: ActiveTab,
    gateway_url: String,
    token: Option<String>,
    session: Option<String>,
    should_quit: bool,
}

impl TuiApp {
    pub fn new(gateway_url: String, token: Option<String>, session: Option<String>) -> Self {
        Self {
            active_tab: ActiveTab::Dashboard,
            gateway_url,
            token,
            session,
            should_quit: false,
        }
    }

    /// Run the TUI event loop.
    #[allow(clippy::unused_async)]
    pub async fn run(&mut self) -> Result<()> {
        use crossterm::{
            event::{self, Event, KeyCode, KeyModifiers},
            execute,
            terminal::{
                disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
            },
        };
        use ratatui::prelude::*;

        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        while !self.should_quit {
            terminal.draw(|frame| {
                self.render(frame);
            })?;

            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match (key.modifiers, key.code) {
                        (KeyModifiers::CONTROL, KeyCode::Char('c')) | (_, KeyCode::Char('q')) => {
                            self.should_quit = true
                        }
                        (_, KeyCode::Tab) => self.active_tab = self.active_tab.next(),
                        (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                            self.active_tab = self.active_tab.prev();
                        }
                        _ => {}
                    }
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn render(&self, frame: &mut ratatui::Frame) {
        use ratatui::{
            prelude::*,
            widgets::{Block, Borders, Paragraph, Tabs},
        };

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tab bar
                Constraint::Min(0),    // Content
                Constraint::Length(1), // Status bar
            ])
            .split(frame.area());

        // Tab bar
        let titles: Vec<Line> = ActiveTab::all()
            .iter()
            .map(|t| {
                let style = if *t == self.active_tab {
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme::FG_DIM)
                };
                Line::from(t.label()).style(style)
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" ZeroClaw TUI "),
            )
            .highlight_style(Style::default().fg(theme::ACCENT))
            .select(
                ActiveTab::all()
                    .iter()
                    .position(|t| *t == self.active_tab)
                    .unwrap_or(0),
            );
        frame.render_widget(tabs, chunks[0]);

        // Content area -- dispatch to tab renderer
        let content_area = chunks[1];
        match self.active_tab {
            ActiveTab::Dashboard => tabs::dashboard::render(frame, content_area),
            ActiveTab::Channels => tabs::channels::render(frame, content_area),
            ActiveTab::Chat => tabs::chat::render(frame, content_area),
            ActiveTab::Logs => tabs::logs::render(frame, content_area),
            ActiveTab::Config => tabs::config::render(frame, content_area),
        }

        // Status bar
        let status = Paragraph::new(" Tab/Shift+Tab: switch tabs | q: quit | Ctrl+C: force quit")
            .style(Style::default().fg(theme::FG_DIM));
        frame.render_widget(status, chunks[2]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tab_cycling() {
        let tab = ActiveTab::Dashboard;
        assert_eq!(tab.next(), ActiveTab::Channels);
        assert_eq!(tab.next().next(), ActiveTab::Chat);
        assert_eq!(ActiveTab::Config.next(), ActiveTab::Dashboard);
    }

    #[test]
    fn test_tab_prev() {
        assert_eq!(ActiveTab::Dashboard.prev(), ActiveTab::Config);
        assert_eq!(ActiveTab::Channels.prev(), ActiveTab::Dashboard);
    }

    #[test]
    fn test_tab_labels() {
        assert_eq!(ActiveTab::Dashboard.label(), "Dashboard");
        assert_eq!(ActiveTab::Chat.label(), "Chat");
    }

    #[test]
    fn test_all_tabs() {
        assert_eq!(ActiveTab::all().len(), 5);
    }
}
