//! Channels tab -- table of configured channels with status.

use crate::tui::theme;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Row, Table},
};

pub fn render(frame: &mut Frame, area: Rect) {
    let header = Row::new(vec!["Channel", "Status", "Type", "Last Message"])
        .style(Style::default().fg(theme::FG).add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows = vec![Row::new(vec!["CLI", "Active", "built-in", "---"])
        .style(Style::default().fg(theme::SUCCESS))];

    let widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
        Constraint::Percentage(40),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Channels "),
        )
        .row_highlight_style(Style::default().bg(theme::SURFACE));

    frame.render_widget(table, area);
}
