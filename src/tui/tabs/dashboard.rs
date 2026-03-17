//! Dashboard tab -- status cards and memory gauge.

use crate::tui::theme;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
};

pub fn render(frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Status cards row
            Constraint::Length(5), // Memory gauge
            Constraint::Min(0),    // Info area
        ])
        .split(area);

    // Status cards
    let card_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[0]);

    let cards = [
        ("Gateway", "Connecting...", theme::WARNING),
        ("Provider", "---", theme::FG_DIM),
        ("Memory", "---", theme::FG_DIM),
        ("Uptime", "---", theme::FG_DIM),
    ];

    for (i, (title, value, color)) in cards.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER))
            .title(format!(" {title} "));
        let paragraph = Paragraph::new(*value)
            .style(Style::default().fg(*color).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(block);
        frame.render_widget(paragraph, card_chunks[i]);
    }

    // Memory gauge
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Memory Usage "),
        )
        .gauge_style(Style::default().fg(theme::ACCENT_SECONDARY))
        .percent(0)
        .label("No data");
    frame.render_widget(gauge, chunks[1]);

    // Info area
    let info = Paragraph::new(vec![
        Line::from("Connect to gateway to see live data."),
        Line::from(""),
        Line::from("Use Tab/Shift+Tab to switch between tabs."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::BORDER))
            .title(" Info "),
    )
    .style(Style::default().fg(theme::FG_DIM));
    frame.render_widget(info, chunks[2]);
}
