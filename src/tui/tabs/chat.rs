//! Chat tab -- message list and text input.

use crate::tui::theme;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub fn render(frame: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),    // Messages
            Constraint::Length(3), // Input
        ])
        .split(area);

    // Messages area
    let messages = vec![Line::from(vec![
        Span::styled("system", Style::default().fg(theme::FG_DIM)),
        Span::raw(": Connect to gateway to start chatting."),
    ])];

    let messages_widget = Paragraph::new(messages)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Chat "),
        )
        .wrap(Wrap { trim: false })
        .style(Style::default().fg(theme::FG));
    frame.render_widget(messages_widget, chunks[0]);

    // Input area
    let input = Paragraph::new(" Type a message... (not connected)")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme::BORDER))
                .title(" Input "),
        )
        .style(Style::default().fg(theme::FG_DIM));
    frame.render_widget(input, chunks[1]);
}
