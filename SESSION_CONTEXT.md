# ZeroClaw Session Context — March 8 2026

## Repository
- Path: `/Users/ehushubhamshaw/Documents/zeroclaw`
- Branch: `Enabling_claw_to_do_multiple_responce` (also tagged `zeroclaw_homecomming`)
- HEAD: `bdecd6bb` — `feat(hardware): register board-info tools unconditionally; fix nucleo firmware build`
- Only uncommitted change: `firmware/zeroclaw-nucleo/Cargo.lock` (harmless lockfile)

## Build Commands

```bash
# Standard (no hardware)
cargo build

# With Pico/serial hardware support
cargo build --features hardware

# With Pico + Nucleo probe-rs support (live register reads) — current binary
cargo build --features hardware,probe

# Run agent
./target/debug/zeroclaw agent -m "your prompt"
```

> The binary currently on disk (`./target/debug/zeroclaw`) was built with `--features hardware,probe`.

## External Tools
- `mpremote`: `~/.local/bin/mpremote` — used by `device_exec` to run MicroPython on Pico
- `probe-rs` v0.31.0: `~/.cargo/bin/probe-rs` — used by `hardware_memory_read` for live Nucleo register reads

---

## Hardware Config — `~/.zeroclaw/config.toml` (peripherals section)

```toml
[[peripherals.boards]]
board = "pico"
transport = "serial"
path = "/dev/cu.usbmodem1101"
baud = 115200

[[peripherals.boards]]
board = "nucleo-f401re"
transport = "serial"
path = "/dev/cu.usbmodem1103"
baud = 115200
```

> **Port warning:** macOS re-assigns `usbmodemXXXX` on every replug.
> If a board stops responding: `ls /dev/cu.usbmodem*` → update path in `~/.zeroclaw/config.toml`. No rebuild needed.

---

## Physical Hardware

### Board 1 — Raspberry Pi Pico (alias `pico0`)
- Physical board: **Pico Breadboard Kit** (loose components on half-size breadboard, jumper-wired)
- Port: `/dev/cu.usbmodem1101`
- Runtime: MicroPython v1.27.0

| GPIO | Component | Notes |
|------|-----------|-------|
| GP25 | Onboard LED | Soldered, always works — no jumper needed |
| GP15 | Active buzzer | `Pin.OUT HIGH/LOW` only — **no PWM**, it's active not passive |
| GP16 | LED1 | Jumper-wired on breadboard |
| GP17 | LED2 | Jumper-wired |
| GP18 | LED3 | Jumper-wired |
| GP19 | LED4 | Jumper-wired |
| GP11 | Button K1 | Active LOW (reads 0 when pressed) |
| GP12 | Button K2 | Active LOW |
| GP13 | Button K3 | Active LOW |
| GP14 | Button K4 | Active LOW |
| GP26–28 | ADC0–2 | Spare analog |

### Board 2 — STM32 Nucleo-F401RE (alias `nucleo0`)
- Port: `/dev/cu.usbmodem1103`
- `hardware_board_info` / `hardware_memory_map` → work **without board connected** (static datasheet data)
- `hardware_memory_read` → requires board **physically connected** via USB (uses probe-rs ST-Link)
- GPIOA base: `0x4002_0000`, ODR at `0x4002_0014`
- Flash: `0x0800_0000`–`0x0807_FFFF` (512KB), RAM: `0x2000_0000`–`0x2001_FFFF` (128KB)

---

## Key Source Files Modified This Sprint

### `src/peripherals/mod.rs`
Added `create_board_info_tools()` — no feature gate, no serial port:
```rust
pub fn create_board_info_tools(config: &PeripheralsConfig) -> Vec<Box<dyn Tool>> {
    if !config.enabled || config.boards.is_empty() { return Vec::new(); }
    let board_names: Vec<String> = config.boards.iter().map(|b| b.board.clone()).collect();
    vec![
        Box::new(crate::tools::HardwareMemoryMapTool::new(board_names.clone())),
        Box::new(crate::tools::HardwareBoardInfoTool::new(board_names.clone())),
        Box::new(crate::tools::HardwareMemoryReadTool::new(board_names)),
    ]
}
```
**Root cause fixed:** These tools were previously inside `create_peripheral_tools()` which is `#[cfg(feature = "hardware")]` gated — so they were never loaded when the hardware feature was enabled.

### `src/agent/loop_.rs`
Both `run()` and `process_message_with_session()` now call `create_board_info_tools()` unconditionally after the hardware feature block.

### `firmware/zeroclaw-nucleo/Cargo.toml`
- Added `[workspace]` table (isolates from root workspace)
- Removed `strip = true` (was stripping `.text` → probe-rs couldn't find flash range)
- Added `cortex-m = { version = "0.7", features = ["inline-asm", "critical-section-single-core"] }`
- `debug = 2`

### `firmware/zeroclaw-nucleo/.cargo/config.toml` (created)
```toml
[target.thumbv7em-none-eabihf]
rustflags = ["-C", "link-arg=-Tlink.x", "-C", "link-arg=-Tdefmt.x"]
runner = "probe-rs run --chip STM32F401RETx"
```

### `Cargo.toml` (root)
Added `exclude` array for all firmware dirs to isolate them from root workspace.

### `~/.zeroclaw/hardware/devices/pico0.md`
Declarative pin map for Pico Breadboard Kit. Active buzzer on GP15 — no PWM.

### `~/.zeroclaw/hardware/HARDWARE.md`
Matching pin map + tool usage rules for the agent.

---

## Verified Working Demo Commands

```bash
# Pico — onboard LED
./target/debug/zeroclaw agent -m "blink the onboard LED 3 times"

# Pico — buzzer
./target/debug/zeroclaw agent -m "beep the buzzer once on pico0"

# Pico — countdown + victory tune (all 4 LEDs + buzzer)
./target/debug/zeroclaw agent -m "on pico0: blink all 4 LEDs and beep the buzzer at the same time, 3 times like a countdown, then play a victory tune on the buzzer"

# Nucleo — static datasheet (no board needed)
./target/debug/zeroclaw agent -m "what peripherals does the STM32F401 expose and what are their base addresses?"
./target/debug/zeroclaw agent -m "show me the upper and lower memory map of the nucleo board"

# Nucleo — live register read (board must be connected)
./target/debug/zeroclaw agent -m "read the current value of the GPIOA ODR register on nucleo0"
```

---

## Alert Escalation Demo Sequence

Run these in order — escalating LED + buzz pattern like a traffic alert:

```bash
./target/debug/zeroclaw agent -m "on pico0: light up LED1 and beep the buzzer once"
./target/debug/zeroclaw agent -m "on pico0: light up LED1 and LED2, then beep the buzzer twice"
./target/debug/zeroclaw agent -m "on pico0: light up LED1 LED2 and LED3, then beep the buzzer 3 times"
./target/debug/zeroclaw agent -m "on pico0: turn on all 4 LEDs and beep the buzzer 4 times fast — full alarm mode"
```

---

## Pending / Not Yet Done

- Telegram E2E tests (Section 8 of pre-Aardvark checklist)
- `crates/aardvark-sys` — Total Phase Aardvark USB I2C/SPI adapter; vendored `.so` is x86_64, needs arm64 build from totalphase.com or compile with `--target x86_64-apple-darwin`
- Button input demo (GP11–GP14 read)
- Internal temperature sensor demo (ADC4)
- Commit current working state to branch
