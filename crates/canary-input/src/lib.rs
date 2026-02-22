//! Linux evdev input emulation for /dev/input/event0.

use std::collections::VecDeque;

pub mod keycodes;

/// A Linux input_event (24 bytes on 64-bit).
#[derive(Debug, Clone, Copy)]
pub struct InputEvent {
    pub tv_sec:  u64,   // seconds
    pub tv_usec: u64,   // microseconds
    pub ev_type: u16,   // EV_KEY, EV_REL, EV_SYN, etc.
    pub code:    u16,   // key code, rel axis, etc.
    pub value:   i32,   // 1=press, 0=release, 2=repeat; or relative delta
}

impl InputEvent {
    pub const SIZE: usize = 24;

    /// Serialize to 24-byte little-endian buffer.
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&self.tv_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&self.tv_usec.to_le_bytes());
        buf[16..18].copy_from_slice(&self.ev_type.to_le_bytes());
        buf[18..20].copy_from_slice(&self.code.to_le_bytes());
        buf[20..24].copy_from_slice(&self.value.to_le_bytes());
        buf
    }

    /// EV_SYN separator event.
    pub fn syn() -> Self {
        InputEvent { tv_sec: 0, tv_usec: 0, ev_type: 0, code: 0, value: 0 }
    }
}

pub const EV_SYN: u16 = 0;
pub const EV_KEY: u16 = 1;
pub const EV_REL: u16 = 2;
pub const EV_ABS: u16 = 3;

pub const REL_X:     u16 = 0;
pub const REL_Y:     u16 = 1;
pub const REL_WHEEL: u16 = 8;

pub const BTN_LEFT:   u16 = 272;
pub const BTN_RIGHT:  u16 = 273;
pub const BTN_MIDDLE: u16 = 274;

/// Input event queue for /dev/input/event0.
pub struct InputCtx {
    /// Pending input events (serialized 24-byte records).
    pub event_queue: VecDeque<InputEvent>,
    /// Inode number for /dev/input/event0 in the VFS (0 if not registered).
    pub event0_ino: usize,
    /// Last seen mouse position (for relative motion calculation).
    pub last_mouse_x: i32,
    pub last_mouse_y: i32,
}

impl InputCtx {
    pub fn new() -> Self {
        InputCtx {
            event_queue: VecDeque::new(),
            event0_ino: 0,
            last_mouse_x: 0,
            last_mouse_y: 0,
        }
    }

    /// Push a key press/release event.
    pub fn key_event(&mut self, linux_keycode: u16, pressed: bool) {
        self.event_queue.push_back(InputEvent {
            tv_sec: 0, tv_usec: 0,
            ev_type: EV_KEY,
            code: linux_keycode,
            value: if pressed { 1 } else { 0 },
        });
        self.event_queue.push_back(InputEvent::syn());
    }

    /// Push a mouse button event.
    pub fn mouse_button(&mut self, btn: u16, pressed: bool) {
        self.event_queue.push_back(InputEvent {
            tv_sec: 0, tv_usec: 0,
            ev_type: EV_KEY, code: btn,
            value: if pressed { 1 } else { 0 },
        });
        self.event_queue.push_back(InputEvent::syn());
    }

    /// Push a mouse motion event (absolute position → relative delta).
    pub fn mouse_move(&mut self, abs_x: i32, abs_y: i32) {
        let dx = abs_x - self.last_mouse_x;
        let dy = abs_y - self.last_mouse_y;
        self.last_mouse_x = abs_x;
        self.last_mouse_y = abs_y;
        if dx != 0 {
            self.event_queue.push_back(InputEvent {
                tv_sec: 0, tv_usec: 0, ev_type: EV_REL, code: REL_X, value: dx,
            });
        }
        if dy != 0 {
            self.event_queue.push_back(InputEvent {
                tv_sec: 0, tv_usec: 0, ev_type: EV_REL, code: REL_Y, value: dy,
            });
        }
        if dx != 0 || dy != 0 {
            self.event_queue.push_back(InputEvent::syn());
        }
    }

    /// Read up to `max_bytes` of pending events into a byte buffer.
    /// Returns the number of bytes written (multiple of InputEvent::SIZE).
    pub fn read_events(&mut self, max_bytes: usize) -> Vec<u8> {
        let max_events = max_bytes / InputEvent::SIZE;
        let mut buf = Vec::with_capacity(max_events * InputEvent::SIZE);
        for _ in 0..max_events {
            match self.event_queue.pop_front() {
                Some(ev) => buf.extend_from_slice(&ev.to_bytes()),
                None => break,
            }
        }
        buf
    }

    pub fn has_events(&self) -> bool { !self.event_queue.is_empty() }
}

impl Default for InputCtx {
    fn default() -> Self {
        Self::new()
    }
}
