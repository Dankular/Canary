/// Map a browser KeyboardEvent.code string to a Linux KEY_* code.
/// Reference: https://www.kernel.org/doc/html/latest/input/event-codes.html
pub fn browser_code_to_linux(code: &str) -> Option<u16> {
    Some(match code {
        "Escape" => 1, "Digit1" => 2, "Digit2" => 3, "Digit3" => 4,
        "Digit4" => 5, "Digit5" => 6, "Digit6" => 7, "Digit7" => 8,
        "Digit8" => 9, "Digit9" => 10, "Digit0" => 11,
        "Minus" => 12, "Equal" => 13, "Backspace" => 14, "Tab" => 15,
        "KeyQ" => 16, "KeyW" => 17, "KeyE" => 18, "KeyR" => 19,
        "KeyT" => 20, "KeyY" => 21, "KeyU" => 22, "KeyI" => 23,
        "KeyO" => 24, "KeyP" => 25, "BracketLeft" => 26, "BracketRight" => 27,
        "Enter" => 28, "ControlLeft" => 29,
        "KeyA" => 30, "KeyS" => 31, "KeyD" => 32, "KeyF" => 33,
        "KeyG" => 34, "KeyH" => 35, "KeyJ" => 36, "KeyK" => 37,
        "KeyL" => 38, "Semicolon" => 39, "Quote" => 40, "Backquote" => 41,
        "ShiftLeft" => 42, "Backslash" => 43,
        "KeyZ" => 44, "KeyX" => 45, "KeyC" => 46, "KeyV" => 47,
        "KeyB" => 48, "KeyN" => 49, "KeyM" => 50,
        "Comma" => 51, "Period" => 52, "Slash" => 53, "ShiftRight" => 54,
        "NumpadMultiply" => 55, "AltLeft" => 56, "Space" => 57,
        "CapsLock" => 58,
        "F1" => 59, "F2" => 60, "F3" => 61, "F4" => 62, "F5" => 63,
        "F6" => 64, "F7" => 65, "F8" => 66, "F9" => 67, "F10" => 68,
        "NumLock" => 69, "ScrollLock" => 70,
        "F11" => 87, "F12" => 88,
        "ArrowUp" => 103, "ArrowLeft" => 105, "ArrowRight" => 106, "ArrowDown" => 108,
        "Insert" => 110, "Delete" => 111, "Home" => 102, "End" => 107,
        "PageUp" => 104, "PageDown" => 109,
        "ControlRight" => 97, "AltRight" => 100,
        "MetaLeft" | "MetaRight" => 125,
        _ => return None,
    })
}
