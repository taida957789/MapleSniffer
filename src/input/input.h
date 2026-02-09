#pragma once

namespace maple {

class Input {
public:
    // Stub: keyboard simulation interface
    // TODO: Implement SendInput-based key press simulation

    static void pressKey(int virtualKeyCode);
    static void releaseKey(int virtualKeyCode);
    static void tapKey(int virtualKeyCode, int delayMs = 50);
};

} // namespace maple
