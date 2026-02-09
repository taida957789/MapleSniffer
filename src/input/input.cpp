#include "input.h"
#include <iostream>
#include <thread>
#include <chrono>

namespace maple {

void Input::pressKey(int virtualKeyCode) {
    // TODO: Implement using Windows SendInput API
    std::cout << "[Input] pressKey stub: VK=" << virtualKeyCode << std::endl;
}

void Input::releaseKey(int virtualKeyCode) {
    // TODO: Implement using Windows SendInput API
    std::cout << "[Input] releaseKey stub: VK=" << virtualKeyCode << std::endl;
}

void Input::tapKey(int virtualKeyCode, int delayMs) {
    pressKey(virtualKeyCode);
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    releaseKey(virtualKeyCode);
}

} // namespace maple
