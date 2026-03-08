#ifndef LED_H
#define LED_H

namespace led {

// Take manual control of all 4 user LEDs (sets trigger to "none")
void init();

// Set LED 0-3 on or off
void set(int led_num, bool on);

// Turn all LEDs off and restore default triggers
void cleanup();

} // namespace led

#endif // LED_H
