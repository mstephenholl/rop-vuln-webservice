#ifndef TEMPERATURE_H
#define TEMPERATURE_H

namespace temperature {

// Temperature thresholds (degrees Celsius)
const float MAX_SAFE     = 105.0f;
const float THIRD        = 35.0f;   // 1/3 of max
const float TWO_THIRDS   = 70.0f;   // 2/3 of max
const float CRITICAL     = 102.9f;  // 98% of max

// Read processor temperature in degrees Celsius.
// Returns a mock value if no sensor is found.
float read_celsius();

} // namespace temperature

#endif // TEMPERATURE_H
