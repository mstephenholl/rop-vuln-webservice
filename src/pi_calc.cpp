#include "pi_calc.h"
#include <vector>

// Number of digits to compute (1 million provides sustained load)
static const int NUM_DIGITS = 1000000;

// Working array size: ceil(10 * n / 3) + 1
static const int ARRAY_SIZE = (10 * NUM_DIGITS) / 3 + 2;

PiCalculator::PiCalculator()
    : m_running(false), m_digit(0), m_place(0) {}

PiCalculator::~PiCalculator() {
    stop();
}

void PiCalculator::start() {
    if (m_running.load()) return;
    m_running.store(true);
    m_digit.store(0);
    m_place.store(0);
    m_thread = std::thread(&PiCalculator::compute, this);
}

void PiCalculator::stop() {
    m_running.store(false);
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

// Rabinowitz-Wagon bounded spigot algorithm for Pi
void PiCalculator::compute() {
    std::vector<int> a(ARRAY_SIZE, 2); // initialize all elements to 2

    int nines = 0;
    int predigit = 0;
    int place = 0;

    for (int j = 1; j <= NUM_DIGITS && m_running.load(); j++) {
        // Multiply and propagate carries right-to-left
        int q = 0;
        for (int i = ARRAY_SIZE - 1; i >= 0; i--) {
            int x = 10 * a[i] + q * (i + 1);
            a[i] = x % (2 * i + 1);
            q = x / (2 * i + 1);
        }

        a[0] = q % 10;
        q = q / 10;

        if (q == 9) {
            nines++;
        } else if (q == 10) {
            // Carry propagation: predigit increments, nines become 0
            place++;
            m_digit.store((predigit + 1) % 10);
            m_place.store(place);
            for (int k = 0; k < nines; k++) {
                place++;
                m_digit.store(0);
                m_place.store(place);
            }
            nines = 0;
            predigit = 0;
        } else {
            if (j > 1) {
                // Output the predigit
                place++;
                m_digit.store(predigit);
                m_place.store(place);
            }
            for (int k = 0; k < nines; k++) {
                place++;
                m_digit.store(9);
                m_place.store(place);
            }
            nines = 0;
            predigit = q;
        }

        // Check cancellation each outer iteration
        if (!m_running.load()) break;
    }

    // Output final predigit
    if (m_running.load()) {
        place++;
        m_digit.store(predigit);
        m_place.store(place);
    }

    m_running.store(false);
}
