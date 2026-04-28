#include "pi_calc.h"
#include <cstring>
#include <vector>

// Working array size for the spigot algorithm: ceil(10 * n / 3) + 1
static const int ARRAY_SIZE = (10 * PiCalculator::CAPACITY) / 3 + 2;

PiCalculator::PiCalculator()
    : m_running(false), m_digit(0), m_place(0), m_count(0) {}

PiCalculator::~PiCalculator() {
    stop();
}

void PiCalculator::start() {
    if (m_running.load()) return;
    m_running.store(true);
    m_digit.store(0);
    m_place.store(0);
    m_count.store(0);
    memset(m_digits, 0, sizeof(m_digits));
    m_thread = std::thread(&PiCalculator::compute, this);
}

// VULNERABLE: signed int is used as an array index with no bounds check.
// Negative or >= CAPACITY values produce an out-of-bounds read, which gives
// an attacker a primitive for leaking adjacent BSS / GOT bytes.
// (The Makefile compiles this TU at -O0, so the unchecked load is preserved.)
unsigned char PiCalculator::digit_at(int idx) const {
    return m_digits[idx];
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

    // Helper: commit one finalised digit. Records it in the digit buffer
    // (bounds-checked internally to keep the lab's vulnerabilities scoped to
    // the public-facing accessor) and publishes the latest position.
    auto emit = [&](int d) {
        place++;
        if (place >= 1 && place <= CAPACITY) {
            m_digits[place - 1] = static_cast<unsigned char>(d);
            m_count.store(place);
        }
        m_digit.store(d);
        m_place.store(place);
    };

    for (int j = 1; j <= CAPACITY && m_running.load(); j++) {
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
            emit((predigit + 1) % 10);
            for (int k = 0; k < nines; k++) {
                emit(0);
            }
            nines = 0;
            predigit = 0;
        } else {
            if (j > 1) {
                emit(predigit);
            }
            for (int k = 0; k < nines; k++) {
                emit(9);
            }
            nines = 0;
            predigit = q;
        }

        // Check cancellation each outer iteration
        if (!m_running.load()) break;
    }

    // Output final predigit
    if (m_running.load()) {
        emit(predigit);
    }

    m_running.store(false);
}
