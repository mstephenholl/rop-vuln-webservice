#ifndef PI_CALC_H
#define PI_CALC_H

#include <atomic>
#include <thread>

class PiCalculator {
public:
    // Maximum number of decimal digits stored. Sized so the buffer lives in
    // BSS with a deterministic address (useful for ROP exercises that need
    // a stable offset to nearby GOT entries).
    static const int CAPACITY = 1000000;

    PiCalculator();
    ~PiCalculator();

    // Start computing Pi digits (launches worker thread)
    void start();

    // Stop computation
    void stop();

    // Is computation running?
    bool running() const { return m_running.load(); }

    // Most recently computed digit (0-9)
    int current_digit() const { return m_digit.load(); }

    // Current decimal place (1-based)
    int current_place() const { return m_place.load(); }

    // Number of digits committed to the digit buffer so far (0..CAPACITY).
    int count() const { return m_count.load(); }

    // Returns the byte at index idx in the digit buffer.
    // VULNERABLE: no bounds check — idx may be negative or >= CAPACITY.
    // Implementation lives in pi_calc.cpp and is built at -O0 to keep the
    // out-of-bounds load observable (not folded away by the optimiser).
    unsigned char digit_at(int idx) const;

private:
    void compute();

    std::atomic<bool> m_running;
    std::atomic<int>  m_digit;
    std::atomic<int>  m_place;
    std::atomic<int>  m_count;
    unsigned char     m_digits[CAPACITY]; // BSS-resident; fixed address with -no-pie
    std::thread       m_thread;
};

#endif // PI_CALC_H
