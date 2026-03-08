#ifndef PI_CALC_H
#define PI_CALC_H

#include <atomic>
#include <thread>

class PiCalculator {
public:
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

private:
    void compute();

    std::atomic<bool> m_running;
    std::atomic<int>  m_digit;
    std::atomic<int>  m_place;
    std::thread       m_thread;
};

#endif // PI_CALC_H
