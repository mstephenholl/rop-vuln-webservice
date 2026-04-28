# ROP-Vulnerable Webservice for BeagleBone Black Rev C
# Educational use only — intentionally disables security mitigations

CROSS_COMPILE ?=
CXX      = $(CROSS_COMPILE)g++
TARGET   = rop-webservice
SRCDIR   = src
SOURCES  = $(SRCDIR)/main.cpp \
           $(SRCDIR)/server.cpp \
           $(SRCDIR)/handlers.cpp \
           $(SRCDIR)/temperature.cpp \
           $(SRCDIR)/led.cpp \
           $(SRCDIR)/pi_calc.cpp

# -no-pie was added in GCC 6.0; older toolchains (e.g. BBB Debian 8 g++ 4.9)
# don't recognise it but also don't enable PIE by default, so omitting it is safe.
GCC_MAJOR := $(shell $(CXX) -dumpversion | cut -d. -f1)
NO_PIE    := $(shell [ $(GCC_MAJOR) -ge 6 ] && echo -no-pie)

# Intentionally vulnerable flags for ROP education
VULN_CXXFLAGS = -fno-stack-protector $(NO_PIE) -O0 -g -std=c++11
VULN_LDFLAGS  = $(NO_PIE) -z execstack -lpthread

# Safe flags with protections enabled
SAFE_CXXFLAGS = -fstack-protector-strong -pie -fPIE -O2 -g -std=c++11 \
                -D_FORTIFY_SOURCE=2
SAFE_LDFLAGS  = -pie -z noexecstack -z relro -z now -lpthread

.PHONY: all clean safe

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(VULN_CXXFLAGS) -o $@ $^ $(VULN_LDFLAGS)
	@echo ""
	@echo "Built with VULNERABLE flags (educational ROP target)"
	@echo "Verify with: checksec --file=$@"

safe: $(SOURCES)
	$(CXX) $(SAFE_CXXFLAGS) -o $(TARGET)-safe $^ $(SAFE_LDFLAGS)
	@echo ""
	@echo "Built with SAFE flags (protections enabled)"
	@echo "Verify with: checksec --file=$(TARGET)-safe"

clean:
	rm -f $(TARGET) $(TARGET)-safe
