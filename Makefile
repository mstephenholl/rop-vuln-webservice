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

# Intentionally vulnerable flags for ROP education
VULN_CXXFLAGS = -fno-stack-protector -no-pie -O0 -g -std=c++11
VULN_LDFLAGS  = -no-pie -z execstack -lpthread

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
