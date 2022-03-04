CXX=g++
CXXFLAGS=-Wall -Wextra -g -O1 -std=c++17 -pthread -lstdc++fs

TARGETS=torero-serve
all: $(TARGETS)

torero-serve: torero-serve.cpp BoundedBuffer.cpp
	$(CXX) $^ -o $@ $(CXXFLAGS)
clean:
	rm -f $(TARGETS)
