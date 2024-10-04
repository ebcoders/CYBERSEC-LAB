CXX = g++
CXXFLAGS = -lcryptopp

TARGETS = 1_setup 2_generate_alice_private_key 3_generate_alice_public_key \
          4_generate_bob_private_key 5_generate_bob_public_key \
          6_setupCA 7_certificate_generation \
          8_verify_certificate 9_session_key_generation

# Default rule
all: $(TARGETS)

# Compile individual binaries
1_setup: 1_setup.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

2_generate_alice_private_key: 2_generate_alice_private_key.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

3_generate_alice_public_key: 3_generate_alice_public_key.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

4_generate_bob_private_key: 4_generate_bob_private_key.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

5_generate_bob_public_key: 5_generate_bob_public_key.cpp
	$(CXX) $< $(CXXFLAGS) -o $@


6_setupCA: 6_setupCA.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

7_certificate_generation: 7_certificate_generation.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

8_verify_certificate: 8_verify_certificate.cpp
	$(CXX) $< $(CXXFLAGS) -o $@

9_session_key_generation: 9_session_key_generation.cpp
	$(CXX) $< $(CXXFLAGS) -o $@
# Clean up generated files
clean:
	rm -f $(TARGETS) *.o
	rm -f *.bin
