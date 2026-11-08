CXX ?= c++

tiny_test: tiny_test.cc ../src/tiny.c
	$(CXX) -I../include tiny_test.cc ../src/tiny.c -lgtest -o tiny_test

check: tiny_test
	./tiny_test
