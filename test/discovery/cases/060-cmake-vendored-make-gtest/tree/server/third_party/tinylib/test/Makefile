CXX ?= c++

gtest-build/libgtest.a:
	cmake -S ../gtest -B gtest-build && cmake --build gtest-build

tiny_test: tiny_test.cc ../src/tiny.c gtest-build/libgtest.a
	$(CXX) -I../include -I../gtest/include tiny_test.cc ../src/tiny.c gtest-build/libgtest.a -o tiny_test

check: tiny_test
	./tiny_test
