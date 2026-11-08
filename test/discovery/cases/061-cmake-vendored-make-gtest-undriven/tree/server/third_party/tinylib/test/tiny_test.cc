#include "gtest/gtest.h"
#include "tiny.h"
TEST(Tiny, Version) { EXPECT_EQ(tiny_version(), 3); }
int main(int argc, char** argv) { testing::InitGoogleTest(&argc, argv); return RUN_ALL_TESTS(); }
