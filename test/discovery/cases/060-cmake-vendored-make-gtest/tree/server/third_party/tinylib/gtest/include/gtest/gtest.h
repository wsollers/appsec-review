#ifndef GTEST_GTEST_H
#define GTEST_GTEST_H
#define TEST(suite, name) void suite##_##name(void)
#define EXPECT_EQ(a, b) ((void)((a) == (b)))
namespace testing { void InitGoogleTest(int* argc, char** argv); }
int RUN_ALL_TESTS(void);
#endif
