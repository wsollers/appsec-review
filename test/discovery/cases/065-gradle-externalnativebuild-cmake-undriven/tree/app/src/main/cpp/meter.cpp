#include <jni.h>

extern "C" JNIEXPORT jint JNICALL
Java_com_example_meter_MainActivity_sampleCount(JNIEnv*, jclass) {
    return 16;
}
