#include <napi.h>

static Napi::Value Twice(const Napi::CallbackInfo &info) {
    return Napi::Number::New(info.Env(), info[0].As<Napi::Number>().DoubleValue() * 2);
}

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("twice", Napi::Function::New(env, Twice));
    return exports;
}

NODE_API_MODULE(addon_native, Init)
