#ifndef SRP_OBJECT_H
#define SRP_OBJECT_H

#include <node.h>
#include <node_object_wrap.h>

extern "C" {
    #include "srp/srp.h"
}

class SrpObject : public node::ObjectWrap
{
public:
    static void Init(v8::Local<v8::Object> exports);

private:
    explicit SrpObject();
    ~SrpObject();

    static void New(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void InitClientSRP6a(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void InitServerSRP6a(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void SetUsername(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void SetParams(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void SetPassword(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void GenPub(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void ComputeKey(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Respond(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void Verify(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void DeInit(const v8::FunctionCallbackInfo<v8::Value>& args);
    static v8::Persistent<v8::Function> constructor;
    SRP *srp;
};

#endif /* SRP_OBJECT_H */
