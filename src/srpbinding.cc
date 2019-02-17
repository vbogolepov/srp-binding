#include <node.h>
#include "srp_object.h"

using v8::Local;
using v8::Object;

void InitAll(Local<Object> exports)
{
    SrpObject::Init(exports);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, InitAll)
