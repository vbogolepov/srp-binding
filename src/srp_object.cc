#include <node_buffer.h>
#include <nan.h>

#include "srp_object.h"

using namespace v8;
using namespace node;

Persistent<Function> SrpObject::constructor;

SrpObject::SrpObject() : srp(NULL)
{
}

SrpObject::~SrpObject()
{
}

void SrpObject::Init(v8::Local<v8::Object> exports)
{
    Isolate* isolate = exports->GetIsolate();

    Local<FunctionTemplate> tpl = FunctionTemplate::New(isolate, New);
    tpl->SetClassName(String::NewFromUtf8(
        isolate, "SrpObject", NewStringType::kNormal).ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);

    NODE_SET_PROTOTYPE_METHOD(tpl, "InitClientSRP6a", InitClientSRP6a);
    NODE_SET_PROTOTYPE_METHOD(tpl, "InitServerSRP6a", InitServerSRP6a);
    NODE_SET_PROTOTYPE_METHOD(tpl, "SetUsername", SetUsername);
    NODE_SET_PROTOTYPE_METHOD(tpl, "SetParams", SetParams);
    NODE_SET_PROTOTYPE_METHOD(tpl, "SetPassword", SetPassword);
    NODE_SET_PROTOTYPE_METHOD(tpl, "GenPub", GenPub);
    NODE_SET_PROTOTYPE_METHOD(tpl, "ComputeKey", ComputeKey);
    NODE_SET_PROTOTYPE_METHOD(tpl, "Respond", Respond);
    NODE_SET_PROTOTYPE_METHOD(tpl, "Verify", Verify);
    NODE_SET_PROTOTYPE_METHOD(tpl, "DeInit", DeInit);

    Local<Context> context = isolate->GetCurrentContext();
    constructor.Reset(isolate, tpl->GetFunction(context).ToLocalChecked());
    exports->Set(context, String::NewFromUtf8(
        isolate, "SrpObject", NewStringType::kNormal).ToLocalChecked(),
        tpl->GetFunction(context).ToLocalChecked()).FromJust();
}

void SrpObject::New(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    Local<Context> context = isolate->GetCurrentContext();
    if (args.IsConstructCall())
    {
        SrpObject* obj = new SrpObject();
        obj->Wrap(args.This());
        args.GetReturnValue().Set(args.This());
    }
    else
    {
        const int argc = 1;
        Local<Value> argv[argc] = { args[0] };
        Local<Function> cons = Local<Function>::New(isolate, constructor);
        Local<Object> result = cons->NewInstance(context, argc, argv).ToLocalChecked();
        args.GetReturnValue().Set(result);
    }
    SRP_initialize_library();
}

void SrpObject::InitClientSRP6a(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    int status = SRP_ERROR;
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    if (obj->srp)
    {
        return Nan::ThrowError("InitClientSRP6a: client already initialized");
    }
    obj->srp = SRP_new(SRP6a_client_method());
    if (obj->srp) status = SRP_SUCCESS;
    args.GetReturnValue().Set(Number::New(args.GetIsolate(), status));
}

void SrpObject::InitServerSRP6a(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    int status = SRP_ERROR;
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    if (obj->srp)
    {
        return Nan::ThrowError("InitServerSRP6a: server already initialized");
    }
    obj->srp = SRP_new(SRP6a_server_method());
    if (obj->srp) status = SRP_SUCCESS;
    args.GetReturnValue().Set(Number::New(args.GetIsolate(), status));
}

void SrpObject::SetUsername(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if ((args.Length() != 1) && !args[0]->IsString())
    {
        return Nan::ThrowError("SetUsername requires a 1 string parameter");
    }

    String::Utf8Value username(args[0]->ToString());
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    args.GetReturnValue().Set(Number::New(args.GetIsolate(), SRP_set_username(obj->srp, *username)));
}

void SrpObject::SetParams(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if (args.Length() < 3
        && !Buffer::HasInstance(args[0]->ToObject())
        && !Buffer::HasInstance(args[1]->ToObject())
        && !Buffer::HasInstance(args[2]->ToObject()))
    {
        return Nan::ThrowError("SetParams requires a 3 parameters as beffer object");
    }

    Handle<Object> messageModulus = args[0]->ToObject();
    unsigned char* modulus = (unsigned char*)Buffer::Data(messageModulus);

    Handle<Object> messageGenerator = args[1]->ToObject();
    unsigned char* generator = (unsigned char*)Buffer::Data(messageGenerator);

    Handle<Object> messageSalt = args[2]->ToObject();
    unsigned char* salt = (unsigned char*)Buffer::Data(messageSalt);

    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    args.GetReturnValue().Set(Number::New(args.GetIsolate(),
        SRP_set_params(obj->srp, modulus, (int)Buffer::Length(messageModulus),
            generator, (int)Buffer::Length(messageGenerator),
            salt, (int)Buffer::Length(messageSalt))));
}

void SrpObject::SetPassword(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if (args.Length() != 1 && !args[0]->IsString())
    {
        return Nan::ThrowError("SetPassword requires a 1 string parameter");
    }

    String::Utf8Value password(args[0]->ToString());
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    args.GetReturnValue().Set(Number::New(args.GetIsolate(), SRP_set_auth_password(obj->srp, *password)));
}

void SrpObject::GenPub(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    cstr *data = cstr_new();
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    if (SRP_gen_pub(obj->srp, &data) == SRP_SUCCESS)
    {
        v8::Local<v8::Object> pubkey = Nan::NewBuffer(data->length).ToLocalChecked();
        unsigned char* pubkeyData = (unsigned char*)Buffer::Data(pubkey);
        for (int i = 0; i < data->length; i++)
        {
            pubkeyData[i] = data->data[i];
        }
        args.GetReturnValue().Set(v8::Local<v8::Object>::New(args.GetIsolate(), pubkey));
    }
    if (data) cstr_free(data);
}

void SrpObject::ComputeKey(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if (args.Length() != 1 && !Buffer::HasInstance(args[0]->ToObject()))
    {
        return Nan::ThrowError("ComputeKey requires a 1 parameter as beffer object");
    }

    Handle<Object> messagePubkey = args[0]->ToObject();
    unsigned char* pubkey = (unsigned char*)Buffer::Data(messagePubkey);

    cstr *data = cstr_new();
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    if (SRP_compute_key(obj->srp, &data, pubkey, (int)Buffer::Length(messagePubkey)) == SRP_SUCCESS)
    {
        v8::Local<v8::Object> secret = Nan::NewBuffer(data->length).ToLocalChecked();
        unsigned char* secretData = (unsigned char*)Buffer::Data(secret);
        for (int i = 0; i < data->length; i++)
        {
            secretData[i] = data->data[i];
        }
        args.GetReturnValue().Set(v8::Local<v8::Object>::New(args.GetIsolate(), secret));
    }
    if (data) cstr_free(data);
}

void SrpObject::Respond(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    cstr *data = cstr_new();
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    if (SRP_respond(obj->srp, &data) == SRP_SUCCESS)
    {
        v8::Local<v8::Object> proof = Nan::NewBuffer(data->length).ToLocalChecked();
        unsigned char* proofData = (unsigned char*)Buffer::Data(proof);
        for (int i = 0; i < data->length; i++)
        {
            proofData[i] = data->data[i];
        }
        args.GetReturnValue().Set(v8::Local<v8::Object>::New(args.GetIsolate(), proof));
    }
    if (data) cstr_free(data);
}

void SrpObject::Verify(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    if (args.Length() != 1 && !Buffer::HasInstance(args[0]->ToObject()))
    {
        return Nan::ThrowError("Verify requires a 1 parameter as beffer object");
    }

    Handle<Object> messageProof = args[0]->ToObject();
    unsigned char* proof = (unsigned char*)Buffer::Data(messageProof);

    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    args.GetReturnValue().Set(Number::New(args.GetIsolate(), SRP_verify(obj->srp, proof, (int)Buffer::Length(messageProof))));
}

void SrpObject::DeInit(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    SrpObject* obj = ObjectWrap::Unwrap<SrpObject>(args.Holder());
    SRP_finalize_library();
    if (obj->srp)
    {
        SRP_free(obj->srp);
        obj->srp = NULL;
    }
}
