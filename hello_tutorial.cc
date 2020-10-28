
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"

namespace
{
  const char *const kHelloString = "hello";
  const char *const kReplyString = "hello from Nacl";
} 

class HelloTutorialInstance : public pp::Instance
{
public:

  explicit HelloTutorialInstance(PP_Instance instance) : pp::Instance(instance)
  {
  }
  virtual ~HelloTutorialInstance() {}

  virtual void HandleMessage(const pp::Var &var_message)
  //todo 
  {

    if (!var_message.is_string())
      return;
    std::string message = var_message.AsString();
    pp::Var var_reply;
    if (message == kHelloString)
    {
      var_reply = pp::Var(kReplyString);
      PostMessage(var_reply);
    }
  }
};

class HelloTutorialModule : public pp::Module
{
public:
  HelloTutorialModule() : pp::Module() {}
  virtual ~HelloTutorialModule() {}

  virtual pp::Instance *CreateInstance(PP_Instance instance)
  {
    return new HelloTutorialInstance(instance);
  }
};

namespace pp
{
  Module *CreateModule()
  {
    return new HelloTutorialModule();
  }
} // namespace pp
