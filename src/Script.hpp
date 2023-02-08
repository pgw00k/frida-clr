#pragma once

#using <WindowsBase.dll>

#include <frida-core.h>
#include <msclr/gcroot.h>

#include "Marshal.hpp"

using namespace System;
using System::Windows::Threading::Dispatcher;

namespace Frida
{
  ref class ScriptMessageEventArgs;
  public delegate void ScriptMessageHandler (Object ^ sender, ScriptMessageEventArgs ^ e);

  public ref class Script
  {
  internal:
    Script (FridaScript * handle, Dispatcher ^ dispatcher);
  public:
    ~Script ();
  protected:
    !Script ();

  public:
    event ScriptMessageHandler ^ Message;

    void Load ();
    void Unload ();
    void Eternalize ();
    void Post (String ^ message);
    void PostWithData (String ^ message, array<unsigned char> ^ data);
    void EnableDebugger ();
    void EnableDebugger (UInt16 port);
    void DisableDebugger ();

  internal:
    void OnMessage (Object ^ sender, ScriptMessageEventArgs ^ e);

  private:
    FridaScript * handle;
    msclr::gcroot<Script ^> * selfHandle;

    Dispatcher ^ dispatcher;
    ScriptMessageHandler ^ onMessageHandler;

    JsonParser* jsonParser;
  };

  public ref class ScriptMessageEventArgs : public EventArgs
  {
  public:
    property String ^ Message { String ^ get () {
        if (String::IsNullOrEmpty(message))
        {
            message = Marshal::UTF8CStringToClrString(rawmessage);
        }
        return message; 
    } };
    property array<unsigned char> ^ Data { array<unsigned char> ^ get () { return data; } };
    
    property String^ Type { String^ get() {
        return type;
    } };

    property String^ PayLoad { String^ get() {
        return payload;
    } };

    ScriptMessageEventArgs (String ^ message, array<unsigned char> ^ data)
    {
      this->message = message;
      this->data = data;
    }

    ScriptMessageEventArgs(const char* message, array<unsigned char>^ data)
    {
        this->rawmessage = message;
        this->data = data;
    }

    void JsonParser(JsonParser* parser)
    {
        bool isJson = json_parser_load_from_data(parser, rawmessage, -1, NULL);

        if (!isJson)
        {
            return;
        }

        JsonObject* root = json_node_get_object(json_parser_get_root(parser));

        const char* rtype = json_object_get_string_member(root, "type");
        const char* rpl = json_object_get_string_member(root, "payload");
        type = Marshal::UTF8CStringToClrString(rtype);
        payload = Marshal::UTF8CStringToClrString(rpl);
    }

  private:
    String ^ message;
    String ^ type;
    String ^ payload;
    array<unsigned char> ^ data;

    const char* rawmessage;
  };
}
