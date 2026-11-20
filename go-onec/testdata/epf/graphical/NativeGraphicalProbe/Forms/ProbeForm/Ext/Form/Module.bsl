&AtServer
Procedure OnCreateAtServer(Cancel, StandardProcessing)
    Message = "HELLO_FROM_SERVER_FORM";
EndProcedure

&AtClient
Procedure ClientAction(Command)
    Message = "CLIENT_HANDLER_EXECUTED";
EndProcedure

&AtServerNoContext
Function ProtocolControl() Export
    Return "GRAPHICAL_PROBE_CONTROL_20261020";
EndFunction

&AtServerNoContext
Function Echo(Text) Export
    Return "echo:" + Text;
EndFunction
