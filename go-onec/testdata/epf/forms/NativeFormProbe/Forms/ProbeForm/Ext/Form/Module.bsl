&AtServerNoContext
Function ProtocolControl() Export
    Return "PROBEFORM_CONTROL_20261019";
EndFunction

&AtServerNoContext
Function Echo(Text) Export
    Return "echo:" + Text;
EndFunction

&AtServerNoContext
Function EchoWithDefault(Text, Suffix = "tail") Export
    Return Text + ":" + Suffix;
EndFunction

&AtServerNoContext
Procedure NoResult(Val Text) Export
EndProcedure

&AtServer
Function ContextControl() Export
    Return "CONTEXT_CONTROL_20261019";
EndFunction

&AtClient
Procedure ClientOnly() Export
EndProcedure