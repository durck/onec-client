&AtServer
Procedure OnCreateAtServer(Cancel, StandardProcessing)
    InputText = "initial";
    ResultText = "READY";
    CounterText = "0";
EndProcedure

&AtServer
Function ProcessText() Export
    ResultText = "server:" + InputText;
    CounterText = String(Number(CounterText) + 1);
    Return ResultText;
EndFunction

&AtServer
Function FailAfterChange() Export
    ResultText = "CHANGED_BEFORE_ERROR";
    Raise "CONTROLLED_FORM_ERROR_20261020";
EndFunction

&AtServerNoContext
Function ProtocolControl() Export
    Return "INTERACTIVE_PROBE_CONTROL_20261020";
EndFunction

&AtClient
Procedure ClientAction(Command)
    ProcessText();
EndProcedure
