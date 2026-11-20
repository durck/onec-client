&AtServer
Procedure OnCreateAtServer(Cancel, StandardProcessing)
    InputText = "initial";
    ResultText = "READY";
    CounterText = "0";
    Quantity = 12.345;
    EnabledFlag = True;
    EventDate = Date(2026, 10, 20, 12, 34, 56);
EndProcedure

&AtServerNoContext
Function ProtocolControl() Export
    Return "RESEARCH_PROBE_CONTROL_20261020";
EndFunction

&AtServerNoContext
Function EchoNumber(Value) Export
    Return Value;
EndFunction

&AtServerNoContext
Function EchoBoolean(Value) Export
    Return Value;
EndFunction

&AtServerNoContext
Function EchoDate(Value) Export
    Return Value;
EndFunction

&AtServer
Function ApplyValues(Multiplier, Suffix) Export
    Quantity = Quantity * Multiplier;
    ResultText = InputText + Suffix;
    CounterText = String(Number(CounterText) + 1);
    Return Quantity;
EndFunction

&AtServer
Function SetPresentation() Export
    Title = "Changed server title";
    Items.InputTextField.ReadOnly = True;
    Items.CounterField.Visible = False;
    Items.ResultField.Title = "Changed result title";
    Return "PRESENTATION_CHANGED";
EndFunction

&AtServer
Function ResetPresentation() Export
    Title = "Interactive protocol probe";
    Items.InputTextField.ReadOnly = False;
    Items.CounterField.Visible = True;
    Items.ResultField.Title = "Server result";
    Return "PRESENTATION_RESET";
EndFunction

&AtServer
Function FailAfterChange() Export
    ResultText = "CHANGED_BEFORE_ERROR";
    Raise "CONTROLLED_RESEARCH_ERROR_20261020";
EndFunction

&AtClient
Function LocalAdd(A, B) Export
    Sum = A + B;
    Return Sum;
EndFunction

&AtClient
Function LocalBranch(A) Export
    If A > 2 Then
        Return "large";
    Else
        Return "small";
    EndIf;
EndFunction

&AtClient
Function LocalLoop(Count) Export
    Total = 0;
    For Index = 1 To Count Do
        Total = Total + Index;
    EndDo;
    Return Total;
EndFunction

&AtClient
Function LocalBoolean(A, B) Export
    Return A And Not B;
EndFunction

&AtClient
Procedure ClientAction(Command)
    LocalResult = LocalAdd(2, 3);
    LocalText = LocalBranch(LocalResult);
    ApplyValues(LocalResult, LocalText);
EndProcedure