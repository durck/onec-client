package wire

import "encoding/json"

// NativeRPCError is a server exception outside the embedded HTTP protocol.
// It deliberately retains no server message, stack, base or routing context.
// Its presence does not authorize replay of an application request.
type NativeRPCError struct {
	class UUID
	code  string
}

func (e *NativeRPCError) Class() UUID   { return e.class }
func (e *NativeRPCError) Code() string  { return e.code }
func (e *NativeRPCError) Error() string { return "native RPC exception: " + e.code }
func (e *NativeRPCError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error string `json:"error"`
		Class string `json:"class"`
	}{e.code, e.class.String()})
}

// Recognize only the two complete exception layouts observed on build 18. Unknown
// layouts remain protocol errors; stack strings are validated then discarded.
func parseNativeRPCError(r []any) *NativeRPCError {
	if (len(r) != 4 && len(r) != 5) || !IsNumber(r[0], 2) {
		return nil
	}
	class, err := GUID(r[1])
	if err != nil {
		return nil
	}
	detailValue := r[2]
	var extraStrings []any
	if len(r) == 5 {
		wrapper, ok := List(r[2], 2)
		if !ok || !IsNumber(r[3], 1) {
			return nil
		}
		detailValue = wrapper[0]
		extraStrings = []any{wrapper[1], r[4]}
	} else if !IsNumber(r[3], 0) {
		return nil
	}
	detail, ok := List(detailValue, 6)
	if !ok || !IsGUID(detail[0], class) || !IsNumber(detail[5], 0) {
		return nil
	}
	nested, ok := List(detail[2], 1)
	if !ok || !IsNumber(nested[0], 0) {
		return nil
	}
	for _, v := range append(extraStrings, detail[1], detail[3], detail[4]) {
		if _, err := String(v); err != nil {
			return nil
		}
	}
	code := "native_rpc_exception"
	message, _ := String(detail[1])
	if class == MustUUID("05a83ab3-14ea-4d74-aef1-3128b035c350") &&
		message == "Попытка подключения к освобождаемому контексту информационной базы. Требуется повторить попытку подключения." {
		code = "infobase_context_releasing"
	}
	return &NativeRPCError{class: class, code: code}
}
