package onec

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// PrepareFormContext enables flat String, Number, Boolean and Date attributes and explicit
// exported server functions when the metadata matches FormStateScalarTrackedV1. Nested objects are
// retained untouched. Unsupported dynamic descriptions or controls fail closed.
func (c *Client) PrepareFormContext(ctx context.Context, form Form, options FormSnapshotOptions) (FormContextState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return FormContextState{}, err
	}
	if err := c.checkForm(form); err != nil {
		return FormContextState{}, err
	}
	if state := form.state.context; state != nil {
		if !state.usable {
			return state.view(), errors.New("form context is retired; open a new form")
		}
		return state.view(), nil
	}
	docs, undefinedValues, err := c.formSnapshotDocuments(ctx, form, options)
	if err != nil {
		return FormContextState{}, err
	}
	state, err := prepareContext(form.state.descriptor, docs)
	if err != nil {
		return FormContextState{}, err
	}
	state.id, state.fid = form.id, form.fid
	state.undefinedValues = undefinedValues
	form.state.context = state
	return state.view(), nil
}

// CallWithContext submits validated scalar changes and invokes one metadata
// discovered exported server function. A stale revision is rejected locally.
// Unknown outcomes retire this context without replay; CloseForm remains usable.
// Arguments are copied scalars. Returned argument values are exposed separately
// in Arguments; the API does not mutate caller-owned variables.
func (c *Client) CallWithContext(ctx context.Context, form Form, method string, revision uint64, changes []FormParameter, args ...Value) (FormContextResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result FormContextResult
	if err := c.applicationReady(); err != nil {
		return result, err
	}
	if err := c.checkForm(form); err != nil {
		return result, err
	}
	state := form.state.context
	if state == nil {
		return result, errors.New("form context has not been prepared")
	}
	result.State = state.view()
	reject := func(message string) (FormContextResult, error) { return result, errors.New(message) }
	if !state.usable {
		return reject("form context is retired; open a new form")
	}
	if revision != state.revision {
		return reject("stale form context revision")
	}
	if len(args) > 32 {
		return reject("context method argument limit")
	}
	if !validFormName(method) || len(changes) > 32 {
		return reject("invalid context method or change count")
	}
	count := 0
	expectedArgs := 0
	for _, m := range state.methods {
		if strings.EqualFold(m.Name, method) && m.Context == "server" && m.Kind == "function" && m.Exported {
			count++
			method = m.Name
			expectedArgs = m.ParameterCount
		}
	}
	if count != 1 {
		return reject("context method is not an unambiguous exported server function")
	}
	if len(args) != expectedArgs {
		return reject("context method argument count mismatch")
	}
	generic := formMethod{Name: method}
	if len(args) > 0 {
		types, values := []string{}, []any{}
		for _, arg := range args {
			if arg.Type != StringType && arg.Type != NumberType && arg.Type != BooleanType && arg.Type != DateType {
				return reject("unsupported context argument type")
			}
			value, err := encodeFormValue(arg)
			if err != nil {
				return result, err
			}
			types, values = append(types, arg.Type), append(values, value)
		}
		generic.Types, generic.Params = &types, &values
	}
	candidate := *state
	candidate.callMethod = method
	candidate.callArgs = append([]Value(nil), args...)
	candidate.returnedArgs = nil
	candidate.values = append([]any(nil), state.values...)
	seen := map[string]bool{}
	dirty := false
	for _, change := range changes {
		key := strings.ToUpper(change.Name)
		if seen[key] || !state.writable[key] {
			return reject("duplicate or noneditable context field")
		}
		seen[key] = true
		value, err := encodeFormValue(change.Value)
		if err != nil {
			return result, err
		}
		for i, field := range state.fields {
			if strings.EqualFold(change.Name, field.name) {
				if err := field.validateEdit(change.Value, value); err != nil {
					return result, err
				}
				if candidate.values[i] != value {
					dirty = true
					candidate.values[i] = value
				}
			}
		}
	}
	proposal := contextProposal{}
	if dirty {
		positions := []string{}
		values := []any{}
		for i, field := range state.fields {
			if !field.object {
				positions = append(positions, strconv.Itoa(i))
				values = append(values, candidate.values[i])
			}
		}
		props := &contextProperties{Values: values}
		if len(values) != len(state.fields) {
			props.Fields = strings.Join(positions, " ")
		}
		proposal = contextProposal{SinDesc: &state.sinDesc, Sin: &state.sin, Seq: &state.seq, Structure: props}
	}
	payload := contextCall{RemoteKey: state.remoteKey, ID: form.id, FID: form.fid, Method: generic, Changes: proposal, Parameters: state.parameters, Dynamic: state.dd, FOP: state.query["fop"], FOver: state.query["fover"], USVer: state.query["usver"]}
	doc, applicationException, submitted, err := c.contextRequest(ctx, "call", payload)
	result.Submitted = submitted
	if err != nil {
		if !submitted {
			return result, err
		}
		if applicationException {
			recovery, _, _, recoveryErr := c.contextRequest(ctx, "synchException", struct {
				Key any `json:"key"`
			}{state.remoteKey})
			if recoveryErr == nil {
				recoveryErr = candidate.recover(recovery)
			}
			if recoveryErr == nil {
				candidate.revision++
				*state = candidate
				result.State = state.view()
				result.Recovered = true
				return result, errors.New("form method returned an application exception; context recovered")
			}
			state.usable = false
			result.State = state.view()
			return result, errors.Join(errors.New("form context recovery failed; context retired"), recoveryErr)
		}
		state.usable = false
		result.State = state.view()
		return result, errors.New("form context call failed; context retired")
	}
	value, err := candidate.apply(doc)
	if err != nil {
		state.usable = false
		result.State = state.view()
		return result, err
	}
	candidate.revision++
	*state = candidate
	result.Value = value
	result.Arguments = append([]Value(nil), candidate.returnedArgs...)
	result.State = state.view()
	return result, nil
}
