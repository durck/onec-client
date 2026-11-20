package onec

import (
	"context"
	"errors"
	"strings"
)

// ErrDynamicListCompactRows means that the server returned a valid compact
// window, but its row/description codec is outside the supported profile.
// A successful exchange alone does not establish decoded application records.
var ErrDynamicListCompactRows = errors.New("dynamic-list compact row codec is unsupported")

const dynamicListType = "65ABAD24-838B-4987-8B35-ED9E2BD4D9C8"

const dynamicListEmptyCache = "00000000-0000-0000-0000-000000000000"

// DynamicList is an opaque binding to one table in an open managed form.
// Later structural form deltas are not synchronized. Open a fresh form after
// invoking logic that changes its attributes or controls.
type DynamicList struct{ state *dynamicListState }

func (DynamicList) String() string { return "1C dynamic-list handle (redacted)" }

func (d DynamicList) GoString() string { return d.String() }

type dynamicListState struct {
	form    Form
	tableID uint64
	path    []string
	period  map[string]any
	columns []DynamicListColumn
}

type DynamicListColumn struct {
	Name string `json:"name"`
}

// DynamicListBookmark is obtained from a decoded row. It cannot be constructed
// from an arbitrary server identifier or reused with another binding.
type DynamicListBookmark struct {
	owner *dynamicListState
	value Value
}

func (DynamicListBookmark) String() string { return "1C dynamic-list bookmark (redacted)" }

func (b DynamicListBookmark) GoString() string { return b.String() }

// DynamicListSearch uses the shipped client's default field comparison
// (wire comparison 2). It is not a SQL expression or a BSL command.
type DynamicListSearch struct {
	Field string
	Value Value
}

type DynamicListWindowOptions struct {
	// Limit is the number of requested rows, from 1 to 1000; zero selects 40.
	Limit  int
	After  *DynamicListBookmark
	Search *DynamicListSearch
}

type DynamicListRow struct {
	Values   map[string]Value    `json:"values"`
	Bookmark DynamicListBookmark `json:"-"`
}

type DynamicListWindow struct {
	Columns    []DynamicListColumn `json:"columns"`
	Rows       []DynamicListRow    `json:"rows,omitempty"`
	First      bool                `json:"first"`
	Last       bool                `json:"last"`
	InProgress bool                `json:"in_progress"`
	Encoding   string              `json:"encoding"`
}

// BindDynamicList supports the inspected metadata schema with a scalar, flat list and
// an explicit table period. It reads form metadata; it executes no form method.
// Runtime-added root attributes and controls are supported; nested paths and
// arbitrary form-description mutations are rejected.
func (c *Client) BindDynamicList(ctx context.Context, form Form, tableName string) (DynamicList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return DynamicList{}, err
	}
	if err := c.checkForm(form); err != nil {
		return DynamicList{}, err
	}
	if !validFormName(tableName) {
		return DynamicList{}, errors.New("invalid dynamic-list table name")
	}
	docs, _, err := c.formSnapshotDocuments(ctx, form, FormSnapshotOptions{})
	if err != nil {
		return DynamicList{}, err
	}
	return bindDynamicList(form, tableName, docs[0], docs[1])
}

func bindDynamicList(form Form, tableName string, elements, description map[string]any) (DynamicList, error) {
	fail := func() (DynamicList, error) {
		return DynamicList{}, errors.New("unsupported dynamic-list form metadata")
	}
	descr, ok := description["descr"].(map[string]any)
	if !ok {
		return fail()
	}
	structures, ok := descr["structure"].([]any)
	if !ok || len(structures) > 2048 {
		return fail()
	}
	var fields []any
	roots := 0
	for _, raw := range structures {
		st, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		if st["name"] == "root" {
			roots++
			if value, exists := st["field"]; exists {
				fields, ok = value.([]any)
				if !ok {
					return fail()
				}
			}
		}
	}
	if roots != 1 {
		return fail()
	}
	fields = append([]any(nil), fields...)
	if raw, exists := form.state.descriptor["pdchs"]; exists {
		pd, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		changed, ok := pd["changed"].([]any)
		if !ok || len(changed) > 64 {
			return fail()
		}
		for _, raw := range changed {
			ch, ok := raw.(map[string]any)
			if !ok || ch["name"] != "root" {
				return fail()
			}
			for key := range ch {
				if key != "name" && key != "added" && key != "##sequence" {
					return fail()
				}
			}
			added, ok := ch["added"].([]any)
			if !ok {
				return fail()
			}
			fields = append(fields, added...)
		}
	}
	if len(fields) > 2048 {
		return fail()
	}
	table := map[string]any{}
	var tableID uint64
	matches := 0
	var visit func(map[string]any, int) bool
	visit = func(doc map[string]any, depth int) bool {
		if depth > 32 {
			return false
		}
		for key, raw := range doc {
			switch value := raw.(type) {
			case []any:
				for _, item := range value {
					child, ok := item.(map[string]any)
					if !ok {
						continue
					}
					if key == "table" && strings.EqualFold(snapshotString(child, "name"), tableName) {
						id, e := contextNumber(child["id"])
						if e != nil || id == 0 {
							return false
						}
						tableID = id
						matches++
						table = cloneContextMap(child)
					}
					if !visit(child, depth+1) {
						return false
					}
				}
			case map[string]any:
				if !visit(value, depth+1) {
					return false
				}
			}
		}
		return true
	}
	if !visit(elements, 0) {
		return fail()
	}
	var changes []any
	if raw, exists := form.state.descriptor["elchs"]; exists {
		el, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		changes, ok = el["elemcs"].([]any)
		if !ok || len(changes) > 8192 {
			return fail()
		}
	}
	for _, raw := range changes {
		ch, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		kind, e := contextNumber(ch["type"])
		if e != nil {
			return fail()
		}
		if kind == 0 && strings.EqualFold(snapshotString(ch, "name"), tableName) {
			id, e := contextNumber(ch["id"])
			if e != nil || id == 0 {
				return fail()
			}
			tableID = id
			matches++
		}
	}
	if matches != 1 {
		return fail()
	}
	propsByID := map[uint64]any{}
	apply := func(p map[string]any) bool {
		for key, value := range p {
			if key != "addProps" {
				table[key] = value
				continue
			}
			add, ok := value.(map[string]any)
			if !ok {
				return false
			}
			list, ok := add["prop"].([]any)
			if !ok || len(list) > 256 {
				return false
			}
			for _, raw := range list {
				pr, ok := raw.(map[string]any)
				if !ok {
					return false
				}
				id, e := contextNumber(pr["id"])
				if e != nil {
					return false
				}
				propsByID[id] = pr["val"]
			}
		}
		return true
	}
	if !apply(cloneContextMap(table)) {
		return fail()
	}
	for _, raw := range changes {
		ch := raw.(map[string]any)
		id, e := contextNumber(ch["id"])
		if e != nil {
			return fail()
		}
		if id != tableID {
			continue
		}
		kind, _ := contextNumber(ch["type"])
		if kind == 1 {
			return fail()
		}
		if kind == 3 {
			p, ok := ch["table"].(map[string]any)
			if !ok || !apply(p) {
				return fail()
			}
		}
	}
	prop, ok := table["prop"].(map[string]any)
	if !ok {
		return fail()
	}
	path, ok := prop["id"].([]any)
	if !ok || len(path) != 1 {
		return fail()
	}
	id, ok := path[0].(string)
	if !ok || id == "" {
		return fail()
	}
	position := -1
	seenIDs := map[string]bool{}
	for i, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		fieldID := snapshotString(field, "id")
		if fieldID == "" || seenIDs[fieldID] {
			return fail()
		}
		seenIDs[fieldID] = true
		if fieldID == id {
			typ, ok := field["type"].(map[string]any)
			if !ok || !strings.EqualFold(snapshotString(typ, "__content"), dynamicListType) {
				return fail()
			}
			position = i
		}
	}
	if position < 0 {
		return fail()
	}
	props, ok := form.state.descriptor["props"].(map[string]any)
	if !ok {
		return fail()
	}
	if _, exists := props["fields"]; exists {
		return fail()
	}
	values, ok := props["v"].([]any)
	if !ok || len(values) != len(fields) {
		return fail()
	}
	value, ok := values[position].(map[string]any)
	if !ok {
		return fail()
	}
	if snapshotBool(value, "HierAvailable", false) || snapshotNonempty(value["GroupFieldsItem"]) {
		return fail()
	}
	if choice, exists := table["choiceMode"]; exists && choice != false {
		return fail()
	}
	used, ok := value["UsedField"].([]any)
	if !ok || len(used) == 0 || len(used) > 128 {
		return fail()
	}
	columns := make([]DynamicListColumn, len(used))
	seenNames := map[string]bool{}
	for i, raw := range used {
		field, ok := raw.(map[string]any)
		if !ok {
			return fail()
		}
		name := snapshotString(field, "Name")
		canonical := strings.ToUpper(name)
		if !validFormName(name) || seenNames[canonical] {
			return fail()
		}
		seenNames[canonical] = true
		columns[i] = DynamicListColumn{Name: name}
	}
	period, ok := propsByID[7].(map[string]any)
	if !ok {
		return fail()
	}
	if len(period) != 4 || snapshotString(period, "variant") != "Custom" || !formUUID(snapshotString(period, "#variant")) || snapshotString(period, "startDate") != "0001-01-01T00:00:00" || snapshotString(period, "endDate") != "0001-01-01T00:00:00" {
		return fail()
	}
	if !validValueText(snapshotString(form.state.descriptor, "remotekey"), 8192) {
		return fail()
	}
	return DynamicList{&dynamicListState{form: form, tableID: tableID, path: []string{id}, period: cloneContextMap(period), columns: columns}}, nil
}

// ReadDynamicListWindow requests a fresh forward window of the bound list.
// No arbitrary query text or form command is sent. InProgress is returned
// without automatic retry. Unsupported compact rows return metadata plus
// ErrDynamicListCompactRows, never a successful empty record set.
func (c *Client) ReadDynamicListWindow(ctx context.Context, list DynamicList, options DynamicListWindowOptions) (DynamicListWindow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.applicationReady(); err != nil {
		return DynamicListWindow{}, err
	}
	if list.state == nil {
		return DynamicListWindow{}, errors.New("invalid dynamic-list binding")
	}
	if err := c.checkForm(list.state.form); err != nil {
		return DynamicListWindow{}, err
	}
	request, err := dynamicListQuery(list, options)
	if err != nil {
		return DynamicListWindow{}, err
	}
	response, err := c.jsonRequest(ctx, "/e1cib/dlist?cmd=query", request)
	if err != nil {
		return DynamicListWindow{}, err
	}
	return decodeDynamicListWindow(response, list.state, request.Page)
}
