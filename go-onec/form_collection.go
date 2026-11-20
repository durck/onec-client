package onec

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const (
	MaxFormCollectionRows       = 10000
	MaxFormCollectionOperations = 10000
	MaxFormCollectionBytes      = 4 * 1024 * 1024
	maxFormCollectionCells      = 65536
	maxFormCollectionID         = 1<<53 - 1
)

// FormCollectionField describes an ordinary monotype scalar column. Object
// columns, computed line-number columns and polymorphic columns are outside
// this bounded codec. ID is the descriptor ID, not the zero-based position.
type FormCollectionField struct {
	ID   string
	Type string
}

// FormCollectionOperation is a closed union. Only the members specified by Kind
// may be nonzero: add(index,id), addRange(index1,index2,startId), remove(index),
// removeRange(index1,index2), swap(index1,index2), move(index,delta), clear().
type FormCollectionOperation struct {
	Kind                  string
	Index, Index1, Index2 int
	ID, StartID           int64
	Delta                 int
}

type FormCollectionRowDelta struct {
	Index  int
	ID     int64
	Fields []int // nil means every descriptor position; empty means none
	Values []Value
}

type FormCollectionTotal struct {
	ID    string
	Total Decimal
}

// FormCollectionDelta is the collection payload nested inside a form structure.
// It is not a request or acknowledgement. Counters belong to the outer factory.
type FormCollectionDelta struct {
	Count          int
	LastID         int64
	FullChanged    bool
	FirstAddedLine int
	DropOld        bool // server invalidation; retained but never applied implicitly
	Operations     []FormCollectionOperation
	Rows           []FormCollectionRowDelta
	Totals         []FormCollectionTotal
}

// FormCollectionCodec encodes the observed Bv.Ls/Bv.Ym payload only. It performs
// no network I/O, lazy fragment loading, qualifier coercion or acknowledgement.
type FormCollectionCodec struct {
	values FormValueCodec
	fields []FormCollectionField
}

func NewFormCollectionCodec(values FormValueCodec, fields []FormCollectionField) (FormCollectionCodec, error) {
	if len(fields) == 0 || len(fields) > 256 {
		return FormCollectionCodec{}, errors.New("invalid collection field count")
	}
	c := FormCollectionCodec{values: values, fields: append([]FormCollectionField(nil), fields...)}
	seen := map[string]bool{}
	for i := range c.fields {
		f := &c.fields[i]
		f.Type = strings.ToUpper(f.Type)
		if f.ID == "" || len(f.ID) > 128 || !formString(f.ID) || seen[f.ID] {
			return FormCollectionCodec{}, errors.New("invalid collection field ID")
		}
		seen[f.ID] = true
		if !builtinFormType(f.Type) && !values.references[f.Type] || f.Type == BinaryType {
			return FormCollectionCodec{}, errors.New("unsupported collection field type")
		}
	}
	return c, nil
}

func (c FormCollectionCodec) Marshal(d FormCollectionDelta) ([]byte, error) {
	if err := c.validate(d); err != nil {
		return nil, err
	}
	out := []byte(`{"count":` + strconv.Itoa(d.Count) + `,"lastId":` + strconv.FormatInt(d.LastID, 10) +
		`,"fullChanged":` + strconv.FormatBool(d.FullChanged) + `,"firstAddedLine":` + strconv.Itoa(d.FirstAddedLine))
	if d.DropOld {
		out = append(out, []byte(`,"dropOld":true`)...)
	}
	if len(d.Operations) > 0 {
		raw, err := marshalCollectionOperations(d.Operations)
		if err != nil {
			return nil, err
		}
		out = append(out, []byte(`,"operations":`)...)
		out = append(out, raw...)
	}
	if d.Count > 0 {
		out = append(out, []byte(`,"items":{"item":[`)...)
		for i, row := range d.Rows {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, []byte(`{"index":`+strconv.Itoa(row.Index)+`,"id":`+strconv.FormatInt(row.ID, 10)+`,"structure":{`)...)
			if row.Fields != nil {
				text := make([]string, len(row.Fields))
				for i, n := range row.Fields {
					text[i] = strconv.Itoa(n)
				}
				raw, _ := json.Marshal(strings.Join(text, " "))
				out = append(out, []byte(`"fields":`)...)
				out = append(out, raw...)
				out = append(out, ',')
			}
			out = append(out, []byte(`"v":[`)...)
			for j, value := range row.Values {
				if j > 0 {
					out = append(out, ',')
				}
				raw, err := c.values.Marshal(value)
				if err != nil {
					return nil, err
				}
				out = append(out, raw...)
				if len(out) > MaxFormCollectionBytes {
					return nil, errors.New("collection delta exceeds size limit")
				}
			}
			out = append(out, []byte(`]}}`)...)
		}
		out = append(out, []byte(`]}`)...)
	}
	out = append(out, []byte(`,"column":[`)...)
	for i, total := range d.Totals {
		if i > 0 {
			out = append(out, ',')
		}
		id, _ := json.Marshal(total.ID)
		value, err := c.values.Marshal(Value{NumberType, total.Total})
		if err != nil {
			return nil, err
		}
		out = append(out, []byte(`{"id":`)...)
		out = append(out, id...)
		out = append(out, []byte(`,"total":`)...)
		out = append(out, value...)
		out = append(out, '}')
	}
	out = append(out, []byte(`]}`)...)
	if len(out) > MaxFormCollectionBytes {
		return nil, errors.New("collection delta exceeds size limit")
	}
	return out, nil
}

func (c FormCollectionCodec) Unmarshal(data []byte) (FormCollectionDelta, error) {
	var d FormCollectionDelta
	if len(data) > MaxFormCollectionBytes {
		return d, errors.New("collection delta exceeds size limit")
	}
	obj, err := collectionObject(data)
	if err != nil || !collectionKeys(obj, "count", "lastId", "fullChanged", "firstAddedLine", "dropOld", "operations", "items", "column") {
		return d, errors.New("invalid collection delta object")
	}
	count, e1 := collectionInt(obj["count"])
	lastID, e2 := collectionInt(obj["lastId"])
	first, e3 := collectionInt(obj["firstAddedLine"])
	if e1 != nil || e2 != nil || e3 != nil || count < 0 || count > MaxFormCollectionRows || first < -1 || first > MaxFormCollectionRows {
		return d, errors.New("invalid collection delta counters")
	}
	d.Count, d.LastID, d.FirstAddedLine = int(count), lastID, int(first)
	if err := json.Unmarshal(obj["fullChanged"], &d.FullChanged); err != nil || bytes.Equal(obj["fullChanged"], []byte("null")) {
		return d, errors.New("invalid collection fullChanged")
	}
	if raw, ok := obj["dropOld"]; ok {
		if err := json.Unmarshal(raw, &d.DropOld); err != nil || bytes.Equal(raw, []byte("null")) {
			return d, errors.New("invalid collection dropOld")
		}
	}
	if raw, ok := obj["operations"]; ok {
		d.Operations, err = unmarshalCollectionOperations(raw)
		if err != nil {
			return d, err
		}
	}
	if raw, ok := obj["items"]; ok {
		items, err := collectionObject(raw)
		if err != nil || !collectionKeys(items, "item", "##sequence") {
			return d, errors.New("invalid collection items")
		}
		var rows [][]byte
		if raw, ok := items["item"]; ok {
			rows, err = collectionArray(raw)
		}
		if err != nil || len(rows) > MaxFormCollectionRows || !collectionProjectionSequence(items, "item", len(rows)) {
			return d, errors.New("invalid collection item count")
		}
		for _, rawRow := range rows {
			row, err := c.unmarshalRow(rawRow)
			if err != nil {
				return d, err
			}
			d.Rows = append(d.Rows, row)
		}
	}
	if raw, ok := obj["column"]; ok {
		totals, err := collectionArray(raw)
		if err != nil || len(totals) > len(c.fields) {
			return d, errors.New("invalid collection totals")
		}
		for _, rawTotal := range totals {
			total, err := collectionObject(rawTotal)
			if err != nil || len(total) != 2 || total["id"] == nil || total["total"] == nil {
				return d, errors.New("invalid collection total")
			}
			id, err := decodeFormJSONString(total["id"])
			if err != nil {
				return d, err
			}
			value, err := c.values.Unmarshal(NumberType, total["total"])
			if err != nil {
				return d, err
			}
			d.Totals = append(d.Totals, FormCollectionTotal{id, value.Value.(Decimal)})
		}
	}
	if err := c.validate(d); err != nil {
		return FormCollectionDelta{}, err
	}
	return d, nil
}

func (c FormCollectionCodec) unmarshalRow(data []byte) (FormCollectionRowDelta, error) {
	var row FormCollectionRowDelta
	obj, err := collectionObject(data)
	if err != nil || len(obj) != 3 || !collectionKeys(obj, "index", "id", "structure") {
		return row, errors.New("invalid collection row")
	}
	index, e1 := collectionInt(obj["index"])
	id, e2 := collectionInt(obj["id"])
	if e1 != nil || e2 != nil || index < 0 || index >= MaxFormCollectionRows {
		return row, errors.New("invalid collection row identity")
	}
	row.Index, row.ID = int(index), id
	structure, err := collectionObject(obj["structure"])
	if err != nil || !collectionKeys(structure, "fields", "#v", "v", "##sequence") || structure["v"] == nil {
		return row, errors.New("invalid collection row structure")
	}
	if raw, ok := structure["fields"]; ok {
		text, err := decodeFormJSONString(raw)
		if err != nil {
			return row, err
		}
		row.Fields = []int{}
		if text != "" {
			for _, part := range strings.Split(text, " ") {
				n, err := strconv.Atoi(part)
				if err != nil || n < 0 || n >= len(c.fields) || strconv.Itoa(n) != part {
					return row, errors.New("invalid collection field positions")
				}
				row.Fields = append(row.Fields, n)
			}
		}
	}
	positions, err := c.positions(row.Fields)
	if err != nil {
		return row, err
	}
	values, err := collectionArray(structure["v"])
	if err != nil || len(values) != len(positions) || !collectionProjectionSequence(structure, "v", len(values)) {
		return row, errors.New("collection field count mismatch")
	}
	if raw, ok := structure["#v"]; ok {
		tags, err := collectionArray(raw)
		if err != nil || len(tags) != len(values) {
			return row, errors.New("invalid collection type tags")
		}
		for i, rawTag := range tags {
			if bytes.Equal(rawTag, []byte("undefined")) {
				continue
			}
			tag, err := decodeFormJSONString(rawTag)
			if err != nil || (tag != "undefined" && !strings.EqualFold(tag, c.fields[positions[i]].Type)) {
				return row, errors.New("unsupported collection runtime type")
			}
		}
	}
	for i, raw := range values {
		v, err := c.values.Unmarshal(c.fields[positions[i]].Type, raw)
		if err != nil {
			return row, err
		}
		row.Values = append(row.Values, v)
	}
	return row, nil
}

// The native response projection records repeated XML children as an array and
// ##sequence sidecar. This is metadata, distinct from the actual operation log.
func collectionProjectionSequence(obj map[string][]byte, name string, count int) bool {
	raw, exists := obj["##sequence"]
	if !exists {
		return true
	}
	sequence, err := collectionArray(raw)
	if err != nil || len(sequence) != 2*count {
		return false
	}
	for i := 0; i < count; i++ {
		field, err := decodeFormJSONString(sequence[2*i])
		if err != nil || field != name {
			return false
		}
		index, err := collectionInt(sequence[2*i+1])
		if err != nil || index != int64(i) {
			return false
		}
	}
	return true
}

func (c FormCollectionCodec) positions(fields []int) ([]int, error) {
	if len(c.fields) == 0 {
		return nil, errors.New("uninitialized collection codec")
	}
	if fields == nil {
		fields = make([]int, len(c.fields))
		for i := range fields {
			fields[i] = i
		}
	}
	if len(fields) > len(c.fields) {
		return nil, errors.New("too many collection field positions")
	}
	seen := map[int]bool{}
	for _, index := range fields {
		if index < 0 || index >= len(c.fields) || seen[index] {
			return nil, errors.New("invalid or duplicate collection field position")
		}
		seen[index] = true
	}
	return fields, nil
}

func (c FormCollectionCodec) validate(d FormCollectionDelta) error {
	if len(c.fields) == 0 || d.Count < 0 || d.Count > MaxFormCollectionRows ||
		d.LastID < -1 || d.LastID > maxFormCollectionID ||
		d.FirstAddedLine < -1 || d.FirstAddedLine > MaxFormCollectionRows ||
		len(d.Operations) > MaxFormCollectionOperations || len(d.Rows) > d.Count || len(d.Totals) > len(c.fields) {
		return errors.New("invalid collection delta bounds")
	}
	seenIndex, seenID := map[int]bool{}, map[int64]bool{}
	cells := 0
	for _, row := range d.Rows {
		if row.Index < 0 || row.Index >= d.Count || row.ID < 0 || row.ID > d.LastID || seenIndex[row.Index] || seenID[row.ID] {
			return errors.New("invalid or duplicate collection row identity")
		}
		seenIndex[row.Index], seenID[row.ID] = true, true
		positions, err := c.positions(row.Fields)
		if err != nil || len(positions) != len(row.Values) {
			return errors.New("invalid collection row fields")
		}
		cells += len(row.Values)
		if cells > maxFormCollectionCells {
			return errors.New("too many collection delta cells")
		}
		for i, v := range row.Values {
			if !strings.EqualFold(v.Type, c.fields[positions[i]].Type) {
				return errors.New("collection value does not match declared monotype")
			}
		}
	}
	numeric := map[string]bool{}
	for _, field := range c.fields {
		if field.Type == NumberType {
			numeric[field.ID] = true
		}
	}
	seenTotal := map[string]bool{}
	for _, total := range d.Totals {
		if !numeric[total.ID] || seenTotal[total.ID] {
			return errors.New("invalid or duplicate collection total")
		}
		seenTotal[total.ID] = true
	}
	return nil
}

func operationMembers(op FormCollectionOperation) ([]string, []int64, error) {
	all := map[string]int64{"index": int64(op.Index), "index1": int64(op.Index1), "index2": int64(op.Index2),
		"id": op.ID, "startId": op.StartID, "delta": int64(op.Delta)}
	var keys []string
	switch op.Kind {
	case "add":
		keys = []string{"index", "id"}
	case "addRange":
		keys = []string{"index1", "index2", "startId"}
	case "remove":
		keys = []string{"index"}
	case "removeRange", "swap":
		keys = []string{"index1", "index2"}
	case "move":
		keys = []string{"index", "delta"}
	case "clear":
	default:
		return nil, nil, errors.New("unsupported collection operation")
	}
	values := make([]int64, len(keys))
	for i, key := range keys {
		value := all[key]
		switch key {
		case "id":
			if value < -1 || value > maxFormCollectionID {
				return nil, nil, errors.New("invalid collection add ID")
			}
		case "startId":
			if value < 0 || value > maxFormCollectionID-int64(op.Index2-op.Index1) {
				return nil, nil, errors.New("invalid collection range ID")
			}
		case "delta":
			if value < -MaxFormCollectionRows || value > MaxFormCollectionRows {
				return nil, nil, errors.New("invalid collection move distance")
			}
		default:
			if value < 0 || value > MaxFormCollectionRows {
				return nil, nil, errors.New("invalid collection operation index")
			}
		}
		values[i] = value
		delete(all, key)
	}
	for _, value := range all {
		if value != 0 {
			return nil, nil, errors.New("extraneous collection operation member")
		}
	}
	if (op.Kind == "addRange" || op.Kind == "removeRange") && op.Index2 < op.Index1 {
		return nil, nil, errors.New("reversed collection operation range")
	}
	return keys, values, nil
}

func marshalCollectionOperations(ops []FormCollectionOperation) ([]byte, error) {
	if len(ops) > MaxFormCollectionOperations {
		return nil, errors.New("too many collection operations")
	}
	sequence := []any{}
	order := []string{}
	groups := map[string][][]byte{}
	for _, op := range ops {
		keys, values, err := operationMembers(op)
		if err != nil {
			return nil, err
		}
		if _, ok := groups[op.Kind]; !ok {
			order = append(order, op.Kind)
		}
		sequence = append(sequence, op.Kind, len(groups[op.Kind]))
		raw := []byte{'{'}
		for i, key := range keys {
			if i > 0 {
				raw = append(raw, ',')
			}
			raw = append(raw, []byte(`"`+key+`":`+strconv.FormatInt(values[i], 10))...)
		}
		groups[op.Kind] = append(groups[op.Kind], append(raw, '}'))
	}
	rawSequence, _ := json.Marshal(sequence)
	out := append([]byte(`{"##sequence":`), rawSequence...)
	for _, kind := range order {
		out = append(out, []byte(`,"`+kind+`":[`)...)
		for i, raw := range groups[kind] {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, raw...)
		}
		out = append(out, ']')
	}
	return append(out, '}'), nil
}

func unmarshalCollectionOperations(data []byte) ([]FormCollectionOperation, error) {
	obj, err := collectionObject(data)
	if err != nil || !collectionKeys(obj, "##sequence", "add", "addRange", "remove", "removeRange", "swap", "move", "clear") {
		return nil, errors.New("invalid collection operations")
	}
	sequence, err := collectionArray(obj["##sequence"])
	if err != nil || len(sequence)%2 != 0 || len(sequence) > 2*MaxFormCollectionOperations {
		return nil, errors.New("invalid collection operation sequence")
	}
	groups := map[string][][]byte{}
	total := 0
	for kind, raw := range obj {
		if kind == "##sequence" {
			continue
		}
		group, err := collectionArray(raw)
		if err != nil {
			return nil, err
		}
		groups[kind] = group
		total += len(group)
	}
	if total != len(sequence)/2 {
		return nil, errors.New("unreferenced collection operations")
	}
	seen := map[string]bool{}
	out := make([]FormCollectionOperation, 0, total)
	for i := 0; i < len(sequence); i += 2 {
		kind, err := decodeFormJSONString(sequence[i])
		if err != nil {
			return nil, err
		}
		index, err := collectionInt(sequence[i+1])
		group := groups[kind]
		key := kind + ":" + strconv.FormatInt(index, 10)
		if err != nil || index < 0 || index >= int64(len(group)) || seen[key] {
			return nil, errors.New("invalid collection operation reference")
		}
		seen[key] = true
		members, err := collectionObject(group[index])
		if err != nil || !collectionKeys(members, "index", "index1", "index2", "id", "startId", "delta") {
			return nil, errors.New("invalid collection operation members")
		}
		op := FormCollectionOperation{Kind: kind}
		keys, _, err := operationMembers(op)
		if err != nil || len(members) != len(keys) {
			return nil, errors.New("invalid collection operation shape")
		}
		for _, name := range keys {
			n, err := collectionInt(members[name])
			if err != nil {
				return nil, err
			}
			switch name {
			case "id":
				op.ID = n
			case "startId":
				op.StartID = n
			case "index":
				if n < 0 || n > MaxFormCollectionRows {
					return nil, errors.New("invalid collection index")
				}
				op.Index = int(n)
			case "index1", "index2":
				if n < 0 || n > MaxFormCollectionRows {
					return nil, errors.New("invalid collection range index")
				}
				if name == "index1" {
					op.Index1 = int(n)
				} else {
					op.Index2 = int(n)
				}
			case "delta":
				if n < -MaxFormCollectionRows || n > MaxFormCollectionRows {
					return nil, errors.New("invalid collection delta")
				}
				op.Delta = int(n)
			}
		}
		if _, _, err := operationMembers(op); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, nil
}

// ApplyFormCollectionOperations applies the row-identity effect to a detached
// list and returns its historical lastId. Failure leaves the input untouched.
// It does not apply values, dropOld, counters, totals or acknowledgements.
func ApplyFormCollectionOperations(ids []int64, lastID int64, ops []FormCollectionOperation) ([]int64, int64, error) {
	fail := func() ([]int64, int64, error) {
		return nil, lastID, errors.New("invalid collection operation for current rows")
	}
	if len(ids) > MaxFormCollectionRows || lastID < -1 || lastID > maxFormCollectionID || len(ops) > MaxFormCollectionOperations {
		return fail()
	}
	out := append([]int64(nil), ids...)
	seen := map[int64]bool{}
	for _, id := range ids {
		if id < 0 || id > lastID || seen[id] {
			return fail()
		}
		seen[id] = true
	}
	next := lastID
	insert := func(index int, id int64) bool {
		if index < 0 || index > len(out) || len(out) >= MaxFormCollectionRows {
			return false
		}
		if id == -1 {
			if next == maxFormCollectionID {
				return false
			}
			id = next + 1
		}
		if seen[id] {
			return false
		}
		if id > next {
			next = id
		}
		out = append(out, 0)
		copy(out[index+1:], out[index:])
		out[index] = id
		seen[id] = true
		return true
	}
	remove := func(index int) {
		delete(seen, out[index])
		out = append(out[:index], out[index+1:]...)
	}
	for _, op := range ops {
		if _, _, err := operationMembers(op); err != nil {
			return fail()
		}
		switch op.Kind {
		case "add":
			if !insert(op.Index, op.ID) {
				return fail()
			}
		case "addRange":
			for index := op.Index1; index <= op.Index2; index++ {
				if !insert(index, op.StartID+int64(index-op.Index1)) {
					return fail()
				}
			}
		case "remove":
			if op.Index >= len(out) {
				return fail()
			}
			remove(op.Index)
		case "removeRange":
			if op.Index2 >= len(out) {
				return fail()
			}
			for index := op.Index2; index >= op.Index1; index-- {
				remove(index)
			}
		case "swap":
			if op.Index1 >= len(out) || op.Index2 >= len(out) {
				return fail()
			}
			out[op.Index1], out[op.Index2] = out[op.Index2], out[op.Index1]
		case "move":
			to := op.Index + op.Delta
			if op.Index >= len(out) || to < 0 || to >= len(out) {
				return fail()
			}
			id := out[op.Index]
			remove(op.Index)
			if !insert(to, id) {
				return fail()
			}
		case "clear":
			out = nil
			seen = map[int64]bool{}
		}
	}
	return out, next, nil
}

func collectionKeys(obj map[string][]byte, keys ...string) bool {
	for key := range obj {
		ok := false
		for _, allowed := range keys {
			ok = ok || key == allowed
		}
		if !ok {
			return false
		}
	}
	return true
}

func collectionInt(raw []byte) (int64, error) {
	if len(raw) == 0 || len(raw) > 17 {
		return 0, errors.New("invalid collection integer")
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || strconv.FormatInt(n, 10) != string(raw) {
		return 0, errors.New("invalid collection integer")
	}
	return n, nil
}

// This bounded lexical parser retains scalar tokens verbatim, including the
// platform's undefined token. It rejects duplicate object keys at every depth.
// It never evaluates source or converts numeric tokens to floating point.
type collectionParser struct {
	formScalarParser
	tokens int
}

func collectionObject(raw []byte) (map[string][]byte, error) {
	p := collectionParser{formScalarParser: formScalarParser{data: raw}}
	obj, _, err := p.object(0)
	p.space()
	if err != nil || p.pos != len(raw) {
		return nil, errors.New("invalid collection JSON object")
	}
	return obj, nil
}

func collectionArray(raw []byte) ([][]byte, error) {
	p := collectionParser{formScalarParser: formScalarParser{data: raw}}
	array, err := p.array(0)
	p.space()
	if err != nil || p.pos != len(raw) {
		return nil, errors.New("invalid collection JSON array")
	}
	return array, nil
}

func (p *collectionParser) object(depth int) (map[string][]byte, []byte, error) {
	p.space()
	start := p.pos
	if depth > 16 || !p.consume('{') {
		return nil, nil, errors.New("invalid collection object depth")
	}
	obj := map[string][]byte{}
	if p.consume('}') {
		return obj, p.data[start:p.pos], nil
	}
	for {
		rawKey, err := p.scalar()
		if err != nil {
			return nil, nil, err
		}
		key, err := decodeFormJSONString(rawKey)
		if err != nil || len(key) > 128 || !p.consume(':') {
			return nil, nil, errors.New("invalid collection object key")
		}
		if _, ok := obj[key]; ok {
			return nil, nil, errors.New("duplicate collection object key")
		}
		raw, err := p.value(depth + 1)
		if err != nil {
			return nil, nil, err
		}
		obj[key] = raw
		if p.consume('}') {
			return obj, p.data[start:p.pos], nil
		}
		if !p.consume(',') {
			return nil, nil, errors.New("invalid collection object separator")
		}
	}
}

func (p *collectionParser) array(depth int) ([][]byte, error) {
	if depth > 16 || !p.consume('[') {
		return nil, errors.New("invalid collection array depth")
	}
	out := [][]byte{}
	if p.consume(']') {
		return out, nil
	}
	for {
		raw, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
		if p.consume(']') {
			return out, nil
		}
		if !p.consume(',') {
			return nil, errors.New("invalid collection array separator")
		}
	}
}

func (p *collectionParser) value(depth int) ([]byte, error) {
	p.space()
	start := p.pos
	p.tokens++
	if depth > 16 || p.tokens > 200000 || p.pos >= len(p.data) {
		return nil, errors.New("collection JSON bounds exceeded")
	}
	switch p.data[p.pos] {
	case '{':
		_, raw, err := p.object(depth)
		return raw, err
	case '[':
		_, err := p.array(depth)
		return p.data[start:p.pos], err
	case '"':
		raw, err := p.scalar()
		if err != nil {
			return nil, err
		}
		if _, err := decodeFormJSONString(raw); err != nil {
			return nil, err
		}
		return raw, nil
	default:
		for p.pos < len(p.data) && !bytes.ContainsRune([]byte(",]} \t\r\n"), rune(p.data[p.pos])) {
			p.pos++
		}
		raw := p.data[start:p.pos]
		if bytes.Equal(raw, []byte("undefined")) || json.Valid(raw) {
			return raw, nil
		}
		return nil, errors.New("invalid collection scalar token")
	}
}
