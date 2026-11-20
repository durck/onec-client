package onec

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"onec/wire"
	"strconv"
	"strings"
	"unicode/utf16"
)

type dynamicListCompact struct {
	description, rows []byte
	dataName, key     string
	first, last       bool
}

func decodeDynamicListWindow(doc map[string]any, owner *dynamicListState, limit int) (DynamicListWindow, error) {
	out := DynamicListWindow{Columns: append([]DynamicListColumn(nil), owner.columns...)}
	bad := func() (DynamicListWindow, error) {
		return DynamicListWindow{}, errors.New("unsupported or malformed dynamic-list window")
	}
	flag := func(doc map[string]any, key string) (bool, bool) {
		v, exists := doc[key]
		if !exists {
			return false, true
		}
		b, ok := v.(bool)
		return b, ok
	}
	progress, ok := flag(doc, "inProgress")
	if !ok {
		return bad()
	}
	if progress {
		if snapshotNonempty(doc["forward"]) || snapshotNonempty(doc["backward"]) {
			return bad()
		}
		token, ok := doc["backgroundSearchInfo"].(string)
		if !ok || !validValueText(token, 8192) {
			return bad()
		}
		out.InProgress = true
		return out, nil
	}
	if level, ok := doc["level"].(json.Number); !ok || level.String() != "-1" {
		return bad()
	}
	for _, key := range []string{"hierarhy", "normalizeKeys"} {
		b, ok := flag(doc, key)
		if !ok || b {
			return bad()
		}
	}
	for _, key := range []string{"opened", "disGroup", "cas", "sortTuplesData"} {
		if snapshotNonempty(doc[key]) {
			return bad()
		}
	}
	if raw, exists := doc["backward"]; exists {
		list, ok := raw.([]any)
		if !ok || len(list) > 1 {
			return bad()
		}
		if len(list) == 1 {
			chunk, ok := list[0].(map[string]any)
			if !ok || len(chunk) != 1 || chunk["intentionallyEmpty"] != true {
				return bad()
			}
		}
	}
	forward, ok := doc["forward"].([]any)
	if !ok || len(forward) != 1 {
		return bad()
	}
	chunk, ok := forward[0].(map[string]any)
	if !ok {
		return bad()
	}
	if chunk["intentionallyEmpty"] == true {
		if len(chunk) != 1 {
			return bad()
		}
		out.Encoding = "empty"
		return out, nil
	}
	first, ok := flag(chunk, "fif")
	if !ok {
		return bad()
	}
	last, ok := flag(chunk, "lil")
	if !ok {
		return bad()
	}
	name, ok := chunk["dataName"].(string)
	if !ok || name != "DynamicListRow" {
		return bad()
	}
	key, ok := chunk["key"].(string)
	if !ok || !validValueText(key, 1024) {
		return bad()
	}
	out.First = first
	out.Last = last
	description, descCompact := chunk["dataDescrData"]
	rows, rowsCompact := chunk["rowsData"]
	if descCompact || rowsCompact {
		if !descCompact || chunk["dataDescr"] != nil || chunk["rows"] != nil {
			return bad()
		}
		decode := func(raw any) ([]byte, error) {
			s, ok := raw.(string)
			if !ok || len(s) > 2<<20 {
				return nil, errors.New("invalid compact window")
			}
			return base64.StdEncoding.Strict().DecodeString(s)
		}
		d, e := decode(description)
		if e != nil || len(d) == 0 {
			return bad()
		}
		// OBb treats an omitted rows member as an empty row sequence. The
		// native end-of-list reply likewise retains its descriptor and omits
		// rowsData. Normalize only that absence to the known empty ListStream.
		r, _ := wire.Pack([]any{0})
		if rowsCompact {
			r, e = decode(rows)
			if e != nil || len(r) == 0 {
				return bad()
			}
		}
		out.Encoding = "compact"
		return decodeDynamicListCompact(dynamicListCompact{d, r, name, key, first, last}, owner, limit, out)
	}
	return bad()
}

func decodeDynamicListCompact(chunk dynamicListCompact, owner *dynamicListState, limit int, out DynamicListWindow) (DynamicListWindow, error) {
	unsupported := func() (DynamicListWindow, error) {
		out.Rows = nil
		return out, fmt.Errorf("%w", ErrDynamicListCompactRows)
	}
	if len(chunk.rows) > 1<<20 {
		return unsupported()
	}
	descr, err := dynamicListDescriptionAtoms(chunk.description)
	if err != nil {
		return unsupported()
	}
	tree, err := dynamicListTree(descr)
	if err != nil || len(tree) != 1 {
		return unsupported()
	}
	root, ok := wire.List(tree[0], 7)
	if !ok || !wire.IsNumber(root[0], 0) || !wire.IsNumber(root[1], 1) {
		return unsupported()
	}
	for _, raw := range root[3:] {
		if !wire.IsNumber(raw, 0) {
			return unsupported()
		}
	}
	table, ok := wire.List(root[2], 3)
	if !ok || !wire.IsNumber(table[0], 0) {
		return unsupported()
	}
	name, err := dynamicListAtomString(table[2])
	if err != nil || name != chunk.dataName {
		return unsupported()
	}
	fields, ok := wire.List(table[1], -1)
	if !ok || len(fields) < 2 || !wire.IsNumber(fields[0], 0) {
		return unsupported()
	}
	count, err := wire.Number(fields[1])
	if err != nil || count == 0 || count > 129 || len(fields) != int(count)+2 {
		return unsupported()
	}
	names := make([]string, count)
	types := make([]string, count)
	seenNames := map[string]bool{}
	seenIDs := map[uint32]bool{}
	keyIndex := -1
	for i, raw := range fields[2:] {
		field, ok := wire.List(raw, 7)
		if !ok {
			return unsupported()
		}
		idPath, ok := wire.List(field[0], 1)
		if !ok {
			return unsupported()
		}
		id, err := wire.Number(idPath[0])
		if err != nil || id == 0 || seenIDs[id] {
			return unsupported()
		}
		seenIDs[id] = true
		name, err := dynamicListAtomString(field[1])
		if err != nil || !validValueText(name, 1024) {
			return unsupported()
		}
		alias, err := dynamicListAtomString(field[2])
		if err != nil || name != alias || seenNames[strings.ToUpper(name)] {
			return unsupported()
		}
		seenNames[strings.ToUpper(name)] = true
		names[i] = name
		pattern, ok := wire.List(field[3], 3)
		if !ok || !wire.IsNumber(pattern[0], 0) || !wire.IsNumber(pattern[1], 0) {
			return unsupported()
		}
		pair, ok := wire.List(pattern[2], 2)
		if !ok || !wire.IsString(pair[0], "Pattern") {
			return unsupported()
		}
		tag, ok := wire.List(pair[1], -1)
		if !ok {
			return unsupported()
		}
		switch {
		case len(tag) == 1 && wire.IsString(tag[0], "N"):
			types[i] = NumberType
		case len(tag) == 3 && wire.IsString(tag[0], "S") && wire.IsNumber(tag[1], 6) && wire.IsNumber(tag[2], 1):
			types[i] = StringType
		default:
			return unsupported()
		}
		if !wire.IsNumber(field[5], 0) || !wire.IsNumber(field[6], 0) {
			return unsupported()
		}
		if name == chunk.key {
			if keyIndex >= 0 || !wire.IsNumber(field[4], 2) {
				return unsupported()
			}
			keyIndex = i
		} else if !wire.IsNumber(field[4], 0) {
			return unsupported()
		}
	}
	if keyIndex < 0 || len(owner.columns) != len(names)-1 {
		return unsupported()
	}
	for _, column := range owner.columns {
		if !seenNames[strings.ToUpper(column.Name)] || column.Name == chunk.key {
			return unsupported()
		}
	}
	rowAtoms, err := wire.DecodeAtoms(chunk.rows)
	if err != nil {
		return unsupported()
	}
	rowsTree, err := dynamicListTree(rowAtoms)
	if err != nil || len(rowsTree) != 1 {
		return unsupported()
	}
	rows, ok := wire.List(rowsTree[0], -1)
	if !ok || len(rows) == 0 {
		return unsupported()
	}
	rowCount, err := wire.Number(rows[0])
	if err != nil || rowCount > uint32(limit) || len(rows) != int(rowCount)+1 {
		return unsupported()
	}
	result := make([]DynamicListRow, rowCount)
	seenKeys := map[string]bool{}
	for i, raw := range rows[1:] {
		row, ok := wire.List(raw, len(names))
		if !ok {
			return unsupported()
		}
		values := make([]Value, len(names))
		for j, raw := range row {
			value, ok := wire.List(raw, 2)
			if !ok {
				return unsupported()
			}
			switch types[j] {
			case NumberType:
				if !wire.IsString(value[0], "N") {
					return unsupported()
				}
				n, err := wire.Number(value[1])
				if err != nil {
					return unsupported()
				}
				values[j] = Value{Type: NumberType, Value: Decimal(strconv.FormatUint(uint64(n), 10))}
			case StringType:
				if !wire.IsString(value[0], "S") {
					return unsupported()
				}
				s, err := wire.String(value[1])
				if err != nil || len(utf16.Encode([]rune(s))) > 6 {
					return unsupported()
				}
				values[j] = StringValue(s)
			}
		}
		key := values[keyIndex]
		identity := key.Type + ":" + fmt.Sprint(key.Value)
		if seenKeys[identity] {
			return unsupported()
		}
		seenKeys[identity] = true
		cells := map[string]Value{}
		for _, column := range owner.columns {
			for j, name := range names {
				if strings.EqualFold(name, column.Name) {
					cells[column.Name] = values[j]
				}
			}
		}
		result[i] = DynamicListRow{Values: cells, Bookmark: DynamicListBookmark{owner: owner, value: key}}
	}
	out.Rows = result
	return out, nil
}

// Code 23 is observed only in the native dynamic description: one unsigned
// byte containing a UTF-16 code-unit count, followed by UTF-16LE. Restrict it to
// 1..127 units; longer/alternate length encodings have not been established.
// The general wire decoder remains unchanged.
func dynamicListDescriptionAtoms(data []byte) ([]wire.Atom, error) {
	bad := func() ([]wire.Atom, error) { return nil, errors.New("unsupported compact dynamic-list description") }
	if len(data) == 0 || len(data) > 64<<10 {
		return bad()
	}
	atoms := []wire.Atom{}
	for pos := 0; pos < len(data); {
		start := pos
		tag := data[pos]
		code := tag & 31
		pos++
		if code == 23 {
			if pos == len(data) {
				return bad()
			}
			units := int(data[pos])
			pos++
			if units == 0 || units > 127 || units > (len(data)-pos)/2 {
				return bad()
			}
			chars := make([]uint16, units)
			for i := range chars {
				chars[i] = binary.LittleEndian.Uint16(data[pos+2*i:])
			}
			for i := 0; i < len(chars); i++ {
				if chars[i] >= 0xd800 && chars[i] <= 0xdbff {
					if i+1 == len(chars) || chars[i+1] < 0xdc00 || chars[i+1] > 0xdfff {
						return bad()
					}
					i++
				} else if chars[i] >= 0xdc00 && chars[i] <= 0xdfff {
					return bad()
				}
			}
			pos += units * 2
			atoms = append(atoms, wire.Atom{Offset: start, End: pos, Tag: tag, Kind: "dynamic-list-utf16", Value: string(utf16.Decode(chars))})
			if len(atoms) > 4096 {
				return bad()
			}
			continue
		}
		n := 0
		switch {
		case code == 0 || code <= 10:
		case code == 11:
			n = 1
		case code == 13:
			n = 2
		case code == 15:
			n = 4
		case code == 21:
			n = 16
		case code == 26:
			if pos == len(data) {
				return bad()
			}
			n = 1 + int(data[pos])
		case code == 27:
			if len(data)-pos < 2 {
				return bad()
			}
			n = 2 + int(binary.LittleEndian.Uint16(data[pos:]))
		default:
			return bad()
		}
		if n > len(data)-pos {
			return bad()
		}
		pos += n
		decoded, err := wire.DecodeAtoms(data[start:pos])
		if err != nil || len(decoded) != 1 {
			return bad()
		}
		a := decoded[0]
		a.Offset = start
		a.End = pos
		atoms = append(atoms, a)
		if len(atoms) > 4096 {
			return bad()
		}
	}
	return atoms, nil
}

func dynamicListAtomString(raw any) (string, error) {
	if atom, ok := raw.(wire.Atom); ok && atom.Kind == "dynamic-list-utf16" {
		text, ok := atom.Value.(string)
		if ok {
			return text, nil
		}
	}
	return wire.String(raw)
}

func dynamicListTree(atoms []wire.Atom) ([]any, error) {
	bad := func() ([]any, error) { return nil, errors.New("invalid compact dynamic-list structure") }
	if len(atoms) > 10000 {
		return bad()
	}
	counts := []int{0}
	for _, atom := range atoms {
		if atom.Tag&32 != 0 {
			if len(counts) == 1 {
				return bad()
			}
			counts = counts[:len(counts)-1]
		}
		if atom.Tag&64 != 0 || atom.Kind != "structure" {
			if (atom.Tag&128 != 0) != (counts[len(counts)-1] > 0) {
				return bad()
			}
			counts[len(counts)-1]++
		}
		if atom.Tag&64 != 0 {
			if len(counts) >= 32 {
				return bad()
			}
			children := 0
			if atom.Kind != "structure" {
				children = 1
			}
			counts = append(counts, children)
		} else if atom.Kind == "structure" && atom.Tag != 32 {
			return bad()
		}
	}
	if len(counts) != 1 {
		return bad()
	}
	return wire.BuildTree(atoms)
}
