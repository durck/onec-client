package onec

import (
	"errors"
	"strings"
)

// These fields retain wBb's order (18 mainform:1653-1656). A sorted Go map
// provably fails native XDTO conversion at list before remoteKey is consumed.
type dynamicListRequest struct {
	RemoteKey string `json:"remoteKey"`
	DataPath  struct {
		ID []string `json:"id"`
	} `json:"dataPath"`
	TableID uint64 `json:"tableId"`
	CacheID string `json:"cacheID"`
	List    struct {
		ChangeState      int      `json:"ChangeState"`
		SettingsComposer struct{} `json:"SettingsComposer"`
	} `json:"list"`
	ChoiceMode    bool                    `json:"choiceMode"`
	FormUUID      string                  `json:"formUUID"`
	Refresh       bool                    `json:"refresh"`
	Forward       bool                    `json:"forward"`
	Autopos       bool                    `json:"autopos"`
	Page          int                     `json:"page"`
	CurrentType   string                  `json:"#current,omitempty"`
	Current       any                     `json:"current,omitempty"`
	Source        int                     `json:"source"`
	ShowTree      bool                    `json:"showTree"`
	FilterTypes   []string                `json:"#filter"`
	Filter        []any                   `json:"filter"`
	Level         int                     `json:"level"`
	Period        dynamicListPeriod       `json:"period"`
	Presents      bool                    `json:"presents"`
	Search        []dynamicListSearchWire `json:"search,omitempty"`
	AllowAsync    bool                    `json:"allowAsync"`
	WaitTime      int                     `json:"waitTime"`
	NeedDataDescr bool                    `json:"needDataDescr"`
}

type dynamicListPeriod struct {
	Start   string `json:"startDate"`
	End     string `json:"endDate"`
	Type    string `json:"#variant"`
	Variant string `json:"variant"`
}

type dynamicListSearchWire struct {
	Path  string `json:"path"`
	Type  string `json:"#value"`
	Value any    `json:"value"`
}

func dynamicListQuery(list DynamicList, options DynamicListWindowOptions) (dynamicListRequest, error) {
	r := dynamicListRequest{}
	s := list.state
	if s == nil {
		return r, errors.New("invalid dynamic-list binding")
	}
	if options.Limit < 0 || options.Limit > 1000 {
		return r, errors.New("dynamic-list window limit must be 1 to 1000")
	}
	r.Page = options.Limit
	if r.Page == 0 {
		r.Page = 40
	}
	r.RemoteKey = snapshotString(s.form.state.descriptor, "remotekey")
	r.DataPath.ID = append([]string(nil), s.path...)
	r.TableID = s.tableID
	r.CacheID = dynamicListEmptyCache
	r.FormUUID = s.form.fid
	r.Refresh = true
	r.Forward = true
	r.Autopos = options.After == nil
	r.FilterTypes = []string{}
	r.Filter = []any{}
	r.Level = -1
	r.Period = dynamicListPeriod{snapshotString(s.period, "startDate"), snapshotString(s.period, "endDate"), snapshotString(s.period, "#variant"), "Custom"}
	r.Presents = true
	r.WaitTime = 200
	r.NeedDataDescr = true
	if options.After != nil {
		if options.After.owner != s {
			return r, errors.New("dynamic-list bookmark belongs to another binding")
		}
		v, err := encodeFormValue(options.After.value)
		if err != nil {
			return r, err
		}
		r.CurrentType = options.After.value.Type
		r.Current = v
	}
	if options.Search != nil {
		name := ""
		for _, column := range s.columns {
			if strings.EqualFold(column.Name, options.Search.Field) {
				name = column.Name
			}
		}
		if name == "" {
			return r, errors.New("unknown dynamic-list search field")
		}
		if options.Search.Value.Type != StringType && options.Search.Value.Type != NumberType && options.Search.Value.Type != BooleanType && options.Search.Value.Type != DateType {
			return r, errors.New("unsupported dynamic-list search value")
		}
		v, err := encodeFormValue(options.Search.Value)
		if err != nil {
			return r, err
		}
		r.Search = []dynamicListSearchWire{{name, options.Search.Value.Type, v}}
	}
	return r, nil
}
