// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package marshal

import (
	"os"
	"testing"
)

type testStruct struct {
	StringVal string
	IntVal    int
}

var tmp *testStruct

func init() {
	tmp = &testStruct{
		StringVal: "strVal",
		IntVal:    134,
	}
	os.MkdirAll("/tmp/marshal", os.ModePerm)
}

func Test_ToJSON(t *testing.T) {
	str, err := ToJSON(tmp)
	if err != nil {
		t.Errorf("Failed to Marshal to JSON")
	}
	t.Logf("%+v", str)
}
func Test_ToJSONFile(t *testing.T) {
	err := ToJSONFile(tmp, "/tmp/marshal/tmp.json")
	if err != nil {
		t.Errorf("Failed to Marshal to JSON")
	}
}
func Test_FromJSONFile(t *testing.T) {
	newTmp := testStruct{}
	err := FromJSONFile("/tmp/marshal/tmp.json", &newTmp)
	if err != nil {
		t.Errorf("Failed to Marshal to JSON")
	}
	t.Logf("%+v", newTmp)
}

func Test_FromJSON(t *testing.T) {
	var result struct {
		Value string `json:"value,omitempty"`
		Data  int    `json:"Data,omitempty"`
	}

	err := FromJSON(`{"value": "test", "Data": 1234}`, &result)
	if err != nil {
		t.Errorf("Failed to Marshal from JSON - %v", err)
	}
	str, err := ToJSON(result)
	t.Logf("%s", str)
}
func Test_ToYAML(t *testing.T) {
	str, err := ToYAML(tmp)
	if err != nil {
		t.Errorf("Failed to Marshal to YAML")
	}
	t.Logf("%+v", str)

}
func Test_FromYAML(t *testing.T) {}

func Test_ToYAMLFile(t *testing.T) {
	err := ToYAMLFile(tmp, "/tmp/marshal/tmp.json")
	if err != nil {
		t.Errorf("Failed to Marshal to JSON")
	}
}
func Test_FromYAMLFile(t *testing.T) {
	newTmp := testStruct{}
	err := FromYAMLFile("/tmp/marshal/tmp.json", &newTmp)
	if err != nil {
		t.Errorf("Failed to Marshal to JSON")
	}
	t.Logf("%+v", newTmp)
}

func Test_ToString(t *testing.T) {
	str := ToString(tmp)
	if len(str) == 0 {
		t.Errorf("Failed to Marshal to String")
	}
	t.Logf("%+v", str)

}

func Test_Duplicate(t *testing.T) {
	tmp1 := &testStruct{}
	err := Duplicate(tmp, tmp1)
	if err != nil {
		t.Errorf("Failed to Duplicate struct ")
	}
	t.Logf("Src: [%s], Dst [%s]", ToString(tmp), ToString(tmp1))

}
