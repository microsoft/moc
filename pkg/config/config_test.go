// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.
package config

import (
	"fmt"
	"testing"

	"github.com/microsoft/moc/pkg/marshal"
)

type SampleStruct struct {
	TestString  string   `json:"testString,omitempty" yaml:testString,omitempty"`
	TestString2 string   `json:"testStrings,omitempty" yaml:testString,omitempty"`
	TestInt     int      `json:"testInt,omitempty" yaml:"testInt,omitempty"`
	TestArray   []string `json:"testArray,omitempty" yaml:"testArray,omitempty"`
}

var tmp = SampleStruct{
	TestString:  "TestString",
	TestString2: "TestString2",
	TestInt:     1,
	TestArray:   []string{"TestArray"},
}

var tmpArray = []SampleStruct{
	{
		TestString:  "test1String",
		TestString2: "test1String2",
		TestInt:     1,
		TestArray:   []string{"test1Array"},
	},
	{
		TestString:  "test2String",
		TestString2: "test2String2",
		TestInt:     2,
		TestArray:   []string{"test2Array"},
	},
}

func Test_LoadYAMLConfig(t *testing.T) {
	tmpString := `teststring: TestString
testInt: 1
testArray:
- TestArray`

	tmpData := SampleStruct{}
	err := LoadYAMLConfig(tmpString, &tmpData)
	if err != nil {
		t.Errorf("Failed to load Yaml Config" + err.Error())
	}
}
func Test_PrintYAML(t *testing.T) {
	tmp := SampleStruct{
		TestString: "TestString",
		TestInt:    1,
		TestArray:  []string{"TestArray"},
	}
	PrintYAML(tmp)
}
func Test_PrintJSON(t *testing.T) {
	PrintJSON(tmp)
}
func Test_PrintYAMLList(t *testing.T) {
	PrintYAMLList(tmpArray)
}
func Test_PrintJSONList(t *testing.T) {
	PrintJSONList(tmpArray)
}
func Test_PrintTable(t *testing.T) {
	PrintTable(tmpArray)
}

func Test_PrintFormat(t *testing.T) {
	PrintFormat(tmp, "", "tsv")
	PrintFormat(tmp, "", "csv")
}

func Test_PrintFormatList(t *testing.T) {
	PrintFormatList(tmpArray, "", "tsv")
	PrintFormatList(tmpArray, "", "csv")
}

func Test_MarshalOutputWithoutQuery(t *testing.T) {
	err := verifyMarshalOutput(tmpArray, "", 2)
	if err != nil {
		t.Errorf("MarshalOutput with empty query failed: %s", err.Error())
	}
}

func Test_MarshalOutputWithIntQuery(t *testing.T) {
	err := verifyMarshalOutput(tmpArray, "[?testInt==`2`]", 1)
	if err != nil {
		t.Errorf("MarshalOutput with int query failed: %s", err.Error())
	}
}

func Test_MarshalOutputWithStringQuery(t *testing.T) {
	err := verifyMarshalOutput(tmpArray, "[?testString=='test1String']", 1)
	if err != nil {
		t.Errorf("MarshalOutput with string query failed: %s", err.Error())
	}
}

func verifyMarshalOutput(data interface{}, query string, expectedResultCount int) error {
	result, err := MarshalOutput(data, query, "json")
	if err != nil {
		return err
	}

	var filteredArray []SampleStruct
	err = marshal.FromJSONBytes(result, &filteredArray)
	if err != nil {
		return err
	}

	if len(filteredArray) != expectedResultCount {
		return fmt.Errorf("Unexpected result count. Expected: %d / Actual: %d", expectedResultCount, len(filteredArray))
	}

	return nil
}
