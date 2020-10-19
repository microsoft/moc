// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package config

import (
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/jmespath/go-jmespath"
	"github.com/microsoft/moc/pkg/marshal"
)

// Load the virtual machine configuration from the specified path
func LoadYAMLFile(path string, outData interface{}) (err error) {
	err = marshal.FromYAMLFile(path, outData)
	if err != nil {
		return
	}

	return
}

// Load the virtual machine configuration from the specified path
func LoadYAMLConfig(data string, outData interface{}) (err error) {
	err = marshal.FromYAMLString(data, outData)
	if err != nil {
		return
	}

	return
}

// PrintYAML
func PrintYAML(data interface{}) {
	str, err := marshal.ToYAML(data)
	if err != nil {
		return
	}
	fmt.Printf("%s", str)
}

// PrintYAMLList
func PrintYAMLList(datasets interface{}) {
	items := reflect.ValueOf(datasets)
	if items.Kind() == reflect.Slice {
		for i := 0; i < items.Len(); i++ {
			PrintYAML(items.Index(i).Interface())
		}
	}
}

// PrintJSON
func PrintJSON(data interface{}) {
	str, err := marshal.ToJSON(data)
	if err != nil {
		return
	}
	fmt.Printf("%s", str)
}

// PrintJSONList
func PrintJSONList(datasets interface{}) {
	items := reflect.ValueOf(datasets)
	if items.Kind() == reflect.Slice {
		for i := 0; i < items.Len(); i++ {
			PrintJSON(items.Index(i).Interface())
		}
	}
}

func printHeader(data reflect.Value) {
	item := reflect.Indirect(data)
	for i := 0; i < item.NumField(); i++ {
		// For now, printing only string elements
		if item.Field(i).Kind() == reflect.String {
			fmt.Printf("%s ", item.Type().Field(i).Name)
		}
	}
	fmt.Println()
}

func printElement(data reflect.Value) {
	items := reflect.Indirect(data)
	for i := 0; i < items.NumField(); i++ {
		// For now, printing only string elements
		if items.Field(i).Kind() == reflect.String {
			fmt.Printf("%s ", items.Field(i).Interface())
		}
	}
	fmt.Println()
}

// PrintTable
func PrintTable(datasets interface{}) {
	items := reflect.ValueOf(datasets)
	if items.Kind() == reflect.Slice && items.Len() > 0 {
		printHeader(items.Index(0))
		for i := 0; i < items.Len(); i++ {
			printElement(items.Index(i))
		}
	}

}

// Load the secret configuration from the specified path
func LoadValueFile(path string) (*string, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := string(contents)

	return &value, nil
}

func ExportFormatList(datasets interface{}, path string, query string, outputType string) error {
	var fileToWrite string

	marshaledByte, err := MarshalOutput(datasets, query, outputType)
	if err != nil {
		fmt.Printf("%v", err)
		return err
	}
	fileToWrite += string(marshaledByte)

	err = ioutil.WriteFile(
		path,
		[]byte(fileToWrite),
		0644)
	return err
}

func PrintFormat(data interface{}, query string, outputType string) {
	marshaledByte, err := MarshalOutput(data, query, outputType)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}
	fmt.Printf("%s\n", string(marshaledByte))
}

func PrintFormatList(datasets interface{}, query string, outputType string) {
	PrintFormat(datasets, query, outputType)
}

func MarshalOutput(data interface{}, query string, outputType string) ([]byte, error) {
	var queryTarget interface{}
	var result interface{}
	var err error

	jsonByte, err := marshal.ToJSONBytes(data)
	if err != nil {
		return nil, err
	}
	marshal.FromJSONBytes(jsonByte, &queryTarget)
	if query != "" {
		result, err = jmespath.Search(query, queryTarget)
		if err != nil {
			return nil, err
		}
	} else {
		result = queryTarget
	}

	var marshaledByte []byte
	if outputType == "json" {
		marshaledByte, err = marshal.ToJSONBytes(result)
	} else if outputType == "tsv" {
		marshaledByte, err = marshal.ToTSVBytes(result)
	} else if outputType == "csv" {
		marshaledByte, err = marshal.ToCSVBytes(result)
	} else {
		marshaledByte, err = marshal.ToYAMLBytes(result)
	}

	if err != nil {
		return nil, err
	}

	return marshaledByte, nil
}
