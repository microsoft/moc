// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package marshal

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
	"sort"

	"gopkg.in/yaml.v3"
)

func Duplicate(data interface{}, duplicatedData interface{}) error {
	dataBytes, err := ToJSONBytes(data)
	if err != nil {
		return err
	}
	err = FromJSONBytes(dataBytes, duplicatedData)
	if err != nil {
		return err
	}
	return nil
}
func ToString(data interface{}) string {
	yamlStr, _ := ToYAML(data)
	return yamlStr
}

func ToJSON(data interface{}) (string, error) {
	jsonBytes, err := ToJSONBytes(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
func ToJSONBytes(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

func ToPrettyPrintedJSONBytes(data interface{}) ([]byte, error) {
	return json.MarshalIndent(data, "", "    ")
}

// json.Marshal writes some characters (e.g. '<') as unicode. This stops that to make logsa easier to read.
func ToUnescapedJSONBytes(data interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	e := json.NewEncoder(&buffer)
	e.SetEscapeHTML(false)
	err := e.Encode(data)
	return buffer.Bytes(), err
}

// ToJSONFile writes the data to path in YAML format
func ToJSONFile(data interface{}, path string) error {
	enc, err := ToJSONBytes(data)
	if err != nil {
		return err

	}

	err = ioutil.WriteFile(path, enc, 0644)
	if err != nil {
		return err
	}
	return nil
}

func FromJSON(jsonString string, object interface{}) error {
	return json.Unmarshal([]byte(jsonString), object)
}

func FromJSONBytes(jsonBytes []byte, object interface{}) error {
	return json.Unmarshal(jsonBytes, object)
}

func FromJSONFile(path string, object interface{}) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return FromJSONBytes(contents, object)
}

func ToBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func FromBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func ToBase64URL(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func FromBase64URL(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}

func ToYAML(data interface{}) (string, error) {
	yamlBytes, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}
func ToYAMLBytes(data interface{}) ([]byte, error) {
	return yaml.Marshal(data)
}

func FingerprintObject(data interface{}) (*[]byte, error) {
	yamlBytes, err := ToJSONBytes(data)
	if err != nil {
		return nil, err
	}

	// Generate the figerprint
	sum := sha512.Sum512(yamlBytes)
	sumSlice := sum[:]
	return &sumSlice, nil
}

// ToYAMLFile writes the data to path in YAML format
func ToYAMLFile(data interface{}, path string) error {
	enc, err := ToYAMLBytes(data)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, enc, 0644)
	if err != nil {
		return err
	}
	return nil
}

func FromYAMLBytes(yamlData []byte, object interface{}) error {
	return yaml.Unmarshal(yamlData, object)
}

func FromYAMLString(yamlString string, object interface{}) error {
	return FromYAMLBytes([]byte(yamlString), object)
}

func FromYAMLFile(path string, object interface{}) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return FromYAMLBytes(contents, object)
}

func ToTSV(data interface{}) (string, error) {
	jsonBytes, err := ToTSVBytes(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func ToTSVBytes(data interface{}) ([]byte, error) {
	return marshalTSV(data)
}

func marshalTSV(result interface{}) ([]byte, error) {
	var bytes []byte
	items := reflect.ValueOf(result)
	if items.Kind() == reflect.Slice {
		for i := 0; i < items.Len(); i++ {
			str, err := marshalOneTSVElement(items.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			bytes = append(bytes, str...)
			if i < items.Len()-1 {
				bytes = append(bytes, '\n')
			}
		}
	} else {
		str, err := marshalOneTSVElement(result)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, str...)
	}

	return bytes, nil
}

func marshalOneTSVElement(result interface{}) ([]byte, error) {
	var str []byte
	switch v := result.(type) {
	case string:
		str = []byte(v)
	case map[string]interface{}:
		var tabString string

		// golang maps purposely store keys and values in a random order.
		// The order typically changes from one map instance to another.
		// In order to provide result consistency, we first sort keys
		// alphabetically then get the associated values
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, key := range keys {
			typ, ok := v[key].(string)
			if ok && typ != "" {
				tabString += typ
				if i < len(keys)-1 {
					tabString += "\t"
				}
			}
		}
		str = []byte(tabString)
	default:
		return nil, fmt.Errorf("Unsupported Format")
	}
	return str, nil
}

func ToCSV(data interface{}) (string, error) {
	jsonBytes, err := marshalCSV(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func ToCSVBytes(data interface{}) ([]byte, error) {
	return marshalCSV(data)
}

func marshalCSV(result interface{}) ([]byte, error) {
	var bytes []byte
	items := reflect.ValueOf(result)
	if items.Kind() == reflect.Slice {
		for i := 0; i < items.Len(); i++ {
			str, err := marshalOneCSVElement(items.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			bytes = append(bytes, str...)
			if i < items.Len()-1 {
				bytes = append(bytes, '\n')
			}
		}
	} else {
		str, err := marshalOneCSVElement(result)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, str...)
	}

	return bytes, nil
}

func marshalOneCSVElement(result interface{}) ([]byte, error) {
	var str []byte
	switch v := result.(type) {
	case string:
		str = []byte(v)
	case map[string]interface{}:
		var tabString string

		// golang maps purposely store keys and values in a random order.
		// The order typically changes from one map instance to another.
		// In order to provide result consistency, we first sort keys
		// alphabetically then get the associated values
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, key := range keys {
			typ, ok := v[key].(string)
			if ok && typ != "" {
				tabString += typ
				if i < len(keys)-1 {
					tabString += ","
				}
			}
		}
		str = []byte(tabString)
	default:
		return nil, fmt.Errorf("Unsupported Format")
	}
	return str, nil
}
