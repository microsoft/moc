// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package redact

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	descriptorpb "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/microsoft/moc/rpc/common"
)

const (
	RedactedString = "** Redacted **"
)

// RedactedMessage - returns a copy of a proto message struct with data from fields marked as sensitive redacted
func RedactedMessage(msg interface{}) interface{} {
	rMsg := proto.Clone((msg).(proto.Message))
	Redact(rMsg, reflect.ValueOf(rMsg))
	return rMsg
}

// Redact - removes data from fields marked as sensitive given a proto message struct
func Redact(msg interface{}, val reflect.Value) {
	// TODO: This needs to be optimized!
	// Should cache messages that contain no sensitive data to ignore, and should cache the map of tag number to field name

	if !val.IsValid() {
		return
	}

	switch val.Kind() {
	case reflect.Slice:
		for i := 0; i < val.Len(); i += 1 {
			Redact(val.Index(i).Interface(), val.Index(i))
		}
	case reflect.Map:
		// TODO: Implement map logic. Currently only certificates in identity use it, and are redacted
	case reflect.Ptr:
		Redact(msg, val.Elem())
	case reflect.Struct:
		redactMessage(msg, val)
	}
}

// Redact - removes data from fields marked as sensitive given a proto message struct
func RedactSensitiveError(msg interface{}, val reflect.Value, err *error) {
	// TODO: This needs to be optimized!
	// Should cache messages that contain no sensitive data to ignore, and should cache the map of tag number to field name

	if !val.IsValid() {
		return
	}

	switch val.Kind() {
	case reflect.Slice:
		for i := 0; i < val.Len(); i += 1 {
			RedactSensitiveError(val.Index(i).Interface(), val.Index(i), err)
		}
	case reflect.Map:
		// TODO: Implement map logic. Currently only certificates in identity use it, and are redacted
	case reflect.Ptr:
		RedactSensitiveError(msg, val.Elem(), err)
	case reflect.Struct:
		redactErrorMessage(msg, val, err)
	}
}

// RedactedMessage - returns a copy of a proto message struct with data from fields marked as sensitive redacted
func RedactedError(msg interface{}, err *error) interface{} {
	rMsg := proto.Clone((msg).(proto.Message))
	RedactSensitiveError(rMsg, reflect.ValueOf(rMsg), err)
	return rMsg
}

func redactMessage(msg interface{}, val reflect.Value) {
	properties := proto.GetProperties(reflect.TypeOf(msg).Elem())
	_, md := descriptor.ForMessage((msg).(descriptor.Message))

	for _, field := range md.GetField() {
		var fieldVal reflect.Value
		if field.Options != nil || field.GetType() == descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
			for _, p := range properties.Prop {
				if int32(p.Tag) == field.GetNumber() {
					fieldVal = val.FieldByName(p.Name)
					break
				}
			}
			if !fieldVal.IsValid() {
				for _, oot := range properties.OneofTypes {
					if int32(oot.Prop.Tag) == field.GetNumber() {
						fieldVal = val.Field(oot.Field).Elem().FieldByName(oot.Prop.Name)
						break
					}
				}
			}
			if !fieldVal.IsValid() {
				return
			}
		}
		if field.Options != nil {
			ex, err := proto.GetExtension(field.Options, common.E_Sensitivejson)
			if err != proto.ErrMissingExtension && err == nil && *ex.(*bool) {
				if fieldVal.Kind() == reflect.String {
					redactJsonSensitiveField(fieldVal)
				} else {
					t := fieldVal.Type()
					fieldVal.Set(reflect.Zero(t))
				}
				continue
			}

			ex, err = proto.GetExtension(field.Options, common.E_Sensitive)
			if err == proto.ErrMissingExtension {
				continue
			}

			if err == nil && *ex.(*bool) {
				if fieldVal.Kind() == reflect.String {
					fieldVal.SetString(RedactedString)
				} else {
					t := fieldVal.Type()
					fieldVal.Set(reflect.Zero(t))
				}
				continue
			}
		}
		if field.GetType() == descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
			Redact(fieldVal.Interface(), reflect.ValueOf(fieldVal.Interface()))
		}
	}
}

func redactJsonSensitiveField(val reflect.Value) {
	var jsonData map[string]interface{}
	validJsonString := strings.ReplaceAll(val.String(), `\`, `"`)
	if err := json.Unmarshal([]byte(validJsonString), &jsonData); err != nil {
		return
	}
	for key := range jsonData {
		// This can be extended to an array of sensitive keys if needed
		if key == "private-key" {
			jsonData[key] = RedactedString
		}
	}
	redactedJson, err := json.Marshal(jsonData)
	if err == nil {
		val.SetString(string(redactedJson))
	}
}

func redactErrorMessage(msg interface{}, val reflect.Value, errMessage *error) {
	properties := proto.GetProperties(reflect.TypeOf(msg).Elem())
	_, md := descriptor.ForMessage((msg).(descriptor.Message))

	for _, field := range md.GetField() {
		fieldVal := getFieldVal(properties, field, val)
		if !fieldVal.IsValid() {
			continue
		}

		if field.Options != nil {
			if redactField(field.Options, fieldVal, errMessage, common.E_Sensitivejson) {
				continue
			}
			if redactField(field.Options, fieldVal, errMessage, common.E_Sensitive) {
				continue
			}
		}

		if field.GetType() == descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
			RedactSensitiveError(fieldVal.Interface(), reflect.ValueOf(fieldVal.Interface()), errMessage)
		}
	}
}

func getFieldVal(properties *proto.StructProperties, field *descriptorpb.FieldDescriptorProto, val reflect.Value) reflect.Value {
	for _, p := range properties.Prop {
		if int32(p.Tag) == field.GetNumber() {
			return val.FieldByName(p.Name)
		}
	}
	for _, oot := range properties.OneofTypes {
		if int32(oot.Prop.Tag) == field.GetNumber() {
			return val.Field(oot.Field).Elem().FieldByName(oot.Prop.Name)
		}
	}
	return reflect.Value{}
}

func redactField(options *descriptorpb.FieldOptions, fieldVal reflect.Value, errMessage *error, extensionType *proto.ExtensionDesc) bool {
	ex, err := proto.GetExtension(options, extensionType)
	if err == proto.ErrMissingExtension || err != nil || !*ex.(*bool) {
		return false
	}

	if fieldVal.Kind() == reflect.String && errMessage != nil && fieldVal.String() != "" {
		if extensionType == common.E_Sensitive {
			redactSensitiveField(fieldVal.String(), errMessage)
		} else if extensionType == common.E_Sensitivejson {
			redactErrorJsonSensitiveField(fieldVal, errMessage)
		}
	}
	return true
}

func redactSensitiveField(fieldVal string, errMessage *error) {
	errMsg := (*errMessage).Error()
	if strings.Contains(errMsg, fieldVal) {
		errMsg = strings.ReplaceAll(errMsg, fieldVal, RedactedString)
		*errMessage = fmt.Errorf("%s", errMsg)
	}
}

func redactErrorJsonSensitiveField(val reflect.Value, errMessage *error) {
	var jsonData map[string]interface{}
	validJsonString := strings.ReplaceAll(val.String(), `\`, `"`)
	if err := json.Unmarshal([]byte(validJsonString), &jsonData); err != nil {
		return
	}
	for key := range jsonData {
		// This can be extended to an array of sensitive keys if needed
		if key == "private-key" {
			if strVal, ok := jsonData[key].(string); ok && errMessage != nil && strVal != "" {
				redactSensitiveField(strVal, errMessage)
			}
		}
	}
}
