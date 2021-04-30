// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache v2.0 license.

package redact

import (
	"reflect"

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
			ex, err := proto.GetExtension(field.Options, common.E_Sensitive)
			if err == proto.ErrMissingExtension {
				continue
			}

			if err != nil || *ex.(*bool) {
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
