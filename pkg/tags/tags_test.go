// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package tags

import (
	"testing"

	common "github.com/microsoft/moc/rpc/common"
)

func TestTag(t *testing.T) {
	tag := InitTag("testkey", "testvalue")
	if tag.GetKey() != "testkey" || tag.GetValue() != "testvalue" {
		t.Errorf("Failed to create Tag")
	}
	t.Logf("%s-%s", tag.GetKey(), tag.GetValue())
}

func TestAddTag(t *testing.T) {
	tags := &common.Tags{}
	AddTag("testkey", "testvalue", tags)
	if len(tags.GetTags()) != 1 || tags.Tags[0].GetKey() != "testkey" || tags.Tags[0].GetValue() != "testvalue" {
		t.Errorf("Failed to add Tag")
	}
	t.Logf("%s-%s", tags.Tags[0].GetKey(), tags.Tags[0].GetValue())
}

func TestGetTagValue(t *testing.T) {
	tags := &common.Tags{}
	AddTag("testkey", "testvalue", tags)
	value, err := GetTagValue("testkey", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue" {
		t.Errorf("Failed to get Tag value")
	}
	t.Logf("%s", value)
}

func TestAddTagValue(t *testing.T) {
	tags := &common.Tags{}
	AddTag("testkey", "testvalue", tags)
	value, err := GetTagValue("testkey", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue" {
		t.Errorf("Failed to get Tag value")
	}
	AddTagValue("testkey", "testvalue1", tags)
	value, err = GetTagValue("testkey", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue1" {
		t.Errorf("Failed to get Tag value")
	}
	AddTagValue("testkey1", "testvalue1", tags)
	value, err = GetTagValue("testkey", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue1" {
		t.Errorf("Failed to get Tag value")
	}
	value, err = GetTagValue("testkey1", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue1" {
		t.Errorf("Failed to get Tag value")
	}
	if len(tags.GetTags()) != 2 {
		t.Errorf("Failed to add Tag value")
	}
	t.Logf("%s", value)
}

func TestProtoToMap(t *testing.T) {
	tags := &common.Tags{}
	AddTagValue("testkey", "testvalue", tags)
	AddTagValue("testkey1", "testvalue1", tags)
	if len(tags.GetTags()) != 2 {
		t.Errorf("Failed to add Tag value")
	}
	tmap := ProtoToMap(tags)
	if *tmap["testkey"] != "testvalue" {
		t.Errorf("Missing key testkey")
	}
	if *tmap["testkey1"] != "testvalue1" {
		t.Errorf("Missing key testkey")
	}
	t.Logf("TestProtoToMap Passed")
}

func TestMapToProto(t *testing.T) {
	mtags := make(map[string]*string, 2)
	key := "testkey"
	key1 := "testkey1"
	value := "testvalue"
	value1 := "testvalue1"
	mtags[key] = &value
	mtags[key1] = &value1
	tags := MapToProto(mtags)
	if len(tags.GetTags()) != 2 {
		t.Errorf("Failed to add Tag value")
	}
	value, err := GetTagValue("testkey", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue" {
		t.Errorf("Failed to get Tag value")
	}
	value, err = GetTagValue("testkey1", tags)
	if err != nil {
		t.Errorf("Failed to get Tag")
	}
	if value != "testvalue1" {
		t.Errorf("Failed to get Tag value")
	}
	t.Logf("TestMapToProto Passed")
}
