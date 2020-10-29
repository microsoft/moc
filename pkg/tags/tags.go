// Copyright (c) Microsoft Corporation
// Licensed under the Apache v2.0 license.
package tags

import (
	"github.com/microsoft/moc/pkg/errors"
	common "github.com/microsoft/moc/rpc/common"
)

// InitTag
func InitTag(key, value string) *common.Tag {
	return &common.Tag{
		Key:   key,
		Value: value,
	}
}

// AddTag
func AddTag(key, value string, tags *common.Tags) {
	tags.Tags = append(tags.GetTags(), InitTag(key, value))
}

//GetTagValue
func GetTagValue(key string, tags *common.Tags) (string, error) {
	for _, tag := range tags.GetTags() {
		if tag.GetKey() == key {
			return tag.GetValue(), nil
		}
	}
	return "", errors.Wrapf(errors.NotFound, "Missing tag %s", key)
}

//GetTagValue
func AddTagValue(key, value string, tags *common.Tags) {
	for _, tag := range tags.GetTags() {
		if tag.GetKey() == key {
			tag.Value = value
			return
		}
	}
	tags.Tags = append(tags.GetTags(), InitTag(key, value))
	return
}

//ProtoToMap
func ProtoToMap(prototags *common.Tags) map[string]*string {
	tags := make(map[string]*string, len(prototags.GetTags()))
	for _, prototag := range prototags.GetTags() {
		tags[prototag.Key] = &prototag.Value
	}
	return tags
}

//MapToProto
func MapToProto(tags map[string]*string) *common.Tags {
	prototags := common.Tags{}
	for key, value := range tags {
		tag := common.Tag{
			Key:   key,
			Value: *value,
		}
		prototags.Tags = append(prototags.GetTags(), &tag)
	}
	return &prototags
}
