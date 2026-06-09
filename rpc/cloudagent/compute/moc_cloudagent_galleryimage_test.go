// Copyright (c) Microsoft Corporation.
// Licensed under the Apache v2.0 license.
package compute

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureBlobImageProperties_JSONKeys locks the exact JSON keys produced by
// the cloudagent AzureBlobImageProperties message. moc-sdk-for-go marshals
// this struct into GalleryImage.sourcePath as the on-the-wire representation
// of AGC (AZURESTORAGEBLOB_SOURCE) image provisioning parameters. Renaming any
// of these proto fields would silently break the encoding agreement with
// wssdagent's parseBlobConfig on the decode side, so this test fails loudly
// if a field name drifts.
func TestAzureBlobImageProperties_JSONKeys(t *testing.T) {
	props := AzureBlobImageProperties{
		CatalogName: "cat",
		Audience:    "aud",
		Version:     "v1",
		ReleaseName: "rel",
		Parts:       4,
		Cloud:       "AzureCloud",
		Endpoint:    "https://example.blob.core.windows.net",
	}
	raw, err := json.Marshal(&props)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))

	expected := []string{"catalogName", "audience", "version", "releaseName", "parts", "cloud", "endpoint"}
	for _, key := range expected {
		_, ok := m[key]
		assert.True(t, ok, "missing JSON key %q (renamed proto field?)", key)
	}
	assert.Len(t, m, len(expected), "unexpected extra/missing JSON keys: %v", m)
}
