package storage

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/microsoft/moc/pkg/redact"
	wssdcloudcompute "github.com/microsoft/moc/rpc/cloudagent/compute"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactedError_VHD(t *testing.T) {
	// Has issue with ampersand (&); queryescape is needed to pass
	uri := url.QueryEscape(`https://test.blob.core.windowssdfsdf.net/testvhd/test.vhdx?sp=r&st=2025-01-31T10:33:25Z&se=2025-01-31T18:33:25Z&spr=https&sv=2022-11-02&sr=b&sig=dfdf`)

	azureProp := AzureGalleryImageProperties{SasURI: uri}
	propertiesJson, e := json.Marshal(azureProp)
	if e != nil {
		t.Error(e)
	}
	vhd := VirtualHardDisk{Name: "test", Source: string(propertiesJson)}
	err := errors.New(uri + " : Unable to reach host")
	redact.RedactError(&vhd, &err)
	assert.False(t, strings.Contains(err.Error(), uri), err.Error())

}

func TestRedactedError_VHD_BlobEndpoint(t *testing.T) {
	endpoint := "https://mystorage.blob.core.windows.net"
	blobProps := AzureBlobImageProperties{
		Cloud:    "AzureCloud",
		Endpoint: endpoint,
	}
	propertiesJson, err := json.Marshal(blobProps)
	require.NoError(t, err)

	vhd := VirtualHardDisk{Name: "test-blob", Source: string(propertiesJson)}
	dlErr := errors.New(endpoint + " : connection refused")
	redact.RedactError(&vhd, &dlErr)

	// endpoint must be scrubbed from the error message
	assert.False(t, strings.Contains(dlErr.Error(), endpoint),
		"endpoint should be redacted from error, got: %s", dlErr.Error())

	// Redact() scrubs the struct fields (used before logging/returning the message)
	redact.Redact(&vhd, reflect.ValueOf(&vhd))
	assert.False(t, strings.Contains(vhd.Source, endpoint),
		"endpoint should be redacted from VHD.Source, got: %s", vhd.Source)
}

// TestAzureBlobImageProperties_JSONKeys locks the exact JSON keys produced by
// the nodeagent AzureBlobImageProperties message. wssdagent's parseBlobConfig
// unmarshals VirtualHardDisk.Source into a struct keyed by "cloud" and
// "endpoint"; mgmtappl / moc-sdk-for-go encode the same shape on the other
// side. Any rename of these proto fields would silently break AGC downloads,
// so this test fails loudly if the wire keys drift.
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

// TestAzureBlobImageProperties_CloudagentNodeagentParity guards the invariant
// that the cloudagent and nodeagent AzureBlobImageProperties messages produce
// identical JSON. moc-sdk-for-go encodes the cloudagent flavor into
// GalleryImage.sourcePath; the agent ultimately decodes the same JSON on the
// nodeagent side. Editing only one of the two proto files would silently break
// wire compatibility — this test makes that drift a compile/test-time error.
func TestAzureBlobImageProperties_CloudagentNodeagentParity(t *testing.T) {
	caTags := collectJSONTags(reflect.TypeOf(wssdcloudcompute.AzureBlobImageProperties{}))
	naTags := collectJSONTags(reflect.TypeOf(AzureBlobImageProperties{}))
	assert.Equal(t, caTags, naTags,
		"cloudagent and nodeagent AzureBlobImageProperties must have identical Go field names and JSON tags")
}

// collectJSONTags returns a map of exported Go field name -> JSON tag (first
// segment) for a struct type, skipping protoc-gen-go's internal XXX_ fields.
func collectJSONTags(typ reflect.Type) map[string]string {
	out := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.HasPrefix(f.Name, "XXX_") {
			continue
		}
		out[f.Name] = strings.Split(f.Tag.Get("json"), ",")[0]
	}
	return out
}
