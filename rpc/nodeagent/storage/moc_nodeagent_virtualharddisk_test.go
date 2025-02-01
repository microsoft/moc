package storage

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/microsoft/moc/pkg/redact"
	"github.com/stretchr/testify/assert"
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
