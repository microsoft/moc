package storage

import (
	"testing"
)

func TestVHDUniqueId (t *testing.T) {
	// Validate the UniqueId field exists and can set GUID value to it
	sampleGuid := "33221100-5544-6677-8899-aabbccddeeff"
	vhd := VirtualHardDisk{Name: "test", UniqueId: sampleGuid}
	t.Logf("Cloudagent VirtualHardDisk UniqueId: %s", vhd.UniqueId)
	if vhd.UniqueId != sampleGuid {
		t.Fatal("Cloudagent VirtualHardDisk UniqueId does not match expected value")
	}
}
