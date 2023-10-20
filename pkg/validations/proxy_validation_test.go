import (
	"testing"
)

func Test_ValidateProxyURL(t *testing.T){
	err := ValidateProxyURL("http://akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128")

	if(err!=nil){
		t.Fatalf("ValidateProxyURL returned error")
	}

	err = ValidateProxyURL("https://akse2e:akse2e@skyproxy.ceccloud1.selfhost.corp.microsoft.com:3128")

	if err != "Invalid proxy URL. The URL scheme should be http"{
		t.Fatalf("Didnt receive the expected error 'Invalid proxy URL. The URL scheme should be http'")
	}
}