package main

import (
	"strings"
	"testing"

	"github.com/EgeBalci/urlscan-go"
)

var TestAPIToken = "2d62fbb4-ef2d-4da1-84ba-e53fe191da8f"

func TestSubmitURL(t *testing.T) {
	cli := urlscan.NewClient(TestAPIToken)
	submitResult, err := cli.SubmitURL("threatintel.blog", "public")
	if err != nil {
		t.Error(err)
		return
	}

	if submitResult.UUID == "" {
		t.Error("empty result UUID value")
		return
	}
}

func TestSearch(t *testing.T) {
	cli := urlscan.NewClient(TestAPIToken)
	searchResult, err := cli.Search("domain:threatintel.blog")
	if err != nil {
		t.Error(err)
		return
	}

	if searchResult.Results[0].ID == "" {
		t.Error("empty search result ID value")
		return
	}
}

// func TestGetScanResult(t *testing.T) {
// 	cli := urlscan.NewClient(TestAPIToken)
// 	// https://urlscan.io/result/edc627f7-0fef-42e9-809d-d1bff1934699/
// 	scanResult, err := cli.GetScanResult("edc627f7-0fef-42e9-809d-d1bff1934699")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	if scanResult.Task.UUID == "" {
// 		t.Error("empty task UUID value")
// 		return
// 	}
// }

func TestGetDOMTree(t *testing.T) {
	cli := urlscan.NewClient(TestAPIToken)
	// https://urlscan.io/result/edc627f7-0fef-42e9-809d-d1bff1934699/
	domTree, err := cli.GetDOMTree("edc627f7-0fef-42e9-809d-d1bff1934699")
	if err != nil {
		t.Error(err)
		return
	}

	if !strings.Contains(string(domTree), "Threat") {
		t.Error("unexpected DOM tree")
		return
	}
}

func TestGetScreenshot(t *testing.T) {
	cli := urlscan.NewClient(TestAPIToken)
	// https://urlscan.io/result/edc627f7-0fef-42e9-809d-d1bff1934699/
	screenShot, err := cli.GetScreenshot("edc627f7-0fef-42e9-809d-d1bff1934699")
	if err != nil {
		t.Error(err)
		return
	}

	if screenShot[0] != 0x89 || screenShot[1] != 'P' || screenShot[2] != 'N' || screenShot[3] != 'G' {
		t.Error("invalid PNG image")
		return
	}
}
