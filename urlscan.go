package urlscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/valyala/fasthttp"
)

// Client contains the URLScan API token
type Client struct {
	Token string
}

// NewClient returns a URLScan client
// which is containing required API token
func NewClient(token string) *Client {
	return &Client{Token: token}
}

// SubmitURL submits a new URL to urlscan.io for scanning
// and returns the corresponding submission response struct
func (cli *Client) SubmitURL(u, visibility string) (*URLSumbitResponse, error) {

	if visibility != "private" && visibility != "public" {
		return nil, errors.New("invalid visibility paramater")
	}

	newSubmission := URLSubmitData{URL: u, Visibility: visibility}
	data, err := json.Marshal(newSubmission)
	if err != nil {
		return nil, err
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	req.Header.SetMethodBytes([]byte("POST"))
	req.Header.SetUserAgent("urlscan-go client")
	req.Header.SetContentType("application/json")
	req.Header.Add("API-Key", cli.Token)
	req.SetBody(data)
	req.SetRequestURIBytes([]byte("https://urlscan.io/api/v1/scan/"))

	err = fasthttp.Do(req, resp)
	if err != nil {
		return nil, err
	}
	fasthttp.ReleaseRequest(req)

	//return resp.StatusCode(), resp.Body(), nil

	scode := resp.StatusCode()
	switch scode {
	case 429:
		return nil, fmt.Errorf("rate limit exceeded")
	case 200:
		break
	default:
		return nil, fmt.Errorf("status code: %d", scode)
	}

	result := &URLSumbitResponse{}
	err = json.Unmarshal(resp.Body(), result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Search performs the given search query in urlscan.io
// and returns a SearchResults struct
// Available query parameters for the search endpoint:
// q - The query term (ElasticSearch Query String Query). Default: "*"
// size - Number of results returned. Default: 100, Max: 10000 (depending on your subscription)
// search_after - For iterating, value of the sort attribute of the last result you received (comma-separated).
// offset - Deprecated, not supported anymore, use search_after.
// The search API returns an array of results where each entry includes these items:
// _id - The UUID of the scan
// sort - The sort key, to be used with search_after
// page - Information about the page after it finished loading
// task - Parameters for the scan
// stats - High-level stats about the page
// brand - Pro Only Detected phishing against specific brands
func (cli *Client) Search(query string) (*SearchResults, error) {

	validURL, err := url.Parse(fmt.Sprintf("https://urlscan.io/api/v1/search/?q=%s", query))
	if err != nil {
		return nil, err
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	req.Header.SetMethodBytes([]byte("GET"))
	req.Header.SetUserAgent("urlscan-go client")
	req.Header.SetContentType("application/json")
	req.Header.Add("API-Key", cli.Token)
	req.SetRequestURIBytes([]byte(validURL.String()))

	err = fasthttp.Do(req, resp)
	if err != nil {
		return nil, err
	}
	fasthttp.ReleaseRequest(req)

	//return resp.StatusCode(), resp.Body(), nil

	scode := resp.StatusCode()
	switch scode {
	case 429:
		return nil, fmt.Errorf("rate limit exceeded")
	case 404:
		return nil, fmt.Errorf("scan is not finished")
	case 200:
		break
	default:
		return nil, fmt.Errorf("status code: %d", scode)
	}

	result := &SearchResults{}
	err = json.Unmarshal(resp.Body(), result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetScanResult retrieves the scan result data from urlscan.io API
// and returns a ScanResult struct
func (cli *Client) GetScanResult(uuid string) (*ScanResult, error) {

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	req.Header.SetMethodBytes([]byte("GET"))
	req.Header.SetUserAgent("urlscan-go client")
	req.Header.SetContentType("application/json")
	req.Header.Add("API-Key", cli.Token)
	req.SetRequestURIBytes([]byte(fmt.Sprintf("https://urlscan.io/api/v1/result/%s/", uuid)))

	err := fasthttp.Do(req, resp)
	if err != nil {
		return nil, err
	}
	fasthttp.ReleaseRequest(req)

	//return resp.StatusCode(), resp.Body(), nil

	scode := resp.StatusCode()
	switch scode {
	case 429:
		return nil, fmt.Errorf("rate limit exceeded")
	case 404:
		return nil, fmt.Errorf("scan is not finished")
	case 200:
		break
	default:
		return nil, fmt.Errorf("status code: %d", scode)
	}

	result := &ScanResult{}
	err = json.Unmarshal(resp.Body(), result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetDOMTree retrieves the DOM tree from a scan result
func (cli *Client) GetDOMTree(uuid string) ([]byte, error) {
	validURL, err := url.Parse(fmt.Sprintf("https://urlscan.io/dom/%s/", uuid))
	if err != nil {
		return nil, err
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethodBytes([]byte("GET"))
	req.Header.SetUserAgent("urlscan-go client")
	req.SetRequestURIBytes([]byte(validURL.String()))

	err = fasthttp.Do(req, resp)
	if err != nil {
		return nil, err
	}
	fasthttp.ReleaseRequest(req)
	scode := resp.StatusCode()
	switch scode {
	case 429:
		return nil, fmt.Errorf("rate limit exceeded")
	case 404:
		return nil, fmt.Errorf("scan is not finished")
	case 200:
		break
	default:
		return nil, fmt.Errorf("status code: %d", scode)
	}

	// Check that the server actually sent compressed data
	if bytes.EqualFold(resp.Header.Peek("Content-Encoding"), []byte("gzip")) {
		body, err := resp.BodyGunzip()
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return resp.Body(), nil

}

// GetScreenshot retrieves the screenshot from a scan result
func (cli *Client) GetScreenshot(uuid string) ([]byte, error) {
	validURL, err := url.Parse(fmt.Sprintf("https://urlscan.io/screenshots/%s.png", uuid))
	if err != nil {
		return nil, err
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethodBytes([]byte("GET"))
	req.Header.SetUserAgent("urlscan-go client")
	req.SetRequestURIBytes([]byte(validURL.String()))

	err = fasthttp.Do(req, resp)
	if err != nil {
		return nil, err
	}
	fasthttp.ReleaseRequest(req)

	scode := resp.StatusCode()
	switch scode {
	case 429:
		return nil, fmt.Errorf("rate limit exceeded")
	case 404:
		return nil, fmt.Errorf("scan is not finished")
	case 200:
		break
	default:
		return nil, fmt.Errorf("status code: %d", scode)
	}

	// Check that the server actually sent compressed data
	if bytes.EqualFold(resp.Header.Peek("Content-Encoding"), []byte("gzip")) {
		body, err := resp.BodyGunzip()
		if err != nil {
			return nil, err
		}
		return body, nil
	}
	return resp.Body(), nil

}

// ScanResult contains the JSON response
// of a submitted URLScan task
type ScanResult struct {
	Data struct {
		Requests []struct {
			Request struct {
				RequestID   string `json:"requestId"`
				LoaderID    string `json:"loaderId"`
				DocumentURL string `json:"documentURL"`
				Request     struct {
					URL     string `json:"url"`
					Method  string `json:"method"`
					Headers struct {
						UpgradeInsecureRequests string `json:"Upgrade-Insecure-Requests"`
						UserAgent               string `json:"User-Agent"`
					} `json:"headers"`
					MixedContentType string `json:"mixedContentType"`
					InitialPriority  string `json:"initialPriority"`
					ReferrerPolicy   string `json:"referrerPolicy"`
				} `json:"request"`
				Timestamp float64 `json:"timestamp"`
				WallTime  float64 `json:"wallTime"`
				Initiator struct {
					Type string `json:"type"`
				} `json:"initiator"`
				Type           string `json:"type"`
				FrameID        string `json:"frameId"`
				HasUserGesture bool   `json:"hasUserGesture"`
			} `json:"request"`
			Response struct {
				EncodedDataLength int    `json:"encodedDataLength"`
				DataLength        int    `json:"dataLength"`
				RequestID         string `json:"requestId"`
				Type              string `json:"type"`
				Response          struct {
					URL        string `json:"url"`
					Status     int    `json:"status"`
					StatusText string `json:"statusText"`
					Headers    struct {
						Server           string `json:"Server"`
						Date             string `json:"Date"`
						ContentType      string `json:"Content-Type"`
						TransferEncoding string `json:"Transfer-Encoding"`
						Connection       string `json:"Connection"`
						Vary             string `json:"Vary"`
						SetCookie        string `json:"Set-Cookie"`
						Expires          string `json:"Expires"`
						CacheControl     string `json:"Cache-Control"`
						Pragma           string `json:"Pragma"`
						ContentEncoding  string `json:"Content-Encoding"`
					} `json:"headers"`
					MimeType       string `json:"mimeType"`
					RequestHeaders struct {
						Host                    string `json:"Host"`
						Connection              string `json:"Connection"`
						Pragma                  string `json:"Pragma"`
						CacheControl            string `json:"Cache-Control"`
						UpgradeInsecureRequests string `json:"Upgrade-Insecure-Requests"`
						UserAgent               string `json:"User-Agent"`
						Accept                  string `json:"Accept"`
						AcceptEncoding          string `json:"Accept-Encoding"`
						AcceptLanguage          string `json:"Accept-Language"`
					} `json:"requestHeaders"`
					RemoteIPAddress   string `json:"remoteIPAddress"`
					RemotePort        int    `json:"remotePort"`
					FromPrefetchCache bool   `json:"fromPrefetchCache"`
					EncodedDataLength int    `json:"encodedDataLength"`
					Timing            struct {
						RequestTime              float64 `json:"requestTime"`
						ProxyStart               float64 `json:"proxyStart"`
						ProxyEnd                 float64 `json:"proxyEnd"`
						DNSStart                 float64 `json:"dnsStart"`
						DNSEnd                   float64 `json:"dnsEnd"`
						ConnectStart             float64 `json:"connectStart"`
						ConnectEnd               float64 `json:"connectEnd"`
						SslStart                 float64 `json:"sslStart"`
						SslEnd                   float64 `json:"sslEnd"`
						WorkerStart              float64 `json:"workerStart"`
						WorkerReady              float64 `json:"workerReady"`
						WorkerFetchStart         float64 `json:"workerFetchStart"`
						WorkerRespondWithSettled int     `json:"workerRespondWithSettled"`
						SendStart                float64 `json:"sendStart"`
						SendEnd                  float64 `json:"sendEnd"`
						PushStart                float64 `json:"pushStart"`
						PushEnd                  float64 `json:"pushEnd"`
						ReceiveHeadersEnd        float64 `json:"receiveHeadersEnd"`
					} `json:"timing"`
					ResponseTime  float64 `json:"responseTime"`
					Protocol      string  `json:"protocol"`
					SecurityState string  `json:"securityState"`
				} `json:"response"`
				Hash string `json:"hash"`
				Size int    `json:"size"`
				Asn  struct {
					IP          string `json:"ip"`
					Asn         string `json:"asn"`
					Country     string `json:"country"`
					Registrar   string `json:"registrar"`
					Date        string `json:"date"`
					Description string `json:"description"`
					Route       string `json:"route"`
					Name        string `json:"name"`
				} `json:"asn"`
				Geoip struct {
					Range       []string  `json:"range"`
					Country     string    `json:"country"`
					Region      string    `json:"region"`
					City        string    `json:"city"`
					Ll          []float64 `json:"ll"`
					Metro       int       `json:"metro"`
					Area        int       `json:"area"`
					Eu          string    `json:"eu"`
					Timezone    string    `json:"timezone"`
					CountryName string    `json:"country_name"`
				} `json:"geoip"`
			} `json:"response"`
			InitiatorInfo struct {
				URL  string `json:"url"`
				Host string `json:"host"`
				Type string `json:"type"`
			} `json:"initiatorInfo,omitempty"`
		} `json:"requests"`
		Cookies []struct {
			Name     string `json:"name"`
			Value    string `json:"value"`
			Domain   string `json:"domain"`
			Path     string `json:"path"`
			Expires  int    `json:"expires"`
			Size     int    `json:"size"`
			HTTPOnly bool   `json:"httpOnly"`
			Secure   bool   `json:"secure"`
			Session  bool   `json:"session"`
			Priority string `json:"priority"`
		} `json:"cookies"`
		Console []interface{} `json:"console"`
		Links   []struct {
			Href string `json:"href"`
			Text string `json:"text"`
		} `json:"links"`
		Timing struct {
			BeginNavigation      time.Time `json:"beginNavigation"`
			FrameStartedLoading  time.Time `json:"frameStartedLoading"`
			FrameNavigated       time.Time `json:"frameNavigated"`
			DomContentEventFired time.Time `json:"domContentEventFired"`
			LoadEventFired       time.Time `json:"loadEventFired"`
			FrameStoppedLoading  time.Time `json:"frameStoppedLoading"`
		} `json:"timing"`
		Globals []struct {
			Prop string `json:"prop"`
			Type string `json:"type"`
		} `json:"globals"`
	} `json:"data"`
	Stats struct {
		ResourceStats []struct {
			Count       int         `json:"count"`
			Size        int         `json:"size"`
			EncodedSize int         `json:"encodedSize"`
			Latency     int         `json:"latency"`
			Countries   []string    `json:"countries"`
			Ips         []string    `json:"ips"`
			Type        string      `json:"type"`
			Compression string      `json:"compression"`
			Percentage  interface{} `json:"percentage"`
		} `json:"resourceStats"`
		ProtocolStats []struct {
			Count         int      `json:"count"`
			Size          int      `json:"size"`
			EncodedSize   int      `json:"encodedSize"`
			Ips           []string `json:"ips"`
			Countries     []string `json:"countries"`
			SecurityState struct {
			} `json:"securityState"`
			Protocol string `json:"protocol"`
		} `json:"protocolStats"`
		TLSStats []struct {
			Count         int      `json:"count"`
			Size          int      `json:"size"`
			EncodedSize   int      `json:"encodedSize"`
			Ips           []string `json:"ips"`
			Countries     []string `json:"countries"`
			SecurityState string   `json:"securityState"`
			Protocols     struct {
				TLS13AES128GCM int `json:"TLS 1.3 /  / AES_128_GCM"`
			} `json:"protocols,omitempty"`
		} `json:"tlsStats"`
		ServerStats []struct {
			Count       int      `json:"count"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Ips         []string `json:"ips"`
			Countries   []string `json:"countries"`
			Server      string   `json:"server"`
		} `json:"serverStats"`
		DomainStats []struct {
			Count       int      `json:"count"`
			Ips         []string `json:"ips"`
			Domain      string   `json:"domain"`
			Size        int      `json:"size"`
			EncodedSize int      `json:"encodedSize"`
			Countries   []string `json:"countries"`
			Index       int      `json:"index"`
			Initiators  []string `json:"initiators"`
			Redirects   int      `json:"redirects"`
		} `json:"domainStats"`
		RegDomainStats []struct {
			Count       int           `json:"count"`
			Ips         []string      `json:"ips"`
			RegDomain   string        `json:"regDomain"`
			Size        int           `json:"size"`
			EncodedSize int           `json:"encodedSize"`
			Countries   []interface{} `json:"countries"`
			Index       int           `json:"index"`
			SubDomains  []interface{} `json:"subDomains"`
			Redirects   int           `json:"redirects"`
		} `json:"regDomainStats"`
		SecureRequests   int `json:"secureRequests"`
		SecurePercentage int `json:"securePercentage"`
		IPv6Percentage   int `json:"IPv6Percentage"`
		UniqCountries    int `json:"uniqCountries"`
		TotalLinks       int `json:"totalLinks"`
		Malicious        int `json:"malicious"`
		AdBlocked        int `json:"adBlocked"`
		IPStats          []struct {
			Requests int      `json:"requests"`
			Domains  []string `json:"domains"`
			IP       string   `json:"ip"`
			Asn      struct {
				IP          string `json:"ip"`
				Asn         string `json:"asn"`
				Country     string `json:"country"`
				Registrar   string `json:"registrar"`
				Date        string `json:"date"`
				Description string `json:"description"`
				Route       string `json:"route"`
				Name        string `json:"name"`
			} `json:"asn"`
			DNS struct {
			} `json:"dns"`
			Geoip struct {
				Range       []string `json:"range"`
				Country     string   `json:"country"`
				Region      string   `json:"region"`
				City        string   `json:"city"`
				Ll          []int    `json:"ll"`
				Metro       int      `json:"metro"`
				Area        int      `json:"area"`
				Eu          string   `json:"eu"`
				Timezone    string   `json:"timezone"`
				CountryName string   `json:"country_name"`
			} `json:"geoip"`
			Size        int         `json:"size"`
			EncodedSize int         `json:"encodedSize"`
			Countries   []string    `json:"countries"`
			Index       int         `json:"index"`
			Ipv6        bool        `json:"ipv6"`
			Redirects   int         `json:"redirects"`
			Count       interface{} `json:"count"`
		} `json:"ipStats"`
	} `json:"stats"`
	Meta struct {
		Processors struct {
			Geoip struct {
				State string `json:"state"`
				Data  []struct {
					IP    string `json:"ip"`
					Geoip struct {
						Range       []string `json:"range"`
						Country     string   `json:"country"`
						Region      string   `json:"region"`
						City        string   `json:"city"`
						Ll          []int    `json:"ll"`
						Metro       int      `json:"metro"`
						Area        int      `json:"area"`
						Eu          string   `json:"eu"`
						Timezone    string   `json:"timezone"`
						CountryName string   `json:"country_name"`
					} `json:"geoip"`
				} `json:"data"`
			} `json:"geoip"`
			Rdns struct {
				State string        `json:"state"`
				Data  []interface{} `json:"data"`
			} `json:"rdns"`
			Wappa struct {
				State string `json:"state"`
				Data  []struct {
					App        string `json:"app"`
					Confidence []struct {
						Pattern    string `json:"pattern"`
						Confidence int    `json:"confidence"`
					} `json:"confidence"`
					ConfidenceTotal int    `json:"confidenceTotal"`
					Icon            string `json:"icon"`
					Website         string `json:"website"`
					Categories      []struct {
						Name     string `json:"name"`
						Priority int    `json:"priority"`
					} `json:"categories"`
				} `json:"data"`
			} `json:"wappa"`
			Asn struct {
				State string `json:"state"`
				Data  []struct {
					IP          string `json:"ip"`
					Asn         string `json:"asn"`
					Country     string `json:"country"`
					Registrar   string `json:"registrar"`
					Date        string `json:"date"`
					Description string `json:"description"`
					Route       string `json:"route"`
					Name        string `json:"name"`
				} `json:"data"`
			} `json:"asn"`
			Done struct {
				State string `json:"state"`
				Data  struct {
					State string `json:"state"`
				} `json:"data"`
			} `json:"done"`
		} `json:"processors"`
	} `json:"meta"`
	Task struct {
		UUID       string    `json:"uuid"`
		Time       time.Time `json:"time"`
		URL        string    `json:"url"`
		Visibility string    `json:"visibility"`
		Options    struct {
			Useragent string `json:"useragent"`
		} `json:"options"`
		Method        string   `json:"method"`
		Source        string   `json:"source"`
		Tags          []string `json:"tags"`
		UserAgent     string   `json:"userAgent"`
		ReportURL     string   `json:"reportURL"`
		ScreenshotURL string   `json:"screenshotURL"`
		DomURL        string   `json:"domURL"`
	} `json:"task"`
	Page struct {
		URL     string `json:"url"`
		Domain  string `json:"domain"`
		Country string `json:"country"`
		City    string `json:"city"`
		Server  string `json:"server"`
		IP      string `json:"ip"`
		Asn     string `json:"asn"`
		Asnname string `json:"asnname"`
	} `json:"page"`
	Lists struct {
		Ips          []string `json:"ips"`
		Countries    []string `json:"countries"`
		Asns         []string `json:"asns"`
		Domains      []string `json:"domains"`
		Servers      []string `json:"servers"`
		Urls         []string `json:"urls"`
		LinkDomains  []string `json:"linkDomains"`
		Certificates []struct {
			SubjectName string `json:"subjectName"`
			Issuer      string `json:"issuer"`
			ValidFrom   int    `json:"validFrom"`
			ValidTo     int    `json:"validTo"`
		} `json:"certificates"`
		Hashes []string `json:"hashes"`
	} `json:"lists"`
	Verdicts struct {
		Overall struct {
			Score       int           `json:"score"`
			Categories  []interface{} `json:"categories"`
			Brands      []interface{} `json:"brands"`
			Tags        []interface{} `json:"tags"`
			Malicious   bool          `json:"malicious"`
			HasVerdicts int           `json:"hasVerdicts"`
		} `json:"overall"`
		Urlscan struct {
			Score            int           `json:"score"`
			Categories       []interface{} `json:"categories"`
			Brands           []interface{} `json:"brands"`
			Tags             []interface{} `json:"tags"`
			DetectionDetails []interface{} `json:"detectionDetails"`
			Malicious        bool          `json:"malicious"`
		} `json:"urlscan"`
		Engines struct {
			Score          int           `json:"score"`
			Malicious      []interface{} `json:"malicious"`
			Benign         []interface{} `json:"benign"`
			MaliciousTotal int           `json:"maliciousTotal"`
			BenignTotal    int           `json:"benignTotal"`
			Verdicts       []interface{} `json:"verdicts"`
			EnginesTotal   int           `json:"enginesTotal"`
		} `json:"engines"`
		Community struct {
			Score          int           `json:"score"`
			Votes          []interface{} `json:"votes"`
			VotesTotal     int           `json:"votesTotal"`
			VotesMalicious int           `json:"votesMalicious"`
			VotesBenign    int           `json:"votesBenign"`
			Tags           []interface{} `json:"tags"`
			Categories     []interface{} `json:"categories"`
		} `json:"community"`
	} `json:"verdicts"`
}

// SearchResults contains the JSON response
// returned from urlscan.io search queries
type SearchResults struct {
	Results []struct {
		Task struct {
			Visibility string    `json:"visibility"`
			Method     string    `json:"method"`
			Time       time.Time `json:"time"`
			Source     string    `json:"source"`
			URL        string    `json:"url"`
		} `json:"task"`
		Stats struct {
			UniqIPs           int `json:"uniqIPs"`
			ConsoleMsgs       int `json:"consoleMsgs"`
			DataLength        int `json:"dataLength"`
			EncodedDataLength int `json:"encodedDataLength"`
			Requests          int `json:"requests"`
		} `json:"stats"`
		Page struct {
			Country string `json:"country"`
			Server  string `json:"server"`
			City    string `json:"city"`
			Domain  string `json:"domain"`
			IP      string `json:"ip"`
			Asnname string `json:"asnname"`
			Asn     string `json:"asn"`
			URL     string `json:"url"`
			Ptr     string `json:"ptr"`
		} `json:"page"`
		UniqCountries int    `json:"uniq_countries"`
		ID            string `json:"_id"`
		Result        string `json:"result"`
	} `json:"results"`
	Total int `json:"total"`
}

// URLSubmitData contains the required parameters
// for submiting a URL for scanning
type URLSubmitData struct {
	URL        string `json:"url"`
	Visibility string `json:"visibility"`
}

// URLSumbitResponse contains the JSON
// response for URLSubmit request
type URLSumbitResponse struct {
	Message    string `json:"message"`
	UUID       string `json:"uuid"`
	Result     string `json:"result"`
	API        string `json:"api"`
	Visibility string `json:"visibility"`
	Options    struct {
		Useragent string `json:"useragent"`
	} `json:"options"`
	URL string `json:"url"`
}
