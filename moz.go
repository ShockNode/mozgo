package mozgo

import (
	"net/http"
	"io/ioutil"
	"crypto/hmac"
	"crypto/sha1"
	"net/url"
	"encoding/base64"
	"strconv"
	"encoding/json"
	"time"
	"bytes"
)
type BitFlag int
type SpamFlag int

//Mozscape API bit flag constants
const (
	TITLE                               BitFlag = 1
	CANONICAL_URL                       BitFlag = 4
	SUBDOMAIN                           BitFlag = 8
	ROOT_DOMAIN                         BitFlag = 16
	EXTERNAL_EQUITY_LINKS               BitFlag = 32
	SUBDOMAIN_EXTERNAL_LINKS            BitFlag = 64
	ROOT_DOMAIN_EXTERNAL_LINKS          BitFlag = 128
	EQUITY_LINKS                        BitFlag = 256
	SUBDOMAINS_LINKING                  BitFlag = 512
	ROOT_DOMAIN_LINKING                 BitFlag = 1024
	LINKS                               BitFlag = 2048
	SUBDOMAIN_SUBDOMAINS_LINKING        BitFlag = 4096
	ROOT_DOMAIN_ROOT_DOMAINS_LINKING    BitFlag = 8192
	MOZRANK_URL                         BitFlag = 16384
	MOZRANK_SUBDOMAIN                   BitFlag = 32768
	MOZRANK_ROOT_DOMAIN                 BitFlag = 65536
	MOZTRUST                            BitFlag = 131072
	MOZTRUST_SUBDOMAIN                  BitFlag = 262144
	MOZTRUST_ROOT_DOMAIN                BitFlag = 524288
	MOZRANK_EXTERNAL_EQUITY             BitFlag = 1048576
	MOZRANK_SUBDOMAIN_EXTERNAL_EQUITY   BitFlag = 2097152
	MOZRANK_ROOT_DOMAIN_EXTERNAL_EQUITY BitFlag = 4194304
	MOZRANK_SUBDOMAIN_COMBINED          BitFlag = 8388608
	MOZRANK_ROOT_DOMAIN_COMBINED        BitFlag = 16777216
	SUBDOMAIN_SPAM_SCORE                BitFlag = 67108864
	SOCIAL                              BitFlag = 134217728
	HTTP_STATUS_CODE                    BitFlag = 536870912
	LINKS_TO_SUBDOMAIN                  BitFlag = 4294967296
	LINKS_TO_ROOT_DOMAIN                BitFlag = 8589934592
	ROOT_DOMAINS_LINKING_TO_SUBDOMAIN   BitFlag = 17179869184
	PAGE_AUTHORITY                      BitFlag = 34359738368
	DOMAIN_AUTHORITY                    BitFlag = 68719476736
	EXTERNAL_LINKS                      BitFlag = 549755813888
	EXTERNAL_LINKS_TO_SUBDOMAIN         BitFlag = 140737488355328
	EXTERNAL_LINKS_TO_ROOT_DOMAIN       BitFlag = 2251799813685248
	LINKING_C_BLOCKS                    BitFlag = 36028797018963968
	TIME_LAST_CRAWLED                   BitFlag = 144115188075855872
)

//Represents Access ID and secret key found in the API Keys section of Mozscape account
type Credentials struct {
	AccessId string
	Secret   string
}

//Represents errors thrown from Mozscape API
type ApiError struct {
	Status string        `json:"status"`
	Error  string        `json:"error_message"`
}

//Represents all URL metrics obtainable from the API
type UrlMetric struct {
	Title                                     string     `json:"ut"`
	CanonicalUrl                              string     `json:"uu"`
	Subdomain                                 string     `json:"ufq"`
	RootDomain                                string     `json:"upl"`
	ExternalEquityLinks                       int        `json:"ueid"`
	SubdomainExternalLinks                    int        `json:"feid"`
	RootDomainExternalLinks                   int        `json:"peid"`
	EquityLinks                               int        `json:"ujid"`
	SubdomainsLinking                         int        `json:"uifq"`
	RootDomainsLinking                        int        `json:"uipl"`
	Links                                     int        `json:"uid"`
	SubdomainSubdomainsLinking                int        `json:"fid"`
	RootDomainRootDomainsLinking              int        `json:"pid"`
	MozRankUrlNormalized                      int        `json:"umrp"`
	MozRankUrlRaw                             int        `json:"umrr"`
	MozRankSubdomainNormalized                int        `json:"fmrp"`
	MozRankSubdomainRaw                       int        `json:"fmrr"`
	MozRankRootDomainNormalized               int        `json:"pmrp"`
	MozRankRootDomainRaw                      int        `json:"pmrr"`
	MozTrustNormalized                        int        `json:"utrp"`
	MozTrustRaw                               int        `json:"utrr"`
	MozTrustSubdomainNormalized               int        `json:"ftrp"`
	MozTrustSubdomainRaw                      int        `json:"ftrr"`
	MozTrustRootDomainNormalized              int        `json:"ptrp"`
	MozTrustRootDomainRaw                     int        `json:"ptrr"`
	MozRankExternalEquityNormalized           int        `json:"uemrp"`
	MozRankExternalEquityRaw                  int        `json:"uemrr"`
	MozRankSubdomainExternalEquityNormalized  int        `json:"fejp"`
	MozRankSubdomainExternalEquityRaw         int        `json:"fejr"`
	MozRankRootDomainExternalEquityNormalized int        `json:"pejp"`
	MozRankRootDomainExternalEquityRaw        int        `json:"pejr"`
	MozRankSubdomainCombinedNormalized        int        `json:"pjp"`
	MozRankSubdomainCombinedRaw               int        `json:"pjr"`
	MozRankRootDomainCombinedNormalized       int        `json:"fjp"`
	MozRankRootDomainCombinedEquityRaw        int        `json:"fjr"`
	SubdomainSpamScore                        int        `json:"fspsc"`
	SubdomainSpamScoreBitField                int        `json:"fspf"`
	SubdomainSpamScoreLanguage                string     `json:"flan"`
	SubdomainSpamScoreStatusCode              int        `json:"fsps"`
	SubdomainSpamScoreLastCrawled             string     `json:"fspp"`
	SocialFacebook                            string     `json:"ffb"`
	SocialTwitter                             string     `json:"ftw"`
	SocialGooglePlus                          string     `json:"fg+"`
	SocialEmailAddress                        string     `json:"fem"`
	HttpStatusCode                            int        `json:"us"`
	LinksToSubdomain                          int        `json:"fuid"`
	LinksToRootDomain                         int        `json:"puid"`
	RootDomainsLinkingToSubdomain             int        `json:"fipl"`
	PageAuthority                             int        `json:"upa"`
	DomainAuthority                           int        `json:"pda"`
	ExternalLinks                             int        `json:"ued"`
	ExternalLinksToSubdomain                  int        `json:"fed"`
	ExternalLinksToRootDomain                 int        `json:"ped"`
	LinkingCBlocks                            int        `json:"pib"`
	TimeLastCrawled                           string     `json:"ulc"`
}

// HMAC SHA1 hash of the access id, the Expires unix timestamp in string format, and the secret key.
func getHmacSha1(credentials Credentials, expires string) string {

	key := []byte(credentials.Secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(credentials.AccessId))
	h.Write([]byte("\n")) //Mozscape API requires line break
	h.Write([]byte(expires))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))

}

// GetMetric is the single URL request. Returns UrlMetric struct, ApiError struct, and error
func GetMetric(target string, credentials Credentials, bitFlags []BitFlag) (*UrlMetric, *ApiError, error) {

	sum := 0

	//Get sum of bit flags
	for _, bitFlag := range bitFlags {

		sum += int(bitFlag)

	}

	//Set expiration of signed authentication request
	expires := time.Now().Add(time.Minute).Unix()

	//Convert unix timestamp to string
	unixString := strconv.Itoa(int(expires))

	//Convert bit flag sum to string
	bitFlagSumString := strconv.Itoa(sum)

	signed := getHmacSha1(credentials, unixString)

	//Build request url
	urlString := "http://lsapi.seomoz.com/linkscape/url-metrics/" + target + "?Cols=" + bitFlagSumString + "&AccessID=" + credentials.AccessId + "&Expires=" + unixString + "&Signature=" + url.QueryEscape(signed)

	client := &http.Client{}

	//Send GET request
	resp, err := client.Get(urlString)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	//Get response from body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	apiErr := new(ApiError)
	urlMetric := new(UrlMetric)

	json.Unmarshal(body, apiErr)
	json.Unmarshal(body, urlMetric)

	return urlMetric, apiErr, nil

}

// GetMetrics is the batch URL request. Return array of UrlMetric, ApiError struct, and error
func GetMetrics(targets []string, credentials Credentials, bitFlags []BitFlag) ([]UrlMetric, *ApiError, error) {

	sum := 0

	//Get sum of bit flags
	for _, bitFlag := range bitFlags {

		sum += int(bitFlag)

	}

	//Set expiration of signed authentication request
	expires := time.Now().Add(time.Minute).Unix()

	//Convert unix timestamp to string
	unixString := strconv.Itoa(int(expires))

	//Convert bit flag sum to string
	bitFlagSumString := strconv.Itoa(sum)

	signed := getHmacSha1(credentials, unixString)

	//Build request url
	urlString := "http://lsapi.seomoz.com/linkscape/url-metrics/?Cols=" + bitFlagSumString + "&AccessID=" + credentials.AccessId + "&Expires=" + unixString + "&Signature=" + url.QueryEscape(signed)

	//Convert target urls to JSON
	b, err := json.Marshal(targets)
	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{}

	//Send POST request
	resp, err := client.Post(urlString, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	//Get response from body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	apiErr := new(ApiError)
	var urlMetrics []UrlMetric

	json.Unmarshal(body, apiErr)
	json.Unmarshal(body, &urlMetrics)

	return urlMetrics, apiErr, nil
}