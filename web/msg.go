package web

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

var PromReloadChan chan string

func init() {
	PromReloadChan = make(chan string)
}

type Response struct {
	Result   bool        `json:"result"`
	ErrorMsg string      `json:"errprMsg"`
	Output   string      `json:output`
	Content  interface{} `json:"content"`
}

const (
	PUT    = "PUT"
	POST   = "POST"
	GET    = "GET"
	DELETE = "DELETE"
)

const (
	applicationTypeJSON = "application/json"
	applicationTypeXML  = "application/xml"
)

const (
	httpHeaderContentType string = "Content-Type"
	httpHeaderAccept      string = "Accept"
)

type Request struct {
	URL     string      `json:"url"`
	Type    string      `json:"type"`
	Content interface{} `json:"content"`
}

func (reqInfo *Request) SendRequestByJSON() ([]byte, error) {
	jsonTypeContent, _ := json.Marshal(reqInfo.Content)
	body := strings.NewReader(string(jsonTypeContent))

	client := &http.Client{}

	req, _ := http.NewRequest(reqInfo.Type, reqInfo.URL, body)
	req.Header.Set(httpHeaderContentType, applicationTypeJSON)
	req.Header.Set(httpHeaderAccept, applicationTypeJSON)

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()
	data, _ := ioutil.ReadAll(resp.Body)
	respBody := data

	return respBody, err
}
