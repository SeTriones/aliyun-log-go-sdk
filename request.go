package sls

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httputil"

	"encoding/json"
	"io/ioutil"

	"github.com/golang/glog"
)

// request sends a request to SLS.
func request(project *LogProject, method, uri string, headers map[string]string,
	body []byte) (*http.Response, []byte, error) {

	// The caller should provide 'x-log-bodyrawsize' header
	if _, ok := headers["x-log-bodyrawsize"]; !ok {
		return nil, nil, fmt.Errorf("Can't find 'x-log-bodyrawsize' header")
	}

	// SLS public request headers
	headers["Host"] = project.Name + "." + project.Endpoint
	headers["Date"] = nowRFC1123()
	headers["x-log-apiversion"] = version
	headers["x-log-signaturemethod"] = signatureMethod

	// Access with token
	if project.SecurityToken != "" {
		headers["x-acs-security-token"] = project.SecurityToken
	}

	if body != nil {
		bodyMD5 := fmt.Sprintf("%X", md5.Sum(body))
		headers["Content-MD5"] = bodyMD5
		if _, ok := headers["Content-Type"]; !ok {
			return nil, nil, fmt.Errorf("Can't find 'Content-Type' header")
		}
	}

	// Calc Authorization
	// Authorization = "SLS <AccessKeyId>:<Signature>"
	digest, err := signature(project, method, uri, headers)
	if err != nil {
		return nil, nil, err
	}
	auth := fmt.Sprintf("SLS %v:%v", project.AccessKeyID, digest)
	headers["Authorization"] = auth

	// Initialize http request
	reader := bytes.NewReader(body)
	urlStr := fmt.Sprintf("https://%v.%v%v", project.Name, project.Endpoint, uri)
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	if glog.V(1) {
		dump, e := httputil.DumpRequest(req, true)
		if e != nil {
			glog.Info(e)
		}
		glog.Infof("HTTP Request:\n%v", string(dump))
	}

	// Get ready to do request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Parse the sls error from body.
	if resp.StatusCode != http.StatusOK {
		err := &Error{}
		buf, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(buf, err)
		err.RequestID = resp.Header.Get("x-log-requestid")
		return nil, nil, err
	}

	if glog.V(1) {
		dump, e := httputil.DumpResponse(resp, true)
		if e != nil {
			glog.Info(e)
		}
		glog.Infof("HTTP Response:\n%v", string(dump))
	}
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, raw, nil
}
