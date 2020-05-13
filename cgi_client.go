package bugzilla

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"k8s.io/klog"
)

// bugzillaCGIClient bugzilla REST API client
type bugzillaCGIClient struct {
	bugzillaAddr                    string
	httpClient                      *http.Client
	bugzillaLogin, bugzillaPassword string
}

// NewCGIClient creates a helper json rpc client for regular HTTP based endpoints
func newCGIClient(addr string, httpClient *http.Client, bugzillaLogin, bugzillaPassword string) (*bugzillaCGIClient, error) {
	return &bugzillaCGIClient{
		bugzillaAddr:     addr,
		httpClient:       httpClient,
		bugzillaLogin:    bugzillaLogin,
		bugzillaPassword: bugzillaPassword,
	}, nil
}

// setBugzillaLoginCookie visits bugzilla page to obtain login cookie
func (client *bugzillaCGIClient) setBugzillaLoginCookie(loginURL string) (err error) {
	req, err := newHTTPRequest("GET", loginURL, nil)
	if err != nil {
		return err
	}

	res, err := client.httpClient.Do(req)
	defer func() {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
	}()

	if err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			return fmt.Errorf("Timeout occured while accessing %v", loginURL)
		}
		return err
	}
	return nil
}

// getBugzillaLoginToken returns Bugzilla_login_token input field value. Requires login cookie to be set
func (client *bugzillaCGIClient) getBugzillaLoginToken(loginURL string) (loginToken string, err error) {
	req, err := newHTTPRequest("GET", loginURL, nil)
	if err != nil {
		return "", err
	}

	res, err := client.httpClient.Do(req)
	defer func() {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
	}()
	if err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			return "", fmt.Errorf("Timeout occured while accessing %v", loginURL)
		}
		return "", err
	}
	//<input type="hidden" name="Bugzilla_login_token" value="1435647781-eV7m3mhmosArYikHPtaisTliTn7e3kKOZ-RhiX-Qz1A">
	r := regexp.MustCompile(`name="Bugzilla_login_token"\s+value="(?P<value>[\d\w-]+)"`)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	match := r.FindStringSubmatch(string(body))
	a := make(map[string]string)
	for i, name := range r.SubexpNames() {
		a[name] = match[i]
	}
	return a["value"], nil
}

// Login allows to login using Bugzilla CGI API
func (client *bugzillaCGIClient) login() (err error) {
	klog.Infof("Authenticating to bugzilla via CGI")

	u, err := url.Parse(client.bugzillaAddr)
	if err != nil {
		return err
	}
	u.Path = "index.cgi"
	loginURL := u.String()

	err = client.setBugzillaLoginCookie(loginURL)
	if err != nil {
		return err
	}

	loginToken, err := client.getBugzillaLoginToken(loginURL)
	if err != nil {
		return err
	}

	data := url.Values{}
	data.Set("Bugzilla_login", client.bugzillaLogin)
	data.Set("Bugzilla_password", client.bugzillaPassword)
	data.Set("Bugzilla_login_token", loginToken)

	req, err := newHTTPRequest("POST", loginURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.httpClient.Do(req)
	defer func() {
		if res != nil && res.Body != nil {
			res.Body.Close()
		}
	}()
	if err != nil {
		if strings.Contains(err.Error(), "use of closed network connection") {
			return fmt.Errorf("Timeout occured while accessing %v", loginURL)
		}
		return err
	}

	return nil
}

func (client *bugzillaCGIClient) GetCookies() []*http.Cookie {
	url, _ := url.Parse(client.bugzillaAddr)
	cookies := client.httpClient.Jar.Cookies(url)
	return cookies
}

func (client *bugzillaCGIClient) SetCookies(cookies []*http.Cookie) {
	url, _ := url.Parse(client.bugzillaAddr)
	client.httpClient.Jar.SetCookies(url, cookies)
}

func (client *bugzillaCGIClient) authenticated(f func() (*http.Response, error)) (*http.Response, error) {
	res, err := f()
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body = ioutil.NopCloser(bytes.NewBuffer(bs))

	if strings.Contains(string(bs), "needs a legitimate login") || strings.Contains(string(bs), "Parameters Required") {
		if err := client.login(); err != nil {
			return nil, err
		}
		res, err = f()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}
