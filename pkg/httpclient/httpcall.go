package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"moodle-api/internal/base/app"
	rdis "moodle-api/internal/base/service/redisser"
	"moodle-api/pkg/helper/netzme"
	"moodle-api/pkg/helper/signhelper"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/sirupsen/logrus"
)

// New creates client Factory
func New() ClientFactory {
	return *&clientFactory{}
}

// ClientFactory creates specific client implementation
type ClientFactory interface {
	CreateClient(redisClient rdis.RedisClient) Client
}

type clientFactory struct{}

func (c clientFactory) CreateClient(redisClient rdis.RedisClient) Client {
	return client{
		RedisClient: redisClient,
	}
}

// Client abstracts third party request client
type Client interface {
	Get(*app.Context, string, map[string]string, interface{}) (int, error)
	PostJSON(*app.Context, string, string, map[string]string, interface{}) (int, error)
	PostJSONWithRetryCond(*app.Context, string, string, map[string]string, interface{}, string, string) (int, error)
	GetWithRetryCond(ctx *app.Context, url string, headers map[string]string, dest interface{}, sourceUrl string, method string, bodyJson string) (int, error)
}

type client struct {
	RedisClient rdis.RedisClient
}

func (c client) PostJSON(ctx *app.Context, url string, bodyJSON string, headers map[string]string, dest interface{}) (int, error) {
	req, err := retryablehttp.NewRequest("POST", url, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	//for k, v := range headers {
	//	req.Header.Set(k, v)
	//}
	// fmt.Println(`curl --location --request POST '` + url + `' \`)
	manualHeader := make(http.Header)

	for k, v := range headers {
		manualHeader[k] = []string{v}
		// fmt.Println("--header '" + k + ": " + v + `'\`)
	}
	// fmt.Println(`--data-raw '` + bodyJSON + `'`)
	req.Header = manualHeader
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT TOKO-NETZME = URL: %s , Payload: %s , Method: %s", ctx.APIReqID, url, bodyJSON, "POST"))

	client := retryablehttp.NewClient()
	//client.RetryWaitMin = 1 * time.Minute
	//client.RetryWaitMax = 2 * time.Minute
	// retry logger
	//client.RequestLogHook = func(logger retryablehttp.Logger, request *http.Request, i int) {
	//	//logrus.Infoln(logger, request)
	//	//logrus.Infoln("ini retry ke-", i)
	//}
	//
	//client.ResponseLogHook = func(logger retryablehttp.Logger, response *http.Response) {
	//	logrus.Info("response", response)
	//}
	res, err := client.Do(req)
	if err != nil {
		return http.StatusServiceUnavailable, err
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&dest)
	if err != nil {
		return res.StatusCode, err
	}

	return res.StatusCode, nil

}

func (c client) PostJSONWithRetryCond(ctx *app.Context, url string, bodyJSON string, headers map[string]string, dest interface{}, sourceUrl string, method string) (int, error) {
	var statusCodeAfterRetry int
	req, err := retryablehttp.NewRequest("POST", url, bytes.NewBuffer([]byte(bodyJSON)))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// fmt.Println(`curl --location --request POST '` + url + `' \`)
	manualHeader := make(http.Header)

	for k, v := range headers {
		manualHeader[k] = []string{v}
		// fmt.Println("--header '" + k + ": " + v + `'\`)
	}
	// fmt.Println(`--data-raw '` + bodyJSON + `'`)
	req.Header = manualHeader
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT TOKO-NETZME = URL: %s , Payload: %s , Method: %s", ctx.APIReqID, url, bodyJSON, "POST"))

	client := retryablehttp.NewClient()
	client.RetryMax, _ = strconv.Atoi(os.Getenv("RETRY_COUNT"))
	client.RetryWaitMax, _ = time.ParseDuration(os.Getenv("RETRY_INTERVAL"))
	client.CheckRetry = func(_ context.Context, resp *http.Response, _ error) (bool, error) {
		var result bool
		if resp.StatusCode == 401 {
			accessToken, errCheck := c.RedisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
			if errCheck != nil {
				logrus.Error(`ERROR GET TOKEN FROM REDIS = ` + errCheck.Error())
			}

			auth := "Bearer " + accessToken
			req.Header.Set("Authorization", auth)

			timeMiliString := headers["Request-Time"]
			// plain = stringToSign
			plain := netzme.BuildSignature(sourceUrl, method, auth, bodyJSON, timeMiliString)
			key := netzme.BuildKey(auth, timeMiliString)
			sign := signhelper.SignHMAC256(key, plain)
			req.Header.Set("Signature", sign)
			statusCodeAfterRetry = resp.StatusCode
			result = true
		}
		return result, nil
	}
	res, err := client.Do(req)
	if err != nil {
		if res == nil {
			return statusCodeAfterRetry, err
		}
		return res.StatusCode, err
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&dest)
	if err != nil {
		return res.StatusCode, err
	}

	return res.StatusCode, nil

}

func (c client) Get(ctx *app.Context, url string, headers map[string]string, dest interface{}) (int, error) {
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// fmt.Println(`curl --location --request GET '` + url + `' \`)
	for k, v := range headers {
		req.Header.Set(k, v)
		// fmt.Println("--header '" + k + ": " + v + `'\`)
	}
	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT TOKO-NETZME = URL: %s , Payload: %s , Method: %s", ctx.APIReqID, url, "", "GET"))

	client := retryablehttp.NewClient()
	res, err := client.Do(req)
	if err != nil {
		return res.StatusCode, err
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&dest)
	if err != nil {
		return res.StatusCode, err
	}

	return res.StatusCode, nil
}

func (c client) GetWithRetryCond(ctx *app.Context, url string, headers map[string]string, dest interface{}, sourceUrl string, method string, bodyJson string) (int, error) {
	var statusCodeAfterRetry int
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// fmt.Println(`curl --location --request POST '` + url + `' \`)
	for k, v := range headers {
		req.Header.Set(k, v)
		// fmt.Println("--header '" + k + ": " + v + `'\`)
	}

	logrus.Infoln(fmt.Sprintf("REQUEST ID: %s , REQUEST HIT TOKO-NETZME = URL: %s , Payload: %s , Method: %s", ctx.APIReqID, url, "", "GET"))

	client := retryablehttp.NewClient()
	client.RetryMax, _ = strconv.Atoi(os.Getenv("RETRY_COUNT"))
	client.RetryWaitMax, _ = time.ParseDuration(os.Getenv("RETRY_INTERVAL"))
	client.CheckRetry = func(_ context.Context, resp *http.Response, _ error) (bool, error) {
		var result bool
		if resp.StatusCode == 401 {
			accessToken, errCheck := c.RedisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman")
			if errCheck != nil {
				logrus.Error(`ERROR c.RedisClient.Get(ctx, os.Getenv("CLIENT_ID_NETZME")+"-batman") = ` + errCheck.Error())
			}

			auth := "Bearer " + accessToken
			req.Header.Set("Authorization", auth)

			timeMiliString := headers["Request-Time"]
			// plain = stringToSign
			plain := netzme.BuildSignature(sourceUrl, method, auth, bodyJson, timeMiliString)
			key := netzme.BuildKey(auth, timeMiliString)
			sign := signhelper.SignHMAC256(key, plain)
			req.Header.Set("Signature", sign)
			statusCodeAfterRetry = resp.StatusCode
			result = true
		}
		return result, nil
	}
	res, err := client.Do(req)
	if err != nil {
		if res == nil {
			return statusCodeAfterRetry, err
		}
		return res.StatusCode, err
	}
	defer res.Body.Close()

	err = json.NewDecoder(res.Body).Decode(&dest)
	if err != nil {
		return res.StatusCode, err
	}

	return res.StatusCode, nil
}
