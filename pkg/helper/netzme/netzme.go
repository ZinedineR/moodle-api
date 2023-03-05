package netzme

import (
	"os"
	"strings"

	"moodle-api/internal/base/domain"
	"moodle-api/pkg/helper/signhelper"
)

func BuildSignature(sourceUrl, method, auth, body, timestamp string) string {
	return "path=" + sourceUrl + "&" + "method=" + method + "&" +
		"token=" + auth + "&" + "timestamp=" + timestamp + "&" + "body=" + body
}

func BuildKey(auth, timestamp string) string {
	return os.Getenv("PASSWORD_NETZME") + "-" + timestamp + "-" + auth
}

func BuildHashPin(newPin, clientId, merchantId string) string {
	key := clientId + merchantId

	hash := signhelper.SignHMAC256(key, newPin)

	return hash
}

func ParsingUri(url, version string) string {
	return strings.Replace(url, version, "", -1)
}

func GetStatusResponse(statusCode, serviceCode, caseCode string, description interface{}) *domain.SnapStatus {
	switch statusCode {
	case "200":
		return &domain.SnapStatus{
			ResponseCode:    statusCode + serviceCode + caseCode,
			ResponseMessage: "Successful",
		}

	case "400":
		switch caseCode {
		case "00":
			if description != "" {
				return &domain.SnapStatus{
					ResponseCode:    statusCode + serviceCode + caseCode,
					ResponseMessage: description,
				}
			}

			return &domain.SnapStatus{
				ResponseCode:    statusCode + serviceCode + caseCode,
				ResponseMessage: "Bad Request",
			}
		case "01", "02":
			return &domain.SnapStatus{
				ResponseCode:    statusCode + serviceCode + caseCode,
				ResponseMessage: description,
			}
		}

	case "401":
		switch caseCode {
		case "00", "01", "02":
			return &domain.SnapStatus{
				ResponseCode:    statusCode + serviceCode + caseCode,
				ResponseMessage: description,
			}
		case "03":
			return &domain.SnapStatus{
				ResponseCode:    statusCode + serviceCode + caseCode,
				ResponseMessage: "token not found",
			}

		}
	case "404":
		return &domain.SnapStatus{
			ResponseCode:    statusCode + serviceCode + caseCode,
			ResponseMessage: description,
		}
	case "503":
		return &domain.SnapStatus{
			ResponseCode:    statusCode + serviceCode + caseCode,
			ResponseMessage: "service unavailable",
		}
	}

	return &domain.SnapStatus{
		ResponseCode:    statusCode + serviceCode + caseCode,
		ResponseMessage: description,
	}
}
