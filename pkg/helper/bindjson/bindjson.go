package bindjson

import (
	"strings"

	"moodle-api/internal/base/app"
)

func BindJSONHelper(ctx *app.Context, obj any) (string, string) {
	var errorField string
	var errorType string
	if err := ctx.BindJSON(obj); err != nil {
		if strings.Contains(err.Error(), `cannot unmarshal`) {
			errorString := strings.Split(err.Error(), ".")
			errorString[0] = ""
			errorString2 := strings.Join(errorString, " ")
			errorField = strings.Split(errorString2, ` of type`)[0]
			errorType = "invalid_format"
		} else if strings.Contains(err.Error(), `Field validation for `) && strings.Contains(err.Error(), ` failed on the 'required' tag`) {
			errorString := strings.Split(err.Error(), `Field validation for `)
			errorField = strings.Split(errorString[1], ` failed on the 'required' tag`)[0]
			errorType = "invalid_mandatory"
		} else if strings.Contains(err.Error(), `Field validation for `) && strings.Contains(err.Error(), ` failed on the`) {
			errorString := strings.Split(err.Error(), `Field validation for `)
			errorField = strings.Split(errorString[1], ` failed on the`)[0]
			errorType = "invalid_format"
		} else {
			errorField = "undefined"
			errorType = "undefined"
		}
	}
	return errorType, errorField
}
