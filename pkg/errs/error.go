package errs

import "gorm.io/gorm"

type ErrorType uint64

type ErrorDebugResponse struct {
	Message string `json:"message"`
	File    string `json:"file"`
}

type errCustom struct {
	Message string    `json:"message"`
	Err     error     `json:"error"`
	Type    ErrorType `json:"type"`
	File    string    `json:"file"`
	Stack   string    `json:"stack-trace"`
}

func (msg errCustom) GetMessage() string {
	return msg.Message
}

func (msg errCustom) Error() string {
	if msg.Message != "" {
		return msg.Message + ": " + msg.Err.Error()
	}
	return msg.Err.Error()
}

func (msg errCustom) GetErr() error {
	return msg.Err
}

func (msg errCustom) GetFile() string {
	return msg.File
}

func (msg errCustom) GetStack() string {
	return msg.Stack
}

func (msg errCustom) GetErrorType() ErrorType {
	return msg.Type
}

func (msg errCustom) IsErrNoRows() bool {
	return msg.Err == gorm.ErrRecordNotFound
}

func (msg *errCustom) IsType(flags ErrorType) bool {
	return msg.Type == flags
}

func (msg *errCustom) UnWrap() error {
	return msg.Err
}

func (msg *errCustom) GetErrorDebugResponse() *ErrorDebugResponse {
	e := ErrorDebugResponse{}

	e.Message = msg.Err.Error()
	e.File = msg.File

	return &e
}
