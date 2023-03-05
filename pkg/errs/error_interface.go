package errs

type Error interface {
	Error() string
	GetErr() error
	GetMessage() string
	GetFile() string
	GetStack() string
	GetErrorType() ErrorType
	IsType(flags ErrorType) bool
	IsErrNoRows() bool
	UnWrap() error
	GetErrorDebugResponse() *ErrorDebugResponse
}
