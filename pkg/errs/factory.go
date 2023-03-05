package errs

import "fmt"

const (
	ErrorTypePanic               = 500
	ErrorTypeUnProcessableEntity = 422
)

func Wrap(err error) Error {
	return generateError("", err, ErrorTypeUnProcessableEntity, 3)
}

func generateError(name string, err error, errType ErrorType, stackIndex int) Error {
	if err == nil {
		return nil
	}
	stack, file := StackAndFile(stackIndex)
	return &errCustom{
		Message: name,
		Err:     err,
		Type:    errType,
		File:    file,
		Stack:   stack,
	}
}

func PanicError(name string, err error, skip int) Error {
	stack, file := StackAndFile(skip)

	if err == nil {
		err = fmt.Errorf("%s", name)
	}

	return &errCustom{
		Message: name,
		Err:     err,
		Type:    ErrorTypePanic,
		File:    file,
		Stack:   stack,
	}

}
