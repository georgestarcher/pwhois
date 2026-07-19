package pwhois

import (
	"errors"
	"fmt"
)

func ExampleOperationError() {
	err := &OperationError{
		Operation: "lookup IP",
		Server:    "whois.pwhois.org:43",
		Err:       ErrRateLimited,
	}

	fmt.Println(errors.Is(err, ErrRateLimited))
	var operationError *OperationError
	fmt.Println(errors.As(err, &operationError))
	fmt.Printf("%s %s\n", operationError.Operation, operationError.Server)

	// Output:
	// true
	// true
	// lookup IP whois.pwhois.org:43
}
