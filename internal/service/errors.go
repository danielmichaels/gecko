package service

// messagedError pairs a sentinel with a client-facing message. errors.Is(e, sentinel)
// remains true while Error() returns exactly the supplied message.
type messagedError struct {
	err error
	msg string
}

func (e messagedError) Error() string { return e.msg }
func (e messagedError) Unwrap() error { return e.err }

// msgErr wraps sentinel with a client-facing message so handlers can surface
// exact text via err.Error() while errors.Is(err, sentinel) still holds.
func msgErr(sentinel error, msg string) error { return messagedError{err: sentinel, msg: msg} }
