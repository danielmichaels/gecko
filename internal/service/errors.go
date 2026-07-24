package service

type messagedError struct {
	err error
	msg string
}

func (e messagedError) Error() string { return e.msg }
func (e messagedError) Unwrap() error { return e.err }

func msgErr(sentinel error, msg string) error { return messagedError{err: sentinel, msg: msg} }
