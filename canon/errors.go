package canon

// Error is the type of the errors this package reports by value. This
// package's functions wrap them with the detail of each failure; match them
// with errors.Is.
type Error string

func (e Error) Error() string { return string(e) }
