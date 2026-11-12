package dplaax

// Error is the type of this package's constant sentinel errors: being
// constants, they cannot be reassigned by an importer.
//
// Compare an error with a sentinel by errors.Is alone: that an error is an
// Error under errors.As, or equal to a sentinel under ==, is not promised.
type Error string

func (e Error) Error() string { return string(e) }

// ErrSyntax is what every refusal of Parse and of ValidateRegistry is
// (errors.Is): the string is not a did:dplaax DID, or not its registry
// segment, by the dplaax rule did.dplaax.syntax. The refusal's text says what
// does not hold. The refusals of ValidateDID, RequireKnownPattern and
// RequireOwner are not ErrSyntax, ValidateDID's of an empty registry included
// (a DID Parse returned has none).
const ErrSyntax Error = "did:dplaax: syntax violation"

// syntaxError is a refusal of Parse or ValidateRegistry: its text is the
// refusal's, and it is ErrSyntax. Each of the two makes one at its only exit
// for a refusal, so every refusal of either function is one.
type syntaxError string

func (e syntaxError) Error() string { return string(e) }

// Is reports whether target is ErrSyntax.
func (e syntaxError) Is(target error) bool { return target == ErrSyntax }
