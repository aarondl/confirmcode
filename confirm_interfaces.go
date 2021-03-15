package confirmcode

import (
	"context"
	"fmt"
	"time"

	"github.com/volatiletech/authboss/v3"
)

// User can be in a state of confirmed or not.
type User interface {
	authboss.User

	GetEmail() (email string)
	GetConfirmed() (confirmed bool)
	GetConfirmCode() (code string)
	GetConfirmExpiration() (date time.Time)
	GetConfirmLastAttempt() (date time.Time)

	PutEmail(email string)
	PutConfirmed(confirmed bool)
	PutConfirmCode(verifier string)
	PutConfirmExpiration(date time.Time)
	PutConfirmLastAttempt(date time.Time)
}

// Storer for confirm module, allows looking up a user by a code
type Storer interface {
	authboss.ServerStorer

	// LoadByConfirmCode finds a user by his confirm selector field
	// and should return ErrUserNotFound if that user cannot be found.
	LoadByConfirmCode(ctx context.Context, code string) (User, error)
}

// MustHaveConfirmFields ensures the user has confirm-related fields
func MustHaveConfirmFields(u authboss.User) User {
	if cu, ok := u.(User); ok {
		return cu
	}
	panic(fmt.Sprintf("could not upgrade user to a confirmable user, type: %T", u))
}

// EnsureCanConfirm makes sure the server storer supports
// confirm-lookup operations
func EnsureCanConfirm(storer authboss.ServerStorer) Storer {
	s, ok := storer.(Storer)
	if !ok {
		panic("could not upgrade ServerStorer to confirm.Storer, check your struct")
	}

	return s
}
