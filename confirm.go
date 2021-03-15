// Package confirmcode implements confirmation of user registration via e-mail
// with copy-paste codes.
package confirmcode

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/friendsofgo/errors"

	"github.com/volatiletech/authboss/v3"
)

const (
	// PageConfirm is only really used for the BodyReader
	PageConfirm = "confirm"

	// EmailConfirmHTML is the name of the html template for e-mails
	EmailConfirmHTML = "confirm_html"
	// EmailConfirmTxt is the name of the text template for e-mails
	EmailConfirmTxt = "confirm_txt"

	// DataConfirmCode is the name of the template field for the user's code
	DataConfirmCode = "code"
)

var (
	// ErrRetryLimit is returned when the user has requested a resend but
	// it is too soon.
	ErrRetryLimit = errors.New("retry limit reached please wait")
)

// Config for the confirm module
type Config struct {
	// Add Dashes to codes after each N characters
	AddDashes int
	// Length of the token excluding automatically added dashes.
	Length int

	// Period between attempts
	AttemptPeriod time.Duration
	// CodeExpiry is the duration before a code expires.
	CodeExpiry time.Duration

	// PathOK is where to redirect when the user is confirmed
	PathOK string
	// PathNotOK is the url back to the confirm page
	PathNotOK string
}

// Defaults returns a safe default configuration
func Defaults() *Config {
	return &Config{
		AddDashes:     4,
		Length:        8,
		AttemptPeriod: time.Minute,
		CodeExpiry:    time.Hour,

		PathOK:    "/",
		PathNotOK: "/confirm",
	}
}

// Confirm module
type Confirm struct {
	config *Config
	*authboss.Authboss
}

// Setup the confirm module
func Setup(ab *authboss.Authboss, cfg *Config) (*Confirm, error) {
	c := new(Confirm)
	c.config = cfg

	c.Authboss = ab

	if err := c.Authboss.Config.Core.MailRenderer.Load(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		return nil, err
	}

	c.Authboss.Config.Core.Router.Get("/confirm", c.Authboss.Config.Core.ErrorHandler.Wrap(c.Get))
	c.Authboss.Config.Core.Router.Post("/confirm", c.Authboss.Config.Core.ErrorHandler.Wrap(c.Post))
	c.Authboss.Config.Core.Router.Post("/confirm/resend", c.Authboss.Config.Core.ErrorHandler.Wrap(func(w http.ResponseWriter, r *http.Request) error {
		_, err := c.StartConfirmationWeb(w, r, false)
		return err
	}))

	c.Events.Before(authboss.EventAuth, c.PreventAuth)
	c.Events.After(authboss.EventRegister, c.StartConfirmationWeb)

	return c, nil
}

// PreventAuth stops the EventAuth from succeeding when a user is not confirmed
// This relies on the fact that the context holds the user at this point in time
// loaded by the auth module (or something else).
func (c *Confirm) PreventAuth(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	logger := c.Authboss.RequestLogger(r)

	user, err := c.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := MustHaveConfirmFields(user)
	if cuser.GetConfirmed() {
		logger.Infof("user %s is confirmed, allowing auth", user.GetPID())
		return false, nil
	}

	logger.Infof("user %s was not confirmed, preventing auth", user.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: c.config.PathNotOK,
		Failure:      "Your account has not been confirmed, please verify the code that was sent to your email.",
	}
	return true, c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// StartConfirmationWeb hijacks a request and forces a user to be confirmed
// first it's assumed that the current user is loaded into the request context.
func (c *Confirm) StartConfirmationWeb(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	user, err := c.Authboss.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := MustHaveConfirmFields(user)
	if err = c.StartConfirmation(r.Context(), cuser, true); err != nil {
		return false, err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: c.config.PathNotOK,
	}
	return true, c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// StartConfirmation begins confirmation on a user by setting them to require
// confirmation via a created token, and optionally sending them an e-mail.
func (c *Confirm) StartConfirmation(ctx context.Context, user User, sendEmail bool) error {
	logger := c.Authboss.Logger(ctx)

	now := time.Now().UTC()
	if last := user.GetConfirmLastAttempt(); now.Before(last.Add(c.config.AttemptPeriod)) {
		return ErrRetryLimit
	}

	code, hash, err := GenerateConfirmCreds(c.config.Length)
	if err != nil {
		return err
	}

	user.PutConfirmed(false)
	user.PutConfirmCode(hash)
	user.PutConfirmLastAttempt(time.Now().UTC())
	user.PutConfirmExpiration(time.Now().UTC().Add(c.config.CodeExpiry))

	logger.Infof("generated new confirm token for user: %s", user.GetPID())
	if err := c.Authboss.Config.Storage.Server.Save(ctx, user); err != nil {
		return errors.Wrap(err, "failed to save user during StartConfirmation, user data may be in weird state")
	}

	if c.Authboss.Config.Modules.MailNoGoroutine {
		c.SendConfirmEmail(ctx, user.GetEmail(), code)
	} else {
		go c.SendConfirmEmail(ctx, user.GetEmail(), code)
	}

	return nil
}

// SendConfirmEmail sends a confirmation e-mail to a user
func (c *Confirm) SendConfirmEmail(ctx context.Context, to, code string) {
	logger := c.Authboss.Logger(ctx)

	email := authboss.Email{
		To:       []string{to},
		From:     c.Config.Mail.From,
		FromName: c.Config.Mail.FromName,
		Subject:  c.Config.Mail.SubjectPrefix + "Confirm New Account",
	}

	logger.Infof("sending confirm e-mail to: %s", to)

	ro := authboss.EmailResponseOptions{
		Data:         authboss.NewHTMLData(DataConfirmCode, addDashes(code, c.config.AddDashes)),
		HTMLTemplate: EmailConfirmHTML,
		TextTemplate: EmailConfirmTxt,
	}
	if err := c.Authboss.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to send confirm e-mail to %s: %+v", to, err)
	}
}

// Get shows a confirm page
func (c *Confirm) Get(w http.ResponseWriter, r *http.Request) error {
	return c.Authboss.Core.Responder.Respond(w, r, http.StatusOK, PageConfirm, nil)
}

// Post the code to the confirm page
func (c *Confirm) Post(w http.ResponseWriter, r *http.Request) error {
	logger := c.Authboss.Logger(r.Context())

	validator, err := c.Authboss.Config.Core.BodyReader.Read(PageConfirm, r)
	if err != nil {
		return err
	}

	if errs := validator.Validate(); errs != nil {
		logger.Infof("validation failed in confirm.Post, this typically means a bad code: %+v", errs)
		return c.invalidToken(w, r)
	}

	values := authboss.MustHaveConfirmValues(validator)
	rawCode := strings.ReplaceAll(values.GetToken(), "-", "")
	if len(rawCode) != c.config.Length {
		logger.Infof("invalid confirm code submitted, size was wrong: %d", len(rawCode))
		return c.invalidToken(w, r)
	}

	codeHash := sha512.Sum512([]byte(rawCode))
	codeHashB64 := base64.StdEncoding.EncodeToString(codeHash[:])

	storer := EnsureCanConfirm(c.Authboss.Config.Storage.Server)
	user, err := storer.LoadByConfirmCode(r.Context(), codeHashB64)
	if err == authboss.ErrUserNotFound {
		logger.Infof("confirm selector was not found in database: %s", codeHashB64)
		return c.invalidToken(w, r)
	} else if err != nil {
		return err
	}

	if time.Now().UTC().After(user.GetConfirmExpiration()) {
		logger.Info("stored confirm code has expired")
		return c.invalidToken(w, r)
	}

	dbConfirmHash, err := base64.StdEncoding.DecodeString(user.GetConfirmCode())
	if err != nil {
		logger.Error("invalid base64 stored in user's confirm code")
		return err
	}

	if subtle.ConstantTimeCompare(codeHash[:], dbConfirmHash) != 1 {
		logger.Info("stored confirm code does not match provided one")
		return c.invalidToken(w, r)
	}

	user.PutConfirmed(true)
	user.PutConfirmCode("")
	user.PutConfirmExpiration(time.Time{})
	user.PutConfirmLastAttempt(time.Time{})

	logger.Infof("user %s confirmed their account", user.GetPID())
	if err = c.Authboss.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "You have successfully confirmed your account.",
		RedirectPath: c.config.PathOK,
	}
	return c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

func (c *Confirm) invalidToken(w http.ResponseWriter, r *http.Request) error {
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Failure:      "confirm token is invalid",
		RedirectPath: c.config.PathNotOK,
	}
	return c.Authboss.Config.Core.Redirector.Redirect(w, r, ro)
}

// Middleware ensures that a user is confirmed, or else it will intercept the
// request and send them to the confirm page, this will load the user if he's
// not been loaded yet from the session.
//
// Panics if the user was not able to be loaded in order to allow a panic
// handler to show a nice error page, also panics if it failed to redirect
// for whatever reason.
func Middleware(ab *authboss.Authboss) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := ab.LoadCurrentUserP(&r)

			cu := MustHaveConfirmFields(user)
			if cu.GetConfirmed() {
				next.ServeHTTP(w, r)
				return
			}

			logger := ab.RequestLogger(r)
			logger.Infof("user %s prevented from accessing %s: not confirmed", user.GetPID(), r.URL.Path)
			ro := authboss.RedirectOptions{
				Code:         http.StatusTemporaryRedirect,
				Failure:      "Your account has not been confirmed, please check your e-mail.",
				RedirectPath: path.Join(ab.Config.Paths.Mount, "/confirm"),
			}
			if err := ab.Config.Core.Redirector.Redirect(w, r, ro); err != nil {
				logger.Errorf("error redirecting in confirm.Middleware: #%v", err)
			}
		})
	}
}

// GenerateConfirmCreds creates a code of given length and returns the sha512
// of that code as well for storage in a database.
func GenerateConfirmCreds(length int) (code string, hash string, err error) {
	rawToken := make([]byte, length)
	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", err
	}

	b := bytes.NewBuffer(make([]byte, 0, length))
	for _, byt := range rawToken {
		b.WriteByte((byt % 10) + '0')
	}

	codeBytes := b.Bytes()

	code = string(codeBytes)
	codeHash := sha512.Sum512(codeBytes)
	hash = base64.StdEncoding.EncodeToString(codeHash[:])

	return code, hash, nil
}

func addDashes(code string, n int) string {
	if n == 0 {
		return code
	}

	ln := len(code)
	if ln <= n {
		return code
	}

	var s strings.Builder
	for i, c := range code {
		if i != 0 && i%n == 0 {
			s.WriteByte('-')
		}
		s.WriteRune(c)
	}

	return s.String()
}
