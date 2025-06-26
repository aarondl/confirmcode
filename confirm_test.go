package confirmcode

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aarondl/authboss/v3"
	"github.com/aarondl/authboss/v3/mocks"
)

type mockUser struct {
	Email              string
	Confirmed          bool
	ConfirmCode        string
	ConfirmExpiration  time.Time
	ConfirmLastAttempt time.Time
}

var (
	_ authboss.User = &mockUser{}
	_ User          = &mockUser{}
)

func (m mockUser) GetPID() string                     { return m.Email }
func (m mockUser) GetEmail() string                   { return m.Email }
func (m mockUser) GetConfirmed() bool                 { return m.Confirmed }
func (m mockUser) GetConfirmCode() string             { return m.ConfirmCode }
func (m mockUser) GetConfirmExpiration() time.Time    { return m.ConfirmExpiration }
func (m mockUser) GetConfirmLastAttempt() time.Time   { return m.ConfirmLastAttempt }
func (m *mockUser) PutPID(v string)                   { m.Email = v }
func (m *mockUser) PutEmail(v string)                 { m.Email = v }
func (m *mockUser) PutConfirmed(v bool)               { m.Confirmed = v }
func (m *mockUser) PutConfirmCode(v string)           { m.ConfirmCode = v }
func (m *mockUser) PutConfirmExpiration(v time.Time)  { m.ConfirmExpiration = v }
func (m *mockUser) PutConfirmLastAttempt(v time.Time) { m.ConfirmLastAttempt = v }

func TestInit(t *testing.T) {
	t.Parallel()

	ab := authboss.New()

	router := &mocks.Router{}
	renderer := &mocks.Renderer{}
	errHandler := &mocks.ErrorHandler{}
	ab.Config.Core.Router = router
	ab.Config.Core.MailRenderer = renderer
	ab.Config.Core.ErrorHandler = errHandler

	_, err := Setup(ab, Defaults())
	if err != nil {
		t.Fatal(err)
	}

	if err := renderer.HasLoadedViews(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		t.Error(err)
	}

	if err := router.HasGets("/confirm"); err != nil {
		t.Error(err)
	}
}

type testHarness struct {
	confirm *Confirm
	ab      *authboss.Authboss

	bodyReader *mocks.BodyReader
	mailer     *mocks.Emailer
	redirector *mocks.Redirector
	renderer   *mocks.Renderer
	responder  *mocks.Responder
	session    *mocks.ClientStateRW
	storer     *mockServerStorer
}

func testSetup() *testHarness {
	harness := &testHarness{}

	harness.ab = authboss.New()
	harness.bodyReader = &mocks.BodyReader{}
	harness.mailer = &mocks.Emailer{}
	harness.redirector = &mocks.Redirector{}
	harness.renderer = &mocks.Renderer{}
	harness.responder = &mocks.Responder{}
	harness.session = mocks.NewClientRW()
	harness.storer = newMockServerStorer()

	harness.ab.Modules.MailNoGoroutine = true

	harness.ab.Config.Core.BodyReader = harness.bodyReader
	harness.ab.Config.Core.Logger = mocks.Logger{}
	harness.ab.Config.Core.Mailer = harness.mailer
	harness.ab.Config.Core.Redirector = harness.redirector
	harness.ab.Config.Core.MailRenderer = harness.renderer
	harness.ab.Config.Core.Responder = harness.responder
	harness.ab.Config.Storage.SessionState = harness.session
	harness.ab.Config.Storage.Server = harness.storer

	harness.confirm = &Confirm{Authboss: harness.ab, config: Defaults()}

	return harness
}

func TestPreventAuthAllow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mockUser{
		Confirmed: true,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if handled {
		t.Error("it should not have been handled")
	}
}

func TestPreventDisallow(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mockUser{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.PreventAuth(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should have been handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm" {
		t.Error("redirect path was wrong:", p)
	}
}

func TestStartConfirmationWeb(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mockUser{Email: "test@test.com"}
	harness.storer.Users["test@test.com"] = user

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	handled, err := harness.confirm.StartConfirmationWeb(w, r, false)
	if err != nil {
		t.Error(err)
	}

	if !handled {
		t.Error("it should always be handled")
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("redirect did not occur")
	}

	if p := harness.redirector.Options.RedirectPath; p != "/confirm" {
		t.Error("redirect path was wrong:", p)
	}

	if to := harness.mailer.Email.To[0]; to != "test@test.com" {
		t.Error("mailer sent e-mail to wrong person:", to)
	}
}

func TestGetSuccess(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	user := &mockUser{Email: "test@test.com", Confirmed: false}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	if err := harness.confirm.Get(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Error("expected ok, got:", w.Code)
	}
	if p := harness.responder.Page; p != PageConfirm {
		t.Error("page was wrong:", p)
	}
}

func TestPostValidationFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Errors: []error{errors.New("fail")},
	}

	r := mocks.Request("POST")
	w := httptest.NewRecorder()

	if err := harness.confirm.Post(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != "/confirm" {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != "confirm token is invalid" {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestPostUserNotFoundFailure(t *testing.T) {
	t.Parallel()

	harness := testSetup()

	harness.bodyReader.Return = mocks.Values{
		Token: "123-123",
	}

	r := mocks.Request("POST")
	w := httptest.NewRecorder()

	if err := harness.confirm.Post(w, r); err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != "/confirm" {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Failure; reason != "confirm token is invalid" {
		t.Error("reason for failure was wrong:", reason)
	}
}

func TestPostSuccess(t *testing.T) {
	t.Parallel()

	code, hash, err := GenerateConfirmCreds(8)
	if err != nil {
		t.Fatal(err)
	}

	user := &mockUser{
		Email:              "test@test.com",
		Confirmed:          false,
		ConfirmExpiration:  time.Now().UTC().Add(time.Hour),
		ConfirmLastAttempt: time.Now().UTC().Add(-time.Hour),
		ConfirmCode:        hash,
	}
	storer := &mockServerStorer{
		Users: map[string]*mockUser{user.Email: user},
	}

	harness := testSetup()
	harness.ab.Storage.Server = storer
	harness.bodyReader.Return = mocks.Values{
		Token: addDashes(code, 3),
	}

	r := mocks.Request("POST")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	if err := harness.confirm.Post(w, r); err != nil {
		t.Error(err)
	}
	if w.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, got:", w.Code)
	}
	if p := harness.redirector.Options.RedirectPath; p != "/" {
		t.Error("redir path was wrong:", p)
	}
	if reason := harness.redirector.Options.Success; reason != "You have successfully confirmed your account." {
		t.Error("reason for success was wrong:", reason)
	}

	user = storer.Users[user.Email]
	if user.ConfirmCode != "" {
		t.Error("confirm code not cleared")
	}
	if !user.Confirmed {
		t.Error("user was not confirmed")
	}
	if !user.ConfirmExpiration.IsZero() {
		t.Error("confirm expiration not cleared")
	}
	if !user.ConfirmLastAttempt.IsZero() {
		t.Error("confirm last attempt not cleared")
	}
}

func TestMiddlewareAllow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	called := false
	server := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mockUser{
		Confirmed: true,
	}

	r := mocks.Request("POST")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if !called {
		t.Error("The user should have been allowed through")
	}
}

func TestMiddlewareDisallow(t *testing.T) {
	t.Parallel()

	ab := authboss.New()
	redirector := &mocks.Redirector{}
	ab.Config.Core.Logger = mocks.Logger{}
	ab.Config.Core.Redirector = redirector

	called := false
	server := Middleware(ab)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	user := &mockUser{
		Confirmed: false,
	}

	r := mocks.Request("GET")
	r = r.WithContext(context.WithValue(r.Context(), authboss.CTXKeyUser, user))
	w := httptest.NewRecorder()

	server.ServeHTTP(w, r)

	if called {
		t.Error("The user should not have been allowed through")
	}
	if redirector.Options.Code != http.StatusTemporaryRedirect {
		t.Error("expected a redirect, but got:", redirector.Options.Code)
	}
	if p := redirector.Options.RedirectPath; p != "/auth/confirm" {
		t.Error("redirect path wrong:", p)
	}
}

func TestAddDashes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		In     string
		Want   string
		Dashes int
	}{
		{In: "123123", Dashes: 0, Want: "123123"},
		{In: "123123", Dashes: 1, Want: "1-2-3-1-2-3"},
		{In: "123123", Dashes: 2, Want: "12-31-23"},
		{In: "123123", Dashes: 3, Want: "123-123"},
		{In: "123123", Dashes: 4, Want: "1231-23"},
		{In: "123123", Dashes: 5, Want: "12312-3"},
		{In: "123123", Dashes: 6, Want: "123123"},
	}

	for i, test := range tests {
		got := addDashes(test.In, test.Dashes)
		if got != test.Want {
			t.Errorf("%d) want: %s, got: %s", i, test.Want, got)
		}
	}
}

func TestGenerateConfirmCreds(t *testing.T) {
	t.Parallel()

	code, hash, err := GenerateConfirmCreds(6)
	if err != nil {
		t.Error(err)
	}

	if code == hash {
		t.Error("the code and hash should be different")
	}

	if len(hash) != base64.StdEncoding.EncodedLen(sha512.Size) {
		t.Errorf("hash length was wrong (%d): %s", len(hash), hash)
	}

	if len(code) != 6 {
		t.Errorf("code length was wrong (%d): %s", len(code), code)
	}

	codeHash, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Error(err)
	}
	check := sha512.Sum512([]byte(code))
	if 0 != bytes.Compare(codeHash, check[:]) {
		t.Error("expected code hashes to match")
	}
}

var (
	_ authboss.ServerStorer = &mockServerStorer{}
	_ Storer                = &mockServerStorer{}
)

type mockServerStorer struct {
	Users map[string]*mockUser
}

// NewServerStorer constructor
func newMockServerStorer() *mockServerStorer {
	return &mockServerStorer{
		Users: make(map[string]*mockUser),
	}
}

// New constructs a blank user to later be created
func (s *mockServerStorer) New(context.Context) authboss.User {
	return &mockUser{}
}

// Create a user
func (s *mockServerStorer) Create(ctx context.Context, user authboss.User) error {
	u := user.(*mockUser)
	if _, ok := s.Users[u.Email]; ok {
		return authboss.ErrUserFound
	}
	s.Users[u.Email] = u
	return nil
}

// Load a user
func (s *mockServerStorer) Load(ctx context.Context, key string) (authboss.User, error) {
	user, ok := s.Users[key]
	if ok {
		return user, nil
	}

	return nil, authboss.ErrUserNotFound
}

func (s *mockServerStorer) Save(ctx context.Context, user authboss.User) error {
	u := user.(*mockUser)
	if _, ok := s.Users[u.Email]; !ok {
		return authboss.ErrUserNotFound
	}
	s.Users[u.Email] = u
	return nil
}

func (s *mockServerStorer) LoadByConfirmCode(ctx context.Context, code string) (User, error) {
	for _, v := range s.Users {
		if v.ConfirmCode == code {
			return v, nil
		}
	}

	return nil, authboss.ErrUserNotFound
}
