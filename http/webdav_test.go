package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"
	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
)

func TestWebDavHandler(t *testing.T) {
	const password = "password"
	hashedPassword, err := users.HashPwd(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	allPerms := users.Permissions{
		Admin:    true,
		Create:   true,
		Rename:   true,
		Modify:   true,
		Delete:   true,
		Download: true,
	}

	testCases := map[string]struct {
		enabled            bool
		method             string
		path               string
		username           string
		password           string
		perm               users.Permissions
		prepareFS          func(fs afero.Fs) error
		expectedStatusCode int
	}{
		"WebDAV disabled": {
			enabled:            false,
			method:             "PROPFIND",
			path:               "/webdav/",
			username:           "admin",
			password:           password,
			perm:               allPerms,
			expectedStatusCode: http.StatusForbidden,
		},
		"WebDAV enabled no auth": {
			enabled:            true,
			method:             "PROPFIND",
			path:               "/webdav/",
			perm:               allPerms,
			expectedStatusCode: http.StatusUnauthorized,
		},
		"WebDAV enabled wrong password": {
			enabled:            true,
			method:             "PROPFIND",
			path:               "/webdav/",
			username:           "admin",
			password:           "wrong",
			perm:               allPerms,
			expectedStatusCode: http.StatusUnauthorized,
		},
		"WebDAV enabled correct auth": {
			enabled:            true,
			method:             "PROPFIND",
			path:               "/webdav/",
			username:           "admin",
			password:           password,
			perm:               allPerms,
			expectedStatusCode: http.StatusMultiStatus,
		},
		"OPTIONS without auth": {
			enabled:            true,
			method:             http.MethodOptions,
			path:               "/webdav/",
			perm:               allPerms,
			expectedStatusCode: http.StatusOK,
		},
		"PUT new file requires create permission": {
			enabled:  true,
			method:   http.MethodPut,
			path:     "/webdav/new.txt",
			username: "admin",
			password: password,
			perm: users.Permissions{
				Admin:    true,
				Create:   false,
				Modify:   true,
				Delete:   true,
				Rename:   true,
				Download: true,
			},
			expectedStatusCode: http.StatusForbidden,
		},
		"PUT existing file requires modify permission": {
			enabled:  true,
			method:   http.MethodPut,
			path:     "/webdav/existing.txt",
			username: "admin",
			password: password,
			perm: users.Permissions{
				Admin:    true,
				Create:   true,
				Modify:   false,
				Delete:   true,
				Rename:   true,
				Download: true,
			},
			prepareFS: func(fs afero.Fs) error {
				return afero.WriteFile(fs, "existing.txt", []byte("x"), 0o644)
			},
			expectedStatusCode: http.StatusForbidden,
		},
		"DELETE requires delete permission": {
			enabled:  true,
			method:   http.MethodDelete,
			path:     "/webdav/existing.txt",
			username: "admin",
			password: password,
			perm: users.Permissions{
				Admin:    true,
				Create:   true,
				Modify:   true,
				Delete:   false,
				Rename:   true,
				Download: true,
			},
			expectedStatusCode: http.StatusForbidden,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "db")
			db, err := storm.Open(dbPath)
			if err != nil {
				t.Fatalf("failed to open db: %v", err)
			}
			t.Cleanup(func() {
				_ = db.Close()
			})

			st, err := bolt.NewStorage(db)
			if err != nil {
				t.Fatalf("failed to get storage: %v", err)
			}

			if err := st.Users.Save(&users.User{
				Username: "admin",
				Password: hashedPassword,
				Perm:     tc.perm,
			}); err != nil {
				t.Fatalf("failed to save user: %v", err)
			}

			if err := st.Settings.Save(&settings.Settings{Key: []byte("key")}); err != nil {
				t.Fatalf("failed to save settings: %v", err)
			}

			baseFs := afero.NewBasePathFs(afero.NewMemMapFs(), "/")
			if tc.prepareFS != nil {
				if err := tc.prepareFS(baseFs); err != nil {
					t.Fatalf("failed to prepare fs: %v", err)
				}
			}

			st.Users = &customFSUser{
				Store: st.Users,
				fs:    baseFs,
			}

			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.username != "" {
				req.SetBasicAuth(tc.username, tc.password)
			}

			recorder := httptest.NewRecorder()
			status, err := webDavHandler(recorder, req, &data{
				server: &settings.Server{Root: "/", EnableWebDAV: tc.enabled},
				store:  st,
			})
			if err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if status != 0 {
				if status != tc.expectedStatusCode {
					t.Fatalf("expected status %d, got %d", tc.expectedStatusCode, status)
				}
				return
			}

			if recorder.Result().StatusCode != tc.expectedStatusCode {
				t.Fatalf("expected status %d, got %d", tc.expectedStatusCode, recorder.Result().StatusCode)
			}
		})
	}
}
