package fbhttp

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/filebrowser/filebrowser/v2/users"
	"golang.org/x/net/webdav"
)

const webDavPrefix = "/webdav"

var (
	webDavLocks   = make(map[uint]webdav.LockSystem)
	webDavLocksMu sync.Mutex
)

func getLockSystem(uid uint) webdav.LockSystem {
	webDavLocksMu.Lock()
	defer webDavLocksMu.Unlock()

	if _, ok := webDavLocks[uid]; !ok {
		webDavLocks[uid] = webdav.NewMemLS()
	}

	return webDavLocks[uid]
}

func webDavPathFromRequest(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, webDavPrefix)
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "."
	}

	return path
}

func hasWritePermForPut(user *users.User, target string) bool {
	if _, err := user.Fs.Stat(target); err == nil {
		return user.Perm.Modify
	} else if errors.Is(err, os.ErrNotExist) {
		return user.Perm.Create
	}

	return user.Perm.Modify
}

func hasWebDavPermission(user *users.User, r *http.Request) bool {
	switch r.Method {
	case "OPTIONS":
		return true
	case "PROPFIND", "GET", "HEAD":
		return user.Perm.Download
	case "PUT":
		return hasWritePermForPut(user, webDavPathFromRequest(r))
	case "MKCOL":
		return user.Perm.Create
	case "DELETE":
		return user.Perm.Delete
	case "COPY":
		return user.Perm.Download && user.Perm.Create
	case "MOVE":
		return user.Perm.Rename
	case "LOCK", "UNLOCK", "PROPPATCH":
		return user.Perm.Modify
	default:
		return user.Perm.Download
	}
}

func webDavHandler(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.server.EnableWebDAV {
		return http.StatusForbidden, nil
	}

	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, LOCK, PUT, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE, UNLOCK, DELETE, GET, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("DAV", "1, 2")
		return 0, nil
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="File Browser"`)
		return http.StatusUnauthorized, nil
	}

	user, err := d.store.Users.Get(d.server.Root, username)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="File Browser"`)
		return http.StatusUnauthorized, nil
	}

	if !users.CheckPwd(password, user.Password) {
		w.Header().Set("WWW-Authenticate", `Basic realm="File Browser"`)
		return http.StatusUnauthorized, nil
	}

	if !hasWebDavPermission(user, r) {
		return http.StatusForbidden, nil
	}

	handler := &webdav.Handler{
		Prefix:     webDavPrefix,
		FileSystem: &webDavFS{fs: user.Fs},
		LockSystem: getLockSystem(user.ID),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WebDAV error: %s [%s]: %v", r.RemoteAddr, r.Method, err)
			}
		},
	}

	handler.ServeHTTP(w, r)
	return 0, nil
}
