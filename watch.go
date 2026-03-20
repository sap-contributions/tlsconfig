package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
)

type certWatcher struct {
	certPath string
	keyPath  string

	snapshot atomic.Value // *tls.Certificate
	reloadMu sync.Mutex
}

func newCertWatcher(certPath, keyPath string) (*certWatcher, error) {
	r := &certWatcher{
		certPath: certPath,
		keyPath:  keyPath,
	}

	certificate, err := r.loadCertificate()
	if err != nil {
		return nil, err
	}

	r.snapshot.Store(certificate)

	if err := watchFiles([]string{certPath, keyPath}, r.reload); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *certWatcher) certificate() *tls.Certificate {
	return r.snapshot.Load().(*tls.Certificate)
}

func (r *certWatcher) reload() {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	certificate, err := r.loadCertificate()
	if err != nil {
		return
	}

	r.snapshot.Store(certificate)
}

func (r *certWatcher) loadCertificate() (*tls.Certificate, error) {
	loadErr := func(err error) error {
		return fmt.Errorf("failed to load keypair: %s", err)
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, loadErr(err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, loadErr(err)
	}

	if err := checkExpiration(x509Cert); err != nil {
		return nil, loadErr(err)
	}

	return &cert, nil
}

type caWatcher struct {
	caPath string

	snapshot atomic.Value // *x509.CertPool
	reloadMu sync.Mutex
}

func newCAWatcher(caPath string) (*caWatcher, error) {
	r := &caWatcher{caPath: caPath}

	pool, err := r.loadPool()
	if err != nil {
		return nil, err
	}

	r.snapshot.Store(pool)

	if err := watchFiles([]string{caPath}, r.reload); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *caWatcher) certPool() *x509.CertPool {
	return r.snapshot.Load().(*x509.CertPool)
}

func (r *caWatcher) reload() {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	pool, err := r.loadPool()
	if err != nil {
		return
	}

	r.snapshot.Store(pool)
}

func (r *caWatcher) loadPool() (*x509.CertPool, error) {
	pool, err := FromEmptyPool(
		WithCertsFromFile(r.caPath),
	).Build()
	if err != nil {
		return nil, err
	}

	return pool, nil
}

func watchFiles(paths []string, onChange func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, path := range paths {
		dir := filepath.Dir(path)
		if _, ok := seen[dir]; ok {
			continue
		}

		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return fmt.Errorf("failed to watch directory %q: %s", dir, err)
		}

		seen[dir] = struct{}{}
	}

	go func() {
		defer watcher.Close()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				handleWatchEvent(watcher, event, onChange)
			case _, ok := <-watcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()

	return nil
}

func handleWatchEvent(watcher *fsnotify.Watcher, event fsnotify.Event, onChange func()) {
	switch {
	case event.Op.Has(fsnotify.Write):
	case event.Op.Has(fsnotify.Create):
	case event.Op.Has(fsnotify.Chmod), event.Op.Has(fsnotify.Remove), event.Op.Has(fsnotify.Rename):
		_ = watcher.Add(event.Name)
	default:
		return
	}

	onChange()
}
