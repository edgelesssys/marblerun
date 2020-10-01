package marble

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

type fileHandler interface {
	Create(path string, perm os.FileMode) error
	Destroy(path string) error
	Write(path string, data []byte, perm os.FileMode) error
	Read(path string) ([]byte, error)
}

type prefixFileHandler struct {
	Prefix string
}

func (pfh *prefixFileHandler) Create(path string, perm os.FileMode) error {
	newPath := filepath.Join(pfh.Prefix, path)
	return os.MkdirAll(filepath.Dir(newPath), perm)
}

func (pfh *prefixFileHandler) Destroy(path string) error {
	newPath := filepath.Join(pfh.Prefix, path)
	return os.RemoveAll(filepath.Dir(newPath))
}

func (pfh *prefixFileHandler) Write(path string, data []byte, perm os.FileMode) error {
	newPath := filepath.Join(pfh.Prefix, path)
	return ioutil.WriteFile(newPath, []byte(data), perm)
}

func (pfh *prefixFileHandler) Read(path string) ([]byte, error) {
	newPath := filepath.Join(pfh.Prefix, path)
	return ioutil.ReadFile(newPath)
}

type mockFileHandler struct {
	files map[string][]byte
}

func (mfh *mockFileHandler) Create(path string, perm os.FileMode) error {
	mfh.files[path] = []byte{}
	return nil
}

func (mfh *mockFileHandler) Destroy(path string) error {
	delete(mfh.files, path)
	return nil
}

func (mfh *mockFileHandler) Write(path string, data []byte, perm os.FileMode) error {
	mfh.files[path] = data
	return nil
}

func (mfh *mockFileHandler) Read(path string) ([]byte, error) {
	if data, ok := mfh.files[path]; ok {
		return data, nil
	}
	return nil, os.ErrNotExist
}
