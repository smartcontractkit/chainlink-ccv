package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildKeyImport(t *testing.T) {
	t.Parallel()

	keyImport, files, err := BuildKeyImport(
		"/host/exports/node-0/ocr2.json",
		"/host/exports/node-0/password.txt",
		"0xAAAA",
	)
	require.NoError(t, err)
	require.NotNil(t, keyImport)
	require.Len(t, files, 2)

	// Every path the config declares must be backed by a mounted file, or the container starts and
	// cannot find the key it was told to import.
	mounted := make(map[string]string, len(files))
	for _, f := range files {
		mounted[f.ContainerFilePath] = f.HostFilePath
	}
	assert.Equal(t, "/host/exports/node-0/ocr2.json", mounted[keyImport.Path])
	assert.Equal(t, "/host/exports/node-0/password.txt", mounted[keyImport.PasswordPath])
	assert.Equal(t, "0xAAAA", keyImport.ExpectedID)

	// Neither the target key nor the export format is part of the config: the bootstrapper derives
	// the first from the keys it declares and reads the second from the file.
	assert.NotEqual(t, keyImport.Path, keyImport.PasswordPath)
}

func TestBuildKeyImportErrors(t *testing.T) {
	t.Parallel()

	t.Run("no key file", func(t *testing.T) {
		t.Parallel()
		_, _, err := BuildKeyImport("", "/a/password.txt", "")
		require.ErrorContains(t, err, "exported key file")
	})

	t.Run("no password file", func(t *testing.T) {
		t.Parallel()
		_, _, err := BuildKeyImport("/a/key.json", "", "")
		require.ErrorContains(t, err, "export password file")
	})
}
