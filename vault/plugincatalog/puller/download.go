// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package puller

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/consts"
)

const releasesURL = "https://releases.hashicorp.com"

type DownloadPluginInput struct {
	Type              consts.PluginType
	Name              string
	Version           string
	TargetFileName    string
	ExpectedPluginSum []byte
}

func (in DownloadPluginInput) sourceFile() string {
	return fmt.Sprintf("vault-plugin-%s-%s", nameForType(in.Type), in.Name)
}

// EnsurePluginDownloaded downloads the plugin if it doesn't exist at the target
// location and returns the SHA256 sum of the plugin binary.
func EnsurePluginDownloaded(ctx context.Context, in DownloadPluginInput) (sha256Sum []byte, err error) {
	// TODO: Per-plugin locking.

	if exists, err := checkExisting(in); err != nil {
		return nil, err
	} else if exists {
		// Plugin already exists, return the SHA256 sum.
		hasher := sha256.New()
		f, err := os.Open(in.TargetFileName)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err := io.Copy(hasher, f); err != nil {
			return nil, err
		}
		fileSum := hasher.Sum(nil)
		if in.ExpectedPluginSum != nil && !slices.Equal(fileSum, in.ExpectedPluginSum) {
			return nil, fmt.Errorf("plugin already existed but expected SHA256 sum %s, got %s",
				hex.EncodeToString(in.ExpectedPluginSum), hex.EncodeToString(fileSum))
		}

		return fileSum, nil
	}

	version := strings.TrimPrefix(in.Version, "v")

	// Get the SHA256SUMS file.
	binName := in.sourceFile()
	zipSums, err := getAsBytes(ctx, fmt.Sprintf("%s/%s/%s/%s_%s_SHA256SUMS", releasesURL, binName, version, binName, version))
	if err != nil {
		return nil, err
	}

	// Get the SHA256SUMS.sig file.
	sig, err := getAsBytes(ctx, fmt.Sprintf("%s/%s/%s/%s_%s_SHA256SUMS.sig", releasesURL, binName, version, binName, version))
	if err != nil {
		return nil, err
	}

	if err := verifySignature(zipSums, sig); err != nil {
		return nil, err
	}

	// Get the zip file.
	zipName := fmt.Sprintf("%s_%s_%s_%s.zip", binName, version, runtime.GOOS, runtime.GOARCH)
	tempZipFile, zipFileSum, err := getAsFileAndHash(ctx, fmt.Sprintf("%s/%s/%s/%s", releasesURL, binName, version, zipName))
	if err != nil {
		return nil, err
	}
	defer os.Remove(tempZipFile)

	// Verify our zip file matches the expected SHA256 sum.
	found := false
	for _, zipSumLine := range strings.Split(string(zipSums), "\n") {
		expectedZipSum, expectedZipName, valid := strings.Cut(zipSumLine, " ")
		if !valid {
			continue
		}
		if strings.TrimSpace(expectedZipName) == zipName {
			if expectedZipSum == hex.EncodeToString(zipFileSum) {
				found = true
				break
			} else {
				// TODO: User error?
				return nil, fmt.Errorf("expected SHA256 sum %s, got %s", expectedZipSum, zipFileSum)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("missing entry for %s in SHA256SUMS", zipName)
	}

	// Verify before we unzip so we never write a bad plugin to the plugin
	// directory and don't have to clean up an additional temp file if it fails.
	pluginSum, err := sha256SumFromZip(tempZipFile, binName)
	if err != nil {
		return nil, err
	}

	// We don't have the SHA256 sum available yet if we're downloading during
	// registration.
	if in.ExpectedPluginSum != nil {
		if !slices.Equal(pluginSum, in.ExpectedPluginSum) {
			return nil, fmt.Errorf("expected SHA256 sum %s, got %s", hex.EncodeToString(in.ExpectedPluginSum), hex.EncodeToString(pluginSum))
		}
	}

	// Unzip to the target in the plugin directory.
	zipReader, err := zip.OpenReader(tempZipFile)
	if err != nil {
		return nil, err
	}
	defer zipReader.Close()
	pluginFile, err := zipReader.Open(binName)
	if err != nil {
		return nil, err
	}
	defer pluginFile.Close()

	f, err := os.OpenFile(in.TargetFileName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(f, pluginFile); err != nil {
		return nil, err
	}

	return pluginSum, nil
}

func checkExisting(in DownloadPluginInput) (bool, error) {
	_, err := os.Stat(in.TargetFileName)
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("error checking if managed plugin file exists: %w", err)
	}
}

func sha256SumFromZip(zipFileName, pluginFileName string) ([]byte, error) {
	zipReader, err := zip.OpenReader(zipFileName)
	if err != nil {
		return nil, err
	}
	defer zipReader.Close()
	pluginFile, err := zipReader.Open(pluginFileName)
	if err != nil {
		return nil, err
	}
	defer pluginFile.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, pluginFile); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func getAsBytes(ctx context.Context, url string) ([]byte, error) {
	// TODO: check if we need to honor proxy and support other settings
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}

	return b, nil
}

func getAsFileAndHash(ctx context.Context, url string) (fileName string, shaSum []byte, retErr error) {
	zipGet, err := http.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer zipGet.Body.Close()

	f, err := os.CreateTemp(os.TempDir(), "vault-plugin-temp")
	if err != nil {
		return "", nil, err
	}
	defer func() {
		retErr = errors.Join(retErr, f.Close())
		if retErr != nil {
			retErr = errors.Join(retErr, os.Remove(f.Name()))
		}
	}()

	hasher := sha256.New()
	zipReader := io.TeeReader(zipGet.Body, hasher)
	if n, err := io.Copy(f, zipReader); err != nil {
		return "", nil, err
	} else if n != zipGet.ContentLength {
		return "", nil, fmt.Errorf("incomplete download, expected %d bytes, got %d bytes", zipGet.ContentLength, n)
	}

	return f.Name(), hasher.Sum(nil), nil
}

func nameForType(t consts.PluginType) string {
	switch t {
	case consts.PluginTypeCredential:
		return "auth"
	case consts.PluginTypeSecrets:
		return "secrets"
	default:
		return t.String()
	}
}
