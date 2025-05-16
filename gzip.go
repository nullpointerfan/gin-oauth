package ginoauth

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
)

func CompressJWT(jwt string) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)

	_, err := zw.Write([]byte(jwt))
	if err != nil {
		return "", err
	}

	if err := zw.Close(); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func DecompressJWT(compressed string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(compressed)
	if err != nil {
		return "", err
	}

	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return "", err
	}

	return string(decompressed), nil
}
