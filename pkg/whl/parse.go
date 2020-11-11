package whl

import (
	"bufio"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func Parse(r io.Reader) ([]types.Library, error) {
	f := bufio.NewReader(r)

	var (
		line    string
		err     error
		libs    []types.Library
		pkgName string
		pkg     string
		version string
	)
	replacer := strings.NewReplacer(">=", "", "<=", "", ";", "", "(", "", ")", "")
	for {
		line, err = f.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, xerrors.Errorf("decode error: %w", err)
		}

		if strings.Contains(line, "Requires-Dist:") {
			pkg = strings.TrimSpace(strings.Split(line, ":")[1])
			pkgName = strings.Split(pkg, " ")[0]
			pkgName := strings.ToLower(pkgName)
			version = strings.Split(pkg, " ")[1]
			version = replacer.Replace(version)
			libs = append(libs, types.Library{
				Name:    pkgName,
				Version: version,
			})
		}

		if err != nil {
			break
		}
	}

	return libs, nil
}
