package whl

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/kylelemons/godebug/pretty"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func TestParse(t *testing.T) {

	sitePackages := "./testdata/site-packages"
	libraries := PipenvNormal

	t.Run(sitePackages, func(t *testing.T) {

		// Get *.dist-info directories
		folders, err := filepath.Glob(sitePackages + "/*.dist-info")
		if err != nil {
			log.Fatalf("Glob() error: %v", err)
		}
		libList := []types.Library{}

		for _, f := range folders {
			if fileExists(f + "/METADATA") {
				f, err := os.Open(f + "/METADATA")
				if err != nil {
					t.Fatalf("Open() error: %v", err)
				}
				libs, err := Parse(f)
				if err != nil {
					t.Fatalf("Parse() error: %v", err)
				}
				libList = append(libList, libs...)
			}
		}

		sort.Slice(libList, func(i, j int) bool {
			ret := strings.Compare(libList[i].Name, libList[j].Name)
			if ret == 0 {
				return libList[i].Version < libList[j].Version
			}
			return ret < 0
		})

		sort.Slice(libraries, func(i, j int) bool {
			ret := strings.Compare(libraries[i].Name, libraries[j].Name)
			if ret == 0 {
				return libraries[i].Version < libraries[j].Version
			}
			return ret < 0
		})

		if len(libList) != len(libraries) {
			t.Fatalf("lib length: %s", pretty.Compare(libList, libraries))
		}

		for i, got := range libList {
			want := libraries[i]
			if want.Name != got.Name {
				t.Errorf("%d: Name: got %s, want %s", i, got.Name, want.Name)
			}
			if want.Version != got.Version {
				t.Errorf("%d: Version: got %s, want %s", i, got.Version, want.Version)
			}
		}
	})
}
