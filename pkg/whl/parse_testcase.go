package whl

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// write something cool here
	FlaskDeps = []types.Library{
		{"jinja2", "2.4"},
		{"werkzeug", "0.7"},
		{"click", "2.0"},
		{"itsdangerous", "0.21"},
	}
	Jinja2Deps = []types.Library{
		{"markupsafe", "0.23"},
		{"babel", "0.8"},
	}
)
