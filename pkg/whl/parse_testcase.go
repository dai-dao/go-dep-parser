package whl

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.7-alpine sh
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	PipenvNormal = []types.Library{
		{"urllib3", "1.24.2"},
		{"requests", "2.21.0"},
		{"pyyaml", "5.1"},
		{"idna", "2.8"},
		{"chardet", "3.0.4"},
		{"certifi", "2019.3.9"},
	}
)
