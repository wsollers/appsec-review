module example.com/app

go 1.22

require (
	golang.org/x/text v0.3.7
	gopkg.in/yaml.v2 v2.2.7
)

replace gopkg.in/yaml.v2 => ./third_party/yamlfork
