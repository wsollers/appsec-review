module example.test/svc

go 1.22

require (
	example.test/dep v0.1.0
	example.test/lib v0.0.0
)

replace example.test/lib => ../lib
