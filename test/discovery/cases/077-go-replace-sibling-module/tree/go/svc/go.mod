module example.com/svc

go 1.22

require example.com/x v0.0.0

// replace example.com/legacy => ../../legacy
replace example.com/x => ../x
