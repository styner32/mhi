module github.com/styner32/mhi

// T-001 pin: toolchain = supported stable Go at bootstrap (1.25.0). Cobra is
// the only runtime dep so far. goproxy is NOT added until M0's CONNECT
// passthrough is implemented (spec §2: pin deps after M0 passes; source-review
// baseline v1.9.2 is a review criterion, not auto-latest).
go 1.27.3

require (
	github.com/elazarl/goproxy v1.9.2
	github.com/spf13/cobra v1.10.2
	go.yaml.in/yaml/v3 v3.0.4
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
