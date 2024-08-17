module go-add

go 1.22.5

replace github.com/zkMIPS/zkm/go-runtime/zkm_runtime => ../../../go-runtime/zkm_runtime

require github.com/zkMIPS/zkm/go-runtime/zkm_runtime v0.0.0-00010101000000-000000000000

require (
	github.com/blocto/solana-go-sdk v1.30.0 // indirect
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56 // indirect
)
