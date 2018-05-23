
build:
	rm -rf bin/tracer
	CGO_LDFLAGS="-Wl,-R -Wl,\$$ORIGIN  -lbcc" go build ./src/tethrnet.com/packet-trace/cmd/tracer.go ./src/tethrnet.com/packet-trace/cmd/cli.go
	mv tracer bin/
	cp lib* bin/
