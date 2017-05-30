
build:
	rm -rf bin/tracer
	go install  ...
	mv bin/cmd bin/tracer
