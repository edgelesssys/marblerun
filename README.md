# Coordinator
## Build
To build both the host and enclave parts:
```
mkdir build
cd build
cmake ..
make
```

To build the marble-dummy host and enclave parts for testing:
```
cd marble
mkdir build
cd build
cmake ..
make
```

## Run
```
OE_SIMULATION=1 ./coordinator
```
## Test
### Unit Tests
```
go test -race ./...
```
### SGX2
```
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/
```
### Simulation
```
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s
```
### NoEnclave
```
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s -noenclave
```

# Protobuf
## Build

To update the protobuf defintion, you need to have the `protoc` compiler and the corresponding Go plugin `protoc-gen-go` installed. Please follow the instructions [here](https://grpc.io/docs/quickstart/go/). (There is no need to install the `gRPC` module as it will be fetched automatically.)

Once `protoc` is installed, run the following to update protobuf definitions.
```bash
go generate
```

## Test

```
go test
```
