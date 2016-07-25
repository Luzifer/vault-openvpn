[![Build Status](https://travis-ci.org/Luzifer/rconfig.svg?branch=master)](https://travis-ci.org/Luzifer/rconfig)
[![License: Apache v2.0](https://badge.luzifer.io/v1/badge?color=5d79b5&title=license&text=Apache+v2.0)](http://www.apache.org/licenses/LICENSE-2.0)
[![Documentation](https://badge.luzifer.io/v1/badge?title=godoc&text=reference)](https://godoc.org/github.com/Luzifer/rconfig)
[![Go Report](http://goreportcard.com/badge/Luzifer/rconfig)](http://goreportcard.com/report/Luzifer/rconfig)

## Description

> Package rconfig implements a CLI configuration reader with struct-embedded defaults, environment variables and posix compatible flag parsing using the [pflag](https://github.com/spf13/pflag) library.

## Installation

Install by running:

```
go get -u github.com/Luzifer/rconfig
```

OR fetch a specific version:

```
go get -u gopkg.in/luzifer/rconfig.v1
```

Run tests by running:

```
go test -v -race -cover github.com/Luzifer/rconfig
```

## Usage

As a first step define a struct holding your configuration:

```go
type config struct {
  Username string `default:"unknown" flag:"user" description:"Your name"`
  Details  struct {
    Age int `default:"25" flag:"age" env:"age" description:"Your age"`
  }
}
```

Next create an instance of that struct and let `rconfig` fill that config:

```go
var cfg config
func init() {
  cfg = config{}
  rconfig.Parse(&cfg)
}
```

You're ready to access your configuration:

```go
func main() {
  fmt.Printf("Hello %s, happy birthday for your %dth birthday.",
		cfg.Username,
		cfg.Details.Age)
}
```

### Provide variable defaults by using a file

Given you have a file `~/.myapp.yml` containing some secrets or usernames (for the example below username is assumed to be "luzifer") as a default configuration for your application you can use this source code to load the defaults from that file using the `vardefault` tag in your configuration struct.

The order of the directives (lower number = higher precedence):

1. Flags provided in command line
1. Environment variables
1. Variable defaults (`vardefault` tag in the struct)
1. `default` tag in the struct

```go
type config struct {
  Username string `vardefault:"username" flag:"username" description:"Your username"`
}

var cfg = config{}

func init() {
  rconfig.SetVariableDefaults(rconfig.VarDefaultsFromYAMLFile("~/.myapp.yml"))
  rconfig.Parse(&cfg)
}

func main() {
  fmt.Printf("Username = %s", cfg.Username)
  // Output: Username = luzifer
}
```

## More info

You can see the full reference documentation of the rconfig package [at godoc.org](https://godoc.org/github.com/Luzifer/rconfig), or through go's standard documentation system by running `godoc -http=:6060` and browsing to [http://localhost:6060/pkg/github.com/Luzifer/rconfig](http://localhost:6060/pkg/github.com/Luzifer/rconfig) after installation.
