# pwhois

A Go (golang) module for looking up [PWHOIS](https://pwhois.org/).

## Installation

```shell
go get github.com/georgestarcher/pwhois
```

## Usage

1. The maximum batch query size is 500 IP addresses. Going larger or querying too frequently could get you rate limited.
2. Watch for error `ERROR: Unable to perform lookup; Daily query limit exceeded.` raised from the Lookup method. You have been rate limited by the phwois server.

In your Go app you can do something like the below. 

```go

TBD

```
## Goroutines

The Lookup method expects to be called as a goroutine. Even if just one of them.
You could break your list of IPs into different value lists, add another channel and goroutine to make simulaneous requests. Keep in mind you are very likely to hit your query limit that way.

```go

TBD

```
