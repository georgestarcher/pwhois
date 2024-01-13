# pwhois [![Go Reference](https://pkg.go.dev/badge/github.com/georgestarcher/pwhois.svg)](https://pkg.go.dev/github.com/georgestarcher/pwhois)[![Report Card](https://goreportcard.com/badge/github.com/georgestarcher/pwhois)](https://goreportcard.com/report/github.com/georgestarcher/pwhois)[![Build Status](https://github.com/georgestarcher/pwhois/workflows/pwhois%20CI/badge.svg)](https://github.com/georgestarcher/pwhois/actions)

A Go (golang) module for looking up information from [PWHOIS](https://pwhois.org/).

Written by George Starcher with OpenAI ChatGPT v3.5 Jan 6rd, 2024
  * https://help.openai.com/en/articles/6825453-chatgpt-release-notes
  * https://chat.openai.com/share/f664e12a-e26f-4a64-96e2-8ecdf9008938

Referenced Original whob source:
* [whob source code](https://pwhois.org/lft/)

MIT license, check license.txt for more information
All text above must be included in any redistribution

## Installation

```shell
go get github.com/georgestarcher/pwhois
```

## Usage

1. The maximum batch query size is 500 IP addresses. Going larger or querying too frequently could get you rate limited.
2. Watch for error `ERROR: Unable to perform lookup; Daily query limit exceeded.` raised from the Lookup method. You have been rate limited by the phwois server.
3. You can consider `server.MaxBatchSize = 100` or other value to protect your daily limit. `500` is the default.

A go usage would be like the following. Note since each query is a network byte stream communications we make a connection for each query. 

In the IP lookup you could add up to the `MaxBatchSize` number of IPs for a single query.

```go

package main

import (
	"fmt"
	"sync"

	"github.com/georgestarcher/pwhois"
)

func main() {

	// A Connection for IP query
	server1 := new(pwhois.WhoisServer)
	server1.SetDefaultValues()
	err := server1.Connect()
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("Connection Established to %+v\n", server1.Connection.RemoteAddr())
	}

	// A Connection for routeview query
	server2 := new(pwhois.WhoisServer)
	server2.SetDefaultValues()
	err = server2.Connect()
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("Connection Established to %+v\n", server2.Connection.RemoteAddr())
	}

	// A Connection for registry query
	server3 := new(pwhois.WhoisServer)
	server3.SetDefaultValues()
	err = server3.Connect()
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("Connection Established to %+v\n", server3.Connection.RemoteAddr())
	}

	// A Connection for netblock query
	server4 := new(pwhois.WhoisServer)
	server4.SetDefaultValues()
	err = server4.Connect()
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("Connection Established to %+v\n", server4.Connection.RemoteAddr())
	}

	// Setup for the IP query
	var wg sync.WaitGroup

	c := make(chan pwhois.IpLookupResponse)

	// IP lookup
	valueIP := "8.8.8.8"
	var values []string
	values = append(values, valueIP)
	query, err := server1.FormatIpQuery(values)
	if err != nil {
		fmt.Printf("%+v", err)
	}

	// Setup for the routeview query
	c2 := make(chan pwhois.BGPLookupResponse)
	valueASN := "15169"
	queryRV, err := server2.FormatRouteViewQuery(valueASN)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	// Setup for the registry query
	c3 := make(chan pwhois.RegistryLookupResponse)
	queryRegistry, err := server3.FormatRegistryQuery(valueASN)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	// Setup for the netblock query
	c4 := make(chan pwhois.NetblockLookupResponse)
	queryNetblock, err := server3.FormatNetblockQuery(valueASN)
	if err != nil {
		fmt.Printf("%+v\n", err)
	}

	// Excute each connection/query as a goroutine
	wg.Add(4)
	go func() {
		defer wg.Done()
		server1.LookupIP(query, c)
		server2.LookupRouteView(valueASN, queryRV, c2)
		server3.LookupRegistry(valueASN, queryRegistry, c3)
		server4.LookupNetblock(valueASN, queryNetblock, c4)
	}()

	// Get IP query results
	whoisAnswer := <-c
	if whoisAnswer.Error != nil {
		fmt.Printf("ERROR: %+v\n", whoisAnswer.Error)
	}

	// Get routeview query results
	asnAnswer := <-c2
	if asnAnswer.Error != nil {
		fmt.Printf("ERROR:%+v\n", asnAnswer.Error)
	}

	// Get registry query results
	registryAnswer := <-c3
	if registryAnswer.Error != nil {
		fmt.Printf("ERROR:%+v\n", registryAnswer.Error)
	}

	// Get netblock query results
	netblockAnswer := <-c4
	if netblockAnswer.Error != nil {
		fmt.Printf("ERROR:%+v\n", netblockAnswer.Error)
	}

	// Show results
	fmt.Printf("IP Response:%+v\n", whoisAnswer.Response)
	fmt.Printf("RouteView Response:%+v with # of Routes:%v\n", asnAnswer.Response.Asn, len(asnAnswer.Response.Routes))
	fmt.Printf("Registration:%+v\n", registryAnswer.Response.Registry)
	fmt.Printf("Netblock Response:%+v with # of Blocks:%v\n", netblockAnswer.Response.Asn, len(netblockAnswer.Response.Netblocks))
}
```

## pwhois Servers

Source: whob.c from the [whob source code](https://pwhois.org/lft/)

* whois.pwhois.org
* whois.ra.net
* whois.cymru.com
* whois.arin.net
* whois.apnic.net
* whois.ripe.net
* riswhois.ripe.net