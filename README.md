# pwhois

A Go (golang) module for looking up from [PWHOIS](https://pwhois.org/).

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
## pwhois Servers

Source: whob.c from the [whob source code](https://pwhois.org/lft/)

* whois.pwhois.org
* whois.ra.net
* whois.cymru.com
* whois.arin.net
* whois.apnic.net
* whois.ripe.net
* riswhois.ripe.net