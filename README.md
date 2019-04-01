# go-socks5

一个简单的基于 socks5 proxy


## Features

- [x] 只实现 TCP
- [x] 只使用RC4 加密通信



## Install

Pre-built binaries for common platforms are available at https://github.com/tluolovembtan/go-socks5/releases

Install from source

```sh
go get -u -v github.com/tluolovembtan/go-socks5
```


## Basic Usage

### Server

Start a server listening on port 8499 

```sh
go-socks5 -p 123456  -debug true
```


### Client

Start a client connecting to the above server. The client listens on port 1080 for incoming SOCKS5 
connections,

```sh
go-socks5  -p 123456  -l 127.0.0.1:1081 -socks 127.0.0.1:8499 -debug true

```
