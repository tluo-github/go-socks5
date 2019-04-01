package main

import (
	"log"
	"flag"
)

var config struct {
	Debug    bool		//是否 debug 日志
}
// 打印日志
func logf(f string, v ...interface{}) {
	if config.Debug {
		log.Printf(f, v...)
	}
}
func main() {
	var flags struct {
		Local    string
		Server    string
		Cipher    string
		Socks     string
		Password  string
		verbose	  bool

	}
	flag.BoolVar(&config.Debug, "debug", false, "debug 模式")
	flag.StringVar(&flags.Cipher, "cipher", "rc4", "可用的 ciphers: RC4 ")
	flag.StringVar(&flags.Password, "p", "123456", "密码")
	flag.StringVar(&flags.Server, "s", "0.0.0.0:8499", "socks5 server 监听地址 eg:0.0.0.0:8499")
	flag.StringVar(&flags.Socks, "socks", "127.0.0.1:8499", "(client-only) SOCKS listen address")
	flag.StringVar(&flags.Local, "l", "", "socks5 client 连接地址 eg: 0.0.0.0.:1080")
	flag.Parse()

	if flags.Password == "" {
		flag.Usage()
		return
	}

	if flags.Local != "" {
		// client 模式
		tcpLocal(flags.Local,flags.Socks,flags.Cipher,flags.Password)
	}else if  flags.Server != "" {
		// server 模式
		tcpServer(flags.Server,flags.Cipher,flags.Password)
	}

}
