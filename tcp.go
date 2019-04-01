package main

import (
	"net"
	"github.com/tluolovembtan/go-socks5/socks"
	"io"
	"time"
)

// socks local
func tcpLocal(addr string, server string, cipher string,password string){
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}
	defer ln.Close()
	logf("listening TCP on %s", addr)

	if err != nil {
		logf("connect socks server err:%v\n", err)
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil{
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer conn.Close()
			conn.(*net.TCPConn).SetKeepAlive(true)
			target, err := socks.Handshake(conn)

			lConn := NewConn(conn,*&Cipher{} ) // socks5 local <--> choreme 不需要加密
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}

			// 连接 socks5 server
			rc, err := net.Dial("tcp", server)
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			sConn := NewConn(rc,*NewCipher(cipher,[]byte(password))) // socks5 local <--> socks 5 server 需要假面
			// 直接发送 address
			if _, err = sConn.Write(target); err != nil {
				logf("failed to send target address: %v", err)
				return
			}
			logf("proxy %s <-> %s <-> %s", conn.RemoteAddr(), server, target)
			_, _, err = relay(sConn, lConn)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}

		}()
	}


}
// socks server
func tcpServer(addr string,cipher string,password string)  {
	ln,err := net.Listen("tcp", addr)
	if err != nil{
		logf("failed to listen on %s: %v", addr, err)
		return
	}
	defer ln.Close()
	logf("listening TCP on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil{
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer conn.Close()
			conn.(*net.TCPConn).SetKeepAlive(true)

			cConn := NewConn(conn,*NewCipher(cipher,[]byte(password))) // socks5 server <--> socks5 local 需要加密


			remote_addr, err := socks.ReadAddr(cConn)
			if err != nil {
				logf("failed to get target address: %v", err)
				return
			}
			// 连接 google
			rc, err := net.Dial("tcp", remote_addr.String())
			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()
			rc.(*net.TCPConn).SetKeepAlive(true)
			logf("proxy %s <-> %s", conn.RemoteAddr(), remote_addr)
			rConn := NewConn(rc, *&Cipher{}) // socks5 server <--> remote 不需要加密

			_, _, err = relay(cConn, rConn)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}


		}()
	}

}

// 复制转发数据流
func relay(left, right *Conn) (int64, int64, error) {
	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)

	go func() {
		n, err := io.Copy(right, left)
		right.conn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		left.conn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	}()

	n, err := io.Copy(left, right)
	right.conn.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	left.conn.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if err == nil {
		err = rs.Err
	}
	return n, rs.N, err
}

