package main

import "net"

type Conn struct {
	conn   net.Conn
	cipher Cipher
}

func NewConn(conn net.Conn, cipher Cipher) *Conn {
	return &Conn{conn, cipher}
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.cipher.dec == nil {
		return c.conn.Read(b)
	}
	n, err := c.conn.Read(b)
	if n > 0 {
		c.cipher.Decrypt(b[0:n], b[0:n])
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.cipher.dec == nil {
		return c.conn.Write(b)
	}
	c.cipher.Encrypt(b, b)
	return c.conn.Write(b)
}

func (c *Conn) Close() {
	c.conn.Close()
}

func (c *Conn) CloseRead() {
	if conn, ok := c.conn.(*net.TCPConn); ok {
		conn.CloseRead()
	}
}

func (c *Conn) CloseWrite() {
	if conn, ok := c.conn.(*net.TCPConn); ok {
		conn.CloseWrite()
	}
}


