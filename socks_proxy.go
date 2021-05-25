package main

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// GO 语言实现的socks5代理

const (
	SERVER_IP   = "0.0.0.0"
	SERVER_PORT = 10002
	MTU         = 1600

	IPV4ADDRESS = 0x01
	DOMAINNAME  = 0x03
	IPV6ADDRESS = 0x04
)

func tunnel(from net.Conn, to net.Conn) {
	var n int
	var err error
	buf := make([]byte, MTU)
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
			from.Close()
			to.Close()
		}
	}()
	for {
		if n, err = from.Read(buf); err != nil {
			panic(err)
		}

		if _, err = to.Write(buf[:n]); err != nil {
			panic(err)
		}
	}
}

// TEST CMD: curl www.baidu.com --socks5 172.18.80.183:10002
// TEST CMD: curl www.feifeishijie.com --socks5-hostname 172.18.80.183:10002
// 主要是IO阻塞会比较麻烦 --- redis 协议抓包试试看

// TODO 握手过程有小概率出现拆包问题(此时代码会出错),粘包问题不会出现
func handler(conn net.Conn) {
	defer func() {
		if err := recover(); err != nil{
			log.Println(err)
		}
	}()
	var n int
	var err error
	buf := make([]byte, MTU)

	if n, err = conn.Read(buf); err != nil {
		// n = 0  且 err 为EOF 时对方关闭描述符
		panic(err)
	}
	if n < 3 {
		log.Println("version method selection message error...")
		return
	}
	/*

			+----+----------+----------+
		 	|VER | NMETHODS | METHODS |
		 	+----+----------+----------+
		 	| 1 | 1 | 1 to 255 |
		 	+----+----------+----------+

			+----+--------+
		 	|VER | METHOD |
		 	+----+--------+
		 	| 1 | 1 |
		 	+----+--------+

	*/

	version := int8(buf[0])
	numOfMethod := int(buf[1])
	for i := 0; i < numOfMethod; i++ {
		method := int(buf[2+i])
		switch {
		case method == 0x00:
			log.Println("NO AUTHENTICATION REQUIRED")
		case method == 0x01:
			log.Println("GSSAPI")
		case method == 0x02:
			log.Println("USERNAME/PASSWORD")
		case method >= 0x03 && method <= 0x7F:
			log.Println(" IANA ASSIGNED")
		case method >= 0x80 && method <= 0xFE:
			log.Println(" RESERVED FOR PRIVATE METHODS")
		case method == 0xFF:
			log.Println(" NO ACCEPTABLE METHODS")
		}
	}
	log.Printf("version : %v, numOfMethod : %v", version, numOfMethod)
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		panic(err)
	}

	// Request
	/*
		 	+----+-----+-------+------+----------+----------+
			|VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
		 	+----+-----+-------+------+----------+----------+
			| 1 | 1 | X’00’ | 1 | Variable | 2 |
			+----+-----+-------+------+----------+----------+


			+----+-----+-------+------+----------+----------+
		 	|VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
		 	+----+-----+-------+------+----------+----------+
		 	| 1 | 1 | X’00’ | 1 | Variable | 2 |
		 	+----+-----+-------+------+----------+----------+

	*/

	if n, err = conn.Read(buf); err != nil {
		// n = 0  且 err 为EOF 时对方关闭描述符
		panic(err)
	}

	VER := buf[0]
	CMD := buf[1]
	RSV := buf[2]
	ATYP := buf[3]
	var ADDR []byte
	if ATYP == IPV4ADDRESS {
		ADDR = buf[4 : n-2]
	} else if ATYP == DOMAINNAME {
		ADDR = buf[5 : n-2]
	} else {
		panic("invalid ATYP...")
	}
	PORT := binary.BigEndian.Uint16(buf[n-2:])
	log.Printf("VER : %v, CMD : %v, RSV : %v, ATYP: %v, ADDR : %v, PORT : %v", VER, CMD, RSV,
		ATYP, ADDR, PORT)
	var addr string
	if ATYP == IPV4ADDRESS {
		IP := strconv.Itoa(int(ADDR[0])) + "." + strconv.Itoa(int(ADDR[1])) + "." +
			strconv.Itoa(int(ADDR[2])) + "." + strconv.Itoa(int(ADDR[3]))
		addr = IP + ":" + strconv.Itoa(int(PORT))
	} else if ATYP == DOMAINNAME {
		addr = string(ADDR) + ":" + strconv.Itoa(int(PORT))
	}
	to, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		panic(err)
	}
	const SUCCEEDED = 0
	var data []byte= make([]byte,10)
	data[0] = VER
	data[1] = SUCCEEDED
	data[2] = 0x00
	data[3] = 0x01
	r := to.LocalAddr().String()
	log.Println("r : ", r)
	localIp := strings.Split(strings.Split(r, ":")[0], ".")
	for i := 0; i < len(localIp); i++{
		d, _ := strconv.Atoi(localIp[i])
		data[4 + i] = byte(d)
	}

	localPortInt ,_ := strconv.Atoi(strings.Split(r, ":")[1])
	localPort := uint16(localPortInt)
	binary.BigEndian.PutUint16(data[8:],localPort)
	if _, err = conn.Write(data); err != nil {
		panic(err)
	}

	go tunnel(conn, to)
	go tunnel(to, conn)

}
func main() {
	address := SERVER_IP + ":" + strconv.Itoa(SERVER_PORT)
	sock, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			panic(err)
		}
		go handler(conn)
	}
}
