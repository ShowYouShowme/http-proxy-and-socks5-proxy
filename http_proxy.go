package main
// 使用go语言实现的HTTP proxy
import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	MTU = 1600
)

func transfer(from net.Conn, to net.Conn) {
	buf := make([]byte, MTU)
	var err error
	var n int
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

func main() {
	// HTTP 代理
	handlerHttp := func(writer http.ResponseWriter, request *http.Request) {
		req, _ := http.NewRequest(request.Method, request.RequestURI, nil)
		req.Header = request.Header
		client := http.Client{}
		resp, _ := client.Do(req)
		for k, v := range resp.Header {
			for i := 0; i < len(v); i++ {
				item := v[i]
				writer.Header().Add(k, item)
			}
		}
		writer.WriteHeader(resp.StatusCode)
		io.Copy(writer, resp.Body)
	}

	// 处理HTTPS 请求,CONNECT 方法
	tunnel := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		// 获取底层TCP连接
		hj, _ := w.(http.Hijacker)
		browser, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		go transfer(conn, browser)
		go transfer(browser, conn)
	}

	http.ListenAndServe(":8888", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			tunnel(w, r)
		} else {
			handlerHttp(w, r)
		}
	}))
}
