// tlscert 生成本地开发用自签名证书（含 127.0.0.1/::1 IP SAN）。
// 仅限开发联调；生产 TLS 由网关/入口层终结。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	out := "tls"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "vertify-local-dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		die(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		die(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(out+"/cert.pem", certPEM, 0o644); err != nil {
		die(err)
	}
	if err := os.WriteFile(out+"/key.pem", keyPEM, 0o600); err != nil {
		die(err)
	}
	fmt.Printf("written: %s/cert.pem %s/key.pem (CN=vertify-local-dev, SAN=127.0.0.1/::1/localhost)\n", out, out)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "tlscert:", err)
	os.Exit(1)
}
