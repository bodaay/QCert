package certtools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

// THANKS TO THIS LINK: https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

//TODO:  1- Add more paramters to the structures 2- Make sure notafter cannot be greate than CA notafter. 3- Add functions to Generate CSR
/*

RootCA Certificate

*/
//RootCA Structure, Default NotAfter Years is 20
type RootCA struct {
	CommonName            string
	Organization          string
	NotAfterNumberOfYears uint8
	CACert                *x509.Certificate
	TLSCACert             *tls.Certificate
	CAPublic              *rsa.PublicKey
	CAPrivate             *rsa.PrivateKey
	CAPEMcert             []byte
	CAPEMpublic           []byte
	CAPEMprivate          []byte
}

func (r *RootCA) CreateNewRootCA(TargetFolder string) ([]string, error) {
	if _, err := os.Stat(path.Join(TargetFolder, "rootca.cert")); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Rootca cert Exists, delete it yourself")
	}
	if r.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}
	if r.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}

	notebefore := time.Now()
	if r.NotAfterNumberOfYears == 0 {
		r.NotAfterNumberOfYears = 20
	}
	notafter := time.Now().AddDate(int(r.NotAfterNumberOfYears), 0, 0)

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	rootcaFileName := path.Join(TargetFolder, "rootca.cert")
	rootcaPublicFileName := path.Join(TargetFolder, "rootca.pub.key")
	rootcaPrivateKeyFileName := path.Join(TargetFolder, "rootca.key")
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	ca := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			CommonName:   r.CommonName,
			Organization: []string{r.Organization},
			// Country:      []string{r.Country},
			// Province:     []string{r.Province},
			// Locality:     []string{r.Locality},
		},
		NotBefore: notebefore,
		NotAfter:  notafter,
		// SignatureAlgorithm:    x509.SHA512WithRSA,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	certparsed, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}
	r.CACert = certparsed
	r.CAPrivate = caPrivKey
	r.CAPublic = &caPrivKey.PublicKey
	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(rootcaFileName, caPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, rootcaFileName)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&caPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(rootcaPublicFileName, caPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, rootcaPublicFileName)
	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(rootcaPrivateKeyFileName, caPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, rootcaPrivateKeyFileName)
	r.CAPEMcert = caPEM.Bytes()
	r.CAPEMpublic = caPublicKeyPEM.Bytes()
	r.CAPEMprivate = caPrivKeyPEM.Bytes()
	// TLS
	tlscert, err := tls.X509KeyPair(r.CAPEMcert, r.CAPEMprivate)
	if err != nil {
		return nil, err
	}
	r.TLSCACert = &tlscert
	return ListOfFilesCreated, nil
}

func (r *RootCA) LoadRootCAFromFiles(certPEMFile string, certPrivateKeyPEMFile string) error {
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPEMFile))

	}
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPrivateKeyPEMFile))
	}
	cabytes, err := ioutil.ReadFile(certPEMFile)
	if err != nil {
		return err
	}
	r.CAPEMcert = cabytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(cabytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	r.CACert = cert
	r.CAPublic = cert.PublicKey.(*rsa.PublicKey)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(r.CAPublic),
	})
	if err != nil {
		return err
	}
	r.CAPEMpublic = caPublicKeyPEM.Bytes()

	caprivateBytes, err := ioutil.ReadFile(certPrivateKeyPEMFile)
	if err != nil {
		return err
	}
	blockpriv, _ := pem.Decode(caprivateBytes)
	caprivate, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	r.CAPEMprivate = caprivateBytes
	r.CAPrivate = caprivate

	r.CommonName = r.CACert.Subject.CommonName
	if len(r.CACert.Subject.Organization) > 0 {
		r.Organization = r.CACert.Subject.Organization[0]
	}
	// r.Organization = r.CACert.Subject.Organization
	// TLS
	tlscert, err := tls.X509KeyPair(r.CAPEMcert, r.CAPEMprivate)
	if err != nil {
		return err
	}
	r.TLSCACert = &tlscert
	//TODO: load other certificate paramters into the structure, like organization, notbefore, etc...
	return nil
}

func (r *RootCA) LoadRootCAFromPEM(certPEM string, certPrivateKeyPEM string) error {

	cabytes := []byte(certPEM)
	r.CAPEMcert = cabytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(cabytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	r.CACert = cert
	r.CAPublic = cert.PublicKey.(*rsa.PublicKey)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(r.CAPublic),
	})
	if err != nil {
		return err
	}
	r.CAPEMpublic = caPublicKeyPEM.Bytes()

	caprivateBytes := []byte(certPrivateKeyPEM)
	blockpriv, _ := pem.Decode(caprivateBytes)
	caprivate, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	r.CAPEMprivate = caprivateBytes
	r.CAPrivate = caprivate

	r.CommonName = r.CACert.Subject.CommonName
	if len(r.CACert.Subject.Organization) > 0 {
		r.Organization = r.CACert.Subject.Organization[0]
	}
	// r.Organization = r.CACert.Subject.Organization
	// TLS
	tlscert, err := tls.X509KeyPair(r.CAPEMcert, r.CAPEMprivate)
	if err != nil {
		return err
	}
	r.TLSCACert = &tlscert
	//TODO: load other certificate paramters into the structure, like organization, notbefore, etc...
	return nil
}

/*

Intermediate Certificate

*/
//IntermediateCert Structure, Default NotAfter Years is 15
type IntermediateCert struct {
	CommonName            string
	Organization          string
	NotAfterNumberOfYears uint8
	CACert                *x509.Certificate
	TLSCACert             *tls.Certificate
	CAPublic              *rsa.PublicKey
	CAPrivate             *rsa.PrivateKey
	CAPEMcert             []byte
	CAPEMpublic           []byte
	CAPEMprivate          []byte
}

func (i *IntermediateCert) CreateNewSignedIntermediateCA(TargetFolder string, rootcert *x509.Certificate, rootprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(path.Join(TargetFolder, "intermediate.cert")); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Intermediate cert Exists, delete it yourself")
	}
	if i.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}
	if i.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	var ListOfFilesCreated []string
	notebefore := time.Now()
	if i.NotAfterNumberOfYears == 0 {
		i.NotAfterNumberOfYears = 15
	}
	notafter := time.Now().AddDate(int(i.NotAfterNumberOfYears), 0, 0)

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	intermediatecaFileName := path.Join(TargetFolder, "intermediate.cert")
	intermediatecaPublicFileName := path.Join(TargetFolder, "intermediate.pub.key")
	intermediatecaPrivateKeyFileName := path.Join(TargetFolder, "intermediate.key")
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			CommonName:   i.CommonName,
			Organization: []string{i.Organization},
			// Country:      []string{r.Country},
			// Province:     []string{r.Province},
			// Locality:     []string{r.Locality},
		},
		NotBefore: notebefore,
		NotAfter:  notafter,
		// SignatureAlgorithm:    x509.SHA512WithRSA,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	//Sanity check
	if ca.Subject.String() == rootcert.Subject.String() {
		return nil, fmt.Errorf("Intermediate Certificate Cannot have same subject name as Root: %s", ca.Subject.String())
	}
	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, rootcert, &caPrivKey.PublicKey, rootprivateKey)
	if err != nil {
		return nil, err
	}
	certparsed, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}
	i.CACert = certparsed
	i.CAPrivate = caPrivKey
	i.CAPublic = &caPrivKey.PublicKey
	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaFileName, caPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaFileName)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&caPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaPublicFileName, caPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaPublicFileName)
	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaPrivateKeyFileName, caPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaPrivateKeyFileName)
	i.CAPEMcert = caPEM.Bytes()
	i.CAPEMpublic = caPublicKeyPEM.Bytes()
	i.CAPEMprivate = caPrivKeyPEM.Bytes()
	// TLS
	tlscert, err := tls.X509KeyPair(i.CAPEMcert, i.CAPEMprivate)
	if err != nil {
		return nil, err
	}
	i.TLSCACert = &tlscert
	return ListOfFilesCreated, nil
}

func (i *IntermediateCert) CreateIntermediateCASignRequest(TargetFolder string) ([]string, error) {
	if _, err := os.Stat(path.Join(TargetFolder, "intermediate.csr")); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Intermediate CSR Exists, delete it yourself")
	}
	if i.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}
	if i.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	intermediatecaCSRFileName := path.Join(TargetFolder, "intermediate.csr")
	intermediatecaPublicFileName := path.Join(TargetFolder, "intermediate.pub.key")
	intermediatecaPrivateKeyFileName := path.Join(TargetFolder, "intermediate.key")
	// Cryptographically secure.
	var ListOfFilesCreated []string
	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   i.CommonName,
			Organization: []string{i.Organization},
			// Country:      []string{r.Country},
			// Province:     []string{r.Province},
			// Locality:     []string{r.Locality},
		},
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// create our private and public key
	csrPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	CSRBytes, err := x509.CreateCertificateRequest(rand.Reader, csrReq, csrPrivKey)
	if err != nil {
		return nil, err
	}
	i.CAPrivate = csrPrivKey
	i.CAPublic = &csrPrivKey.PublicKey
	// pem encode
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: CSRBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaCSRFileName, csrPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaCSRFileName)
	csrPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&csrPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaPublicFileName, csrPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaPublicFileName)
	csrPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(intermediatecaPrivateKeyFileName, csrPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, intermediatecaPrivateKeyFileName)
	i.CAPEMcert = csrPEM.Bytes()
	i.CAPEMpublic = csrPublicKeyPEM.Bytes()
	i.CAPEMprivate = csrPrivKeyPEM.Bytes()
	return ListOfFilesCreated, nil
}

func (i *IntermediateCert) LoadIntermediateCAFromFiles(certPEMFile string, certPrivateKeyPEMFile string) error {
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPEMFile))

	}
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPrivateKeyPEMFile))
	}
	cabytes, err := ioutil.ReadFile(certPEMFile)
	if err != nil {
		return err
	}
	i.CAPEMcert = cabytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(cabytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	i.CACert = cert
	i.CAPublic = cert.PublicKey.(*rsa.PublicKey)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(i.CAPublic),
	})
	if err != nil {
		return err
	}
	i.CAPEMpublic = caPublicKeyPEM.Bytes()

	caprivateBytes, err := ioutil.ReadFile(certPrivateKeyPEMFile)
	if err != nil {
		return err
	}
	blockpriv, _ := pem.Decode(caprivateBytes)
	caprivate, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	i.CAPEMprivate = caprivateBytes
	i.CAPrivate = caprivate

	i.CommonName = i.CACert.Subject.CommonName
	if len(i.CACert.Subject.Organization) > 0 {
		i.Organization = i.CACert.Subject.Organization[0]
	}
	// i.Organization = i.CACert.Subject.Organization
	// TLS
	tlscert, err := tls.X509KeyPair(i.CAPEMcert, i.CAPEMprivate)
	if err != nil {
		return err
	}
	i.TLSCACert = &tlscert
	return nil
}
func (i *IntermediateCert) LoadIntermediateCAFromPEM(certPEM string, certPrivateKeyPEM string) error {

	cabytes := []byte(certPEM)
	i.CAPEMcert = cabytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(cabytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	i.CACert = cert
	i.CAPublic = cert.PublicKey.(*rsa.PublicKey)
	caPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(i.CAPublic),
	})
	if err != nil {
		return err
	}
	i.CAPEMpublic = caPublicKeyPEM.Bytes()

	caprivateBytes := []byte(certPrivateKeyPEM)
	blockpriv, _ := pem.Decode(caprivateBytes)
	caprivate, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	i.CAPEMprivate = caprivateBytes
	i.CAPrivate = caprivate

	i.CommonName = i.CACert.Subject.CommonName
	if len(i.CACert.Subject.Organization) > 0 {
		i.Organization = i.CACert.Subject.Organization[0]
	}
	// i.Organization = i.CACert.Subject.Organization
	// TLS
	tlscert, err := tls.X509KeyPair(i.CAPEMcert, i.CAPEMprivate)
	if err != nil {
		return err
	}
	i.TLSCACert = &tlscert
	return nil
}
func SignIntermediateCSR(csrfilePEM string, TargetFolder string, NotAfterNumberOfYears uint8, rootcert *x509.Certificate, rootprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(csrfilePEM); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return nil, fmt.Errorf(fmt.Sprintf("cannot find: %s", csrfilePEM))

	}
	var ListOfFilesCreated []string
	csrbytes, err := ioutil.ReadFile(csrfilePEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrbytes)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 15
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	//Sanity check
	if ca.Subject.String() == rootcert.Subject.String() {
		return nil, fmt.Errorf("Intermediate Certificate Cannot have same subject name as Root: %s", ca.Subject.String())
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, rootcert, &rootprivateKey.PublicKey, rootprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	signedCertFileName := path.Join(TargetFolder, "intermediate.cert")
	if _, err := os.Stat(signedCertFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	ioutil.WriteFile(signedCertFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, signedCertFileName)
	return ListOfFilesCreated, nil
}

func SignIntermediateCSRPEM(csrPEM []byte, NotAfterNumberOfYears uint8, rootcert *x509.Certificate, rootprivateKey *rsa.PrivateKey) ([]byte, error) {

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 15
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	//Sanity check
	if ca.Subject.String() == rootcert.Subject.String() {
		return nil, fmt.Errorf("Intermediate Certificate Cannot have same subject name as Root: %s", ca.Subject.String())
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, ca, rootcert, &rootprivateKey.PublicKey, rootprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

/*

Server Certificate

*/
//ServerCert Structure, Default NotAfter Years is 10
type ServerCert struct {
	CommonName            string
	Organization          string
	Country               string
	Province              string
	Locality              string
	DNSNames              []string
	IPAddresses           []net.IP
	NotAfterNumberOfYears uint8
	Cert                  *x509.Certificate
	TLSCert               *tls.Certificate
	PrivateKey            *rsa.PrivateKey
	PublicKey             *rsa.PublicKey
	PEMcert               []byte
	PEMpublic             []byte
	PEMprivate            []byte
}

func (s *ServerCert) CreateAndSignNewServerCert(TargetFolder string, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {

	if s.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	// if s.Organization == "" {
	// 	return errors.New("Organization Cannot be empty")
	// }
	rootNames := cacert.Subject
	if s.Organization == "" {
		s.Organization = rootNames.Organization[0]
	}
	if s.Country == "" {
		s.Country = "QA"
	}
	if s.Province == "" {
		s.Province = "DOHA"
	}
	if s.Locality == "" {
		s.Locality = "DOHA"
	}

	notebefore := time.Now()
	if s.NotAfterNumberOfYears == 0 {
		s.NotAfterNumberOfYears = 10
	}
	notafter := time.Now().AddDate(int(s.NotAfterNumberOfYears), 0, 0)
	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			CommonName:   s.CommonName,
			Organization: []string{s.Organization},
			Country:      []string{s.Country},
			Province:     []string{s.Province},
			Locality:     []string{s.Locality},
		},
		DNSNames:    s.DNSNames,
		IPAddresses: s.IPAddresses,
		NotBefore:   notebefore,
		NotAfter:    notafter,
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &certPrivKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	// serverFileName := path.Join(TargetFolder, s.CommonName+".cert")
	// serverPublicFileName := path.Join(TargetFolder, s.CommonName+".pub.key")
	// serverPrivateKeyFileName := path.Join(TargetFolder, s.CommonName+".key")
	certFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".cert")
	if _, err := os.Stat(certFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	certPublicFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".pub.key")
	certPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".key")
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&certPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPublicFileName, certPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPublicFileName)
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPrivateKeyFileName, certPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPrivateKeyFileName)
	certparsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	s.Cert = certparsed
	s.PrivateKey = certPrivKey
	s.PublicKey = &certPrivKey.PublicKey
	s.PEMcert = certPEM.Bytes()
	s.PEMpublic = certPublicKeyPEM.Bytes()
	s.PEMprivate = certPrivKeyPEM.Bytes()
	// TLS
	tlscert, err := tls.X509KeyPair(s.PEMcert, s.PEMprivate)
	if err != nil {
		return nil, err
	}
	s.TLSCert = &tlscert
	return ListOfFilesCreated, nil
}

func (s *ServerCert) CreateServerSignRequest(TargetFolder string) ([]string, error) {

	if s.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	if s.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	CSRFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".csr")
	if _, err := os.Stat(CSRFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Request Exists, delete it yourself")
	}
	csrPublicFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".pub.key")
	csrPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(s.CommonName, "\n\r .?!@#$%^")+".key")
	// Cryptographically secure.

	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   s.CommonName,
			Organization: []string{s.Organization},
			Country:      []string{s.Country},
			Province:     []string{s.Province},
			Locality:     []string{s.Locality},
		},
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           s.DNSNames,
		IPAddresses:        s.IPAddresses,
	}

	// create our private and public key
	csrPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	CSRBytes, err := x509.CreateCertificateRequest(rand.Reader, csrReq, csrPrivKey)
	if err != nil {
		return nil, err
	}
	s.PrivateKey = csrPrivKey
	s.PublicKey = &csrPrivKey.PublicKey
	// pem encode
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: CSRBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(CSRFileName, csrPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, CSRFileName)

	csrPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&csrPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPublicFileName, csrPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPublicFileName)
	csrPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPrivateKeyFileName, csrPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPrivateKeyFileName)
	s.PEMcert = csrPEM.Bytes()
	s.PEMpublic = csrPublicKeyPEM.Bytes()
	s.PEMprivate = csrPrivKeyPEM.Bytes()
	return ListOfFilesCreated, err
}

func (s *ServerCert) LoadServerCertFromFiles(certPEMFile string, certPrivateKeyPEMFile string) error {
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPEMFile))

	}
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPrivateKeyPEMFile))
	}
	certbytes, err := ioutil.ReadFile(certPEMFile)
	if err != nil {
		return err
	}
	s.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	s.Cert = cert
	s.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(s.PublicKey),
	})
	if err != nil {
		return err
	}
	s.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes, err := ioutil.ReadFile(certPrivateKeyPEMFile)
	if err != nil {
		return err
	}
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	s.PEMprivate = privateBytes
	s.PrivateKey = private

	s.CommonName = s.Cert.Subject.CommonName
	if len(s.Cert.Subject.Organization) > 0 {
		s.Organization = s.Cert.Subject.Organization[0]
	}
	if len(s.Cert.Subject.Country) > 0 {
		s.Country = s.Cert.Subject.Country[0]
	}
	if len(s.Cert.Subject.Province) > 0 {
		s.Province = s.Cert.Subject.Province[0]
	}
	if len(s.Cert.Subject.Locality) > 0 {
		s.Locality = s.Cert.Subject.Locality[0]
	}
	// s.Organization = s.Cert.Subject.Organization
	// s.Country = s.Cert.Subject.Country
	// s.Province = s.Cert.Subject.Province
	// s.Locality = s.Cert.Subject.Locality
	s.IPAddresses = s.Cert.IPAddresses
	s.DNSNames = s.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(s.PEMcert, s.PEMprivate)
	if err != nil {
		return err
	}
	s.TLSCert = &tlscert
	//TODO: load other certificate paramters into the structure, like organization, notbefore, etc...
	return nil
}

func (s *ServerCert) LoadServerCertFromPEM(certPEM string, certPrivateKeyPEM string) error {

	certbytes := []byte(certPEM)
	s.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	s.Cert = cert
	s.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(s.PublicKey),
	})
	if err != nil {
		return err
	}
	s.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes := []byte(certPrivateKeyPEM)
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	s.PEMprivate = privateBytes
	s.PrivateKey = private

	s.CommonName = s.Cert.Subject.CommonName
	if len(s.Cert.Subject.Organization) > 0 {
		s.Organization = s.Cert.Subject.Organization[0]
	}
	if len(s.Cert.Subject.Country) > 0 {
		s.Country = s.Cert.Subject.Country[0]
	}
	if len(s.Cert.Subject.Province) > 0 {
		s.Province = s.Cert.Subject.Province[0]
	}
	if len(s.Cert.Subject.Locality) > 0 {
		s.Locality = s.Cert.Subject.Locality[0]
	}
	// s.Organization = s.Cert.Subject.Organization
	// s.Country = s.Cert.Subject.Country
	// s.Province = s.Cert.Subject.Province
	// s.Locality = s.Cert.Subject.Locality
	s.IPAddresses = s.Cert.IPAddresses
	s.DNSNames = s.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(s.PEMcert, s.PEMprivate)
	if err != nil {
		return err
	}
	s.TLSCert = &tlscert
	//TODO: load other certificate paramters into the structure, like organization, notbefore, etc...
	return nil
}

func SignServerCSR(csrfilePEM string, TargetFolder string, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(csrfilePEM); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return nil, fmt.Errorf(fmt.Sprintf("cannot find: %s", csrfilePEM))

	}
	var ListOfFilesCreated []string
	csrbytes, err := ioutil.ReadFile(csrfilePEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrbytes)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 10
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	signedCertFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".cert")
	if _, err := os.Stat(signedCertFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	ioutil.WriteFile(signedCertFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, signedCertFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}

	return ListOfFilesCreated, nil
}

func SignServerCSRPEM(csrPEM []byte, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]byte, error) {

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 10
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

/*

Client Certificate

*/
//ClientCert Structure, Default NotAfter Years is 5
type ClientCert struct {
	CommonName   string
	Organization string
	Country      string
	Province     string
	Locality     string
	// DNSNames              []string
	// IPAddresses           []net.IP
	NotAfterNumberOfYears uint8
	Cert                  *x509.Certificate
	TLSCert               *tls.Certificate
	PrivateKey            *rsa.PrivateKey
	PublicKey             *rsa.PublicKey
	PEMcert               []byte
	PEMpublic             []byte
	PEMprivate            []byte
}

func (c *ClientCert) CreateAndSignNewClientCert(TargetFolder string, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(path.Join(TargetFolder, c.CommonName+".cert")); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	if c.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	// if s.Organization == "" {
	// 	return errors.New("Organization Cannot be empty")
	// }
	rootNames := cacert.Subject
	if c.Organization == "" {
		c.Organization = rootNames.Organization[0]
	}
	if c.Country == "" {
		c.Country = "QA"
	}
	if c.Province == "" {
		c.Province = "DOHA"
	}
	if c.Locality == "" {
		c.Locality = "DOHA"
	}

	notebefore := time.Now()
	if c.NotAfterNumberOfYears == 0 {
		c.NotAfterNumberOfYears = 5
	}
	notafter := time.Now().AddDate(int(c.NotAfterNumberOfYears), 0, 0)
	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			CommonName:   c.CommonName,
			Organization: []string{c.Organization},
			Country:      []string{c.Country},
			Province:     []string{c.Province},
			Locality:     []string{c.Locality},
		},
		// DNSNames:           c.DNSNames,
		// IPAddresses:        c.IPAddresses,
		NotBefore: notebefore,
		NotAfter:  notafter,
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &certPrivKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".cert")
	certPublicFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".pub.key")
	certPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".key")
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&certPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPublicFileName, certPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPublicFileName)
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPrivateKeyFileName, certPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPrivateKeyFileName)
	certparsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	c.Cert = certparsed
	c.PrivateKey = certPrivKey
	c.PublicKey = &certPrivKey.PublicKey
	c.PEMcert = certPEM.Bytes()
	c.PEMpublic = certPublicKeyPEM.Bytes()
	c.PEMprivate = certPrivKeyPEM.Bytes()
	// TLS
	tlscert, err := tls.X509KeyPair(c.PEMcert, c.PEMprivate)
	if err != nil {
		return nil, err
	}
	c.TLSCert = &tlscert
	return ListOfFilesCreated, nil
}

func (c *ClientCert) CreateClientSignRequest(TargetFolder string) ([]string, error) {

	if c.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	if c.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}

	CSRFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".csr")
	if _, err := os.Stat(CSRFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Request Exists, delete it yourself")
	}
	csrPublicFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".pub.key")
	csrPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(c.CommonName, "\n\r .?!@#$%^")+".key")
	// Cryptographically secure.
	var ListOfFilesCreated []string
	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   c.CommonName,
			Organization: []string{c.Organization},
			Country:      []string{c.Country},
			Province:     []string{c.Province},
			Locality:     []string{c.Locality},
		},
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		// DNSNames:           s.DNSNames,
		// IPAddresses:        s.IPAddresses,
	}

	// create our private and public key
	csrPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	CSRBytes, err := x509.CreateCertificateRequest(rand.Reader, csrReq, csrPrivKey)
	if err != nil {
		return nil, err
	}
	c.PrivateKey = csrPrivKey
	c.PublicKey = &csrPrivKey.PublicKey
	// pem encode
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: CSRBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(CSRFileName, csrPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, CSRFileName)
	csrPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&csrPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPublicFileName, csrPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPublicFileName)
	csrPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPrivateKeyFileName, csrPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPrivateKeyFileName)
	c.PEMcert = csrPEM.Bytes()
	c.PEMpublic = csrPublicKeyPEM.Bytes()
	c.PEMprivate = csrPrivKeyPEM.Bytes()
	return ListOfFilesCreated, nil
}
func (c *ClientCert) LoadClientCertFromFiles(certPEMFile string, certPrivateKeyPEMFile string) error {
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPEMFile))

	}
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPrivateKeyPEMFile))
	}
	certbytes, err := ioutil.ReadFile(certPEMFile)
	if err != nil {
		return err
	}
	c.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	c.Cert = cert
	c.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(c.PublicKey),
	})
	if err != nil {
		return err
	}
	c.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes, err := ioutil.ReadFile(certPrivateKeyPEMFile)
	if err != nil {
		return err
	}
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	c.PEMprivate = privateBytes
	c.PrivateKey = private

	c.CommonName = c.Cert.Subject.CommonName
	if len(c.Cert.Subject.Organization) > 0 {
		c.Organization = c.Cert.Subject.Organization[0]
	}
	if len(c.Cert.Subject.Country) > 0 {
		c.Country = c.Cert.Subject.Country[0]
	}
	if len(c.Cert.Subject.Province) > 0 {
		c.Province = c.Cert.Subject.Province[0]
	}
	if len(c.Cert.Subject.Locality) > 0 {
		c.Locality = c.Cert.Subject.Locality[0]
	}
	// c.IPAddresses = c.Cert.IPAddresses
	// c.DNSNames = c.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(c.PEMcert, c.PEMprivate)
	if err != nil {
		return err
	}
	c.TLSCert = &tlscert
	return nil
}

func (c *ClientCert) LoadClientCertFromPEM(certPEM string, certPrivateKeyPEM string) error {

	certbytes := []byte(certPEM)
	c.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	c.Cert = cert
	c.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(c.PublicKey),
	})
	if err != nil {
		return err
	}
	c.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes := []byte(certPrivateKeyPEM)
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	c.PEMprivate = privateBytes
	c.PrivateKey = private

	c.CommonName = c.Cert.Subject.CommonName
	if len(c.Cert.Subject.Organization) > 0 {
		c.Organization = c.Cert.Subject.Organization[0]
	}
	if len(c.Cert.Subject.Country) > 0 {
		c.Country = c.Cert.Subject.Country[0]
	}
	if len(c.Cert.Subject.Province) > 0 {
		c.Province = c.Cert.Subject.Province[0]
	}
	if len(c.Cert.Subject.Locality) > 0 {
		c.Locality = c.Cert.Subject.Locality[0]
	}
	// c.IPAddresses = c.Cert.IPAddresses
	// c.DNSNames = c.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(c.PEMcert, c.PEMprivate)
	if err != nil {
		return err
	}
	c.TLSCert = &tlscert
	return nil
}

func SignClientCSR(csrfilePEM string, TargetFolder string, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {

	if _, err := os.Stat(csrfilePEM); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return nil, fmt.Errorf(fmt.Sprintf("cannot find: %s", csrfilePEM))

	}

	csrbytes, err := ioutil.ReadFile(csrfilePEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrbytes)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 5
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject:      csr.Subject,
		// DNSNames:           csr.DNSNames,
		// IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	signedCertFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".cert")
	if _, err := os.Stat(signedCertFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	ioutil.WriteFile(signedCertFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, signedCertFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}
	return ListOfFilesCreated, nil
}

func SignClientCSRPEM(csrPEM []byte, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]byte, error) {

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 5
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject:      csr.Subject,
		// DNSNames:           csr.DNSNames,
		// IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

/*

Peer Certificate: Peer has both server auth and client auth extkeyusage

*/
//PeerCert Structure, Default NotAfter Years is 10
type PeerCert struct {
	CommonName            string
	Organization          string
	Country               string
	Province              string
	Locality              string
	DNSNames              []string
	IPAddresses           []net.IP
	NotAfterNumberOfYears uint8
	Cert                  *x509.Certificate
	TLSCert               *tls.Certificate
	PrivateKey            *rsa.PrivateKey
	PublicKey             *rsa.PublicKey
	PEMcert               []byte
	PEMpublic             []byte
	PEMprivate            []byte
}

func (p *PeerCert) CreateAndSignNewPeerCert(TargetFolder string, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(path.Join(TargetFolder, p.CommonName+".cert")); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	if p.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	// if s.Organization == "" {
	// 	return errors.New("Organization Cannot be empty")
	// }
	rootNames := cacert.Subject
	if p.Organization == "" {
		p.Organization = rootNames.Organization[0]
	}
	if p.Country == "" {
		p.Country = "QA"
	}
	if p.Province == "" {
		p.Province = "DOHA"
	}
	if p.Locality == "" {
		p.Locality = "DOHA"
	}

	notebefore := time.Now()
	if p.NotAfterNumberOfYears == 0 {
		p.NotAfterNumberOfYears = 10
	}
	notafter := time.Now().AddDate(int(p.NotAfterNumberOfYears), 0, 0)
	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	cert := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			CommonName:   p.CommonName,
			Organization: []string{p.Organization},
			Country:      []string{p.Country},
			Province:     []string{p.Province},
			Locality:     []string{p.Locality},
		},
		DNSNames:    p.DNSNames,
		IPAddresses: p.IPAddresses,
		NotBefore:   notebefore,
		NotAfter:    notafter,
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &certPrivKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".cert")
	certPublicFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".pub.key")
	certPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".key")
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&certPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPublicFileName, certPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPublicFileName)
	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(certPrivateKeyFileName, certPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, certPrivateKeyFileName)
	certparsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	p.Cert = certparsed
	p.PrivateKey = certPrivKey
	p.PublicKey = &certPrivKey.PublicKey
	p.PEMcert = certPEM.Bytes()
	p.PEMpublic = certPublicKeyPEM.Bytes()
	p.PEMprivate = certPrivKeyPEM.Bytes()
	// TLS
	tlscert, err := tls.X509KeyPair(p.PEMcert, p.PEMprivate)
	if err != nil {
		return nil, err
	}
	p.TLSCert = &tlscert
	return ListOfFilesCreated, nil
}

func (p *PeerCert) CreatePeerSignRequest(TargetFolder string) ([]string, error) {

	if p.CommonName == "" {
		return nil, errors.New("CommonName Cannot be empty")
	}
	if p.Organization == "" {
		return nil, errors.New("Organization Cannot be empty")
	}

	err := os.MkdirAll(TargetFolder, os.ModePerm)
	if err != nil {
		return nil, err
	}

	CSRFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".csr")
	if _, err := os.Stat(CSRFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Request Exists, delete it yourself")
	}
	csrPublicFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".pub.key")
	csrPrivateKeyFileName := path.Join(TargetFolder, strings.Trim(p.CommonName, "\n\r .?!@#$%^")+".key")
	// Cryptographically secure.
	var ListOfFilesCreated []string
	csrReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   p.CommonName,
			Organization: []string{p.Organization},
			Country:      []string{p.Country},
			Province:     []string{p.Province},
			Locality:     []string{p.Locality},
		},
		// SignatureAlgorithm: x509.SHA512WithRSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           p.DNSNames,
		IPAddresses:        p.IPAddresses,
	}

	// create our private and public key
	csrPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// create the CA
	CSRBytes, err := x509.CreateCertificateRequest(rand.Reader, csrReq, csrPrivKey)
	if err != nil {
		return nil, err
	}
	p.PrivateKey = csrPrivKey
	p.PublicKey = &csrPrivKey.PublicKey
	// pem encode
	csrPEM := new(bytes.Buffer)
	err = pem.Encode(csrPEM, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: CSRBytes,
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(CSRFileName, csrPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, CSRFileName)
	csrPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&csrPrivKey.PublicKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPublicFileName, csrPublicKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPublicFileName)
	csrPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(csrPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrPrivKey),
	})
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile(csrPrivateKeyFileName, csrPrivKeyPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, csrPrivateKeyFileName)
	p.PEMcert = csrPEM.Bytes()
	p.PEMpublic = csrPublicKeyPEM.Bytes()
	p.PEMprivate = csrPrivKeyPEM.Bytes()
	return ListOfFilesCreated, nil
}

func (p *PeerCert) LoadPeerCertFromFiles(certPEMFile string, certPrivateKeyPEMFile string) error {
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPEMFile))

	}
	if _, err := os.Stat(certPEMFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return fmt.Errorf(fmt.Sprintf("cannot find: %s", certPrivateKeyPEMFile))
	}
	certbytes, err := ioutil.ReadFile(certPEMFile)
	if err != nil {
		return err
	}
	p.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	p.Cert = cert
	p.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(p.PublicKey),
	})
	if err != nil {
		return err
	}
	p.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes, err := ioutil.ReadFile(certPrivateKeyPEMFile)
	if err != nil {
		return err
	}
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	p.PEMprivate = privateBytes
	p.PrivateKey = private

	p.CommonName = p.Cert.Subject.CommonName
	if len(p.Cert.Subject.Organization) > 0 {
		p.Organization = p.Cert.Subject.Organization[0]
	}
	if len(p.Cert.Subject.Country) > 0 {
		p.Country = p.Cert.Subject.Country[0]
	}
	if len(p.Cert.Subject.Province) > 0 {
		p.Province = p.Cert.Subject.Province[0]
	}
	if len(p.Cert.Subject.Locality) > 0 {
		p.Locality = p.Cert.Subject.Locality[0]
	}
	p.IPAddresses = p.Cert.IPAddresses
	p.DNSNames = p.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(p.PEMcert, p.PEMprivate)
	if err != nil {
		return err
	}
	p.TLSCert = &tlscert
	return nil
}

func (p *PeerCert) LoadPeerCertFromPEM(certPEM string, certPrivateKeyPEM string) error {

	certbytes := []byte(certPEM)
	p.PEMcert = certbytes
	// var pubkey *rsa.PublicKey
	block, _ := pem.Decode(certbytes)
	if block == nil {
		return errors.New("PEM Decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	p.Cert = cert
	p.PublicKey = cert.PublicKey.(*rsa.PublicKey)
	certPublicKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPublicKeyPEM, &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(p.PublicKey),
	})
	if err != nil {
		return err
	}
	p.PEMpublic = certPublicKeyPEM.Bytes()

	privateBytes := []byte(certPrivateKeyPEM)
	blockpriv, _ := pem.Decode(privateBytes)
	private, err := x509.ParsePKCS1PrivateKey(blockpriv.Bytes)
	if err != nil {
		return err
	}
	p.PEMprivate = privateBytes
	p.PrivateKey = private

	p.CommonName = p.Cert.Subject.CommonName
	if len(p.Cert.Subject.Organization) > 0 {
		p.Organization = p.Cert.Subject.Organization[0]
	}
	if len(p.Cert.Subject.Country) > 0 {
		p.Country = p.Cert.Subject.Country[0]
	}
	if len(p.Cert.Subject.Province) > 0 {
		p.Province = p.Cert.Subject.Province[0]
	}
	if len(p.Cert.Subject.Locality) > 0 {
		p.Locality = p.Cert.Subject.Locality[0]
	}
	p.IPAddresses = p.Cert.IPAddresses
	p.DNSNames = p.Cert.DNSNames
	// TLS
	tlscert, err := tls.X509KeyPair(p.PEMcert, p.PEMprivate)
	if err != nil {
		return err
	}
	p.TLSCert = &tlscert
	return nil
}
func SignPeerCSR(csrfilePEM string, TargetFolder string, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]string, error) {
	if _, err := os.Stat(csrfilePEM); os.IsNotExist(err) {
		// path/to/whatever does not exist
		return nil, fmt.Errorf(fmt.Sprintf("cannot find: %s", csrfilePEM))

	}

	csrbytes, err := ioutil.ReadFile(csrfilePEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrbytes)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 5
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	var ListOfFilesCreated []string
	cert := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}
	signedCertFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".cert")
	if _, err := os.Stat(signedCertFileName); !os.IsNotExist(err) {
		// path/to/whatever exists
		return nil, errors.New("Target Certificate Exists, delete it yourself")
	}
	ioutil.WriteFile(signedCertFileName, certPEM.Bytes(), os.ModePerm)
	if err != nil {
		return nil, err
	}
	ListOfFilesCreated = append(ListOfFilesCreated, signedCertFileName)
	//creating bundled version in case ca is not root ca
	//we can check if supplied ca is root or intermediate, if its intermediate, we have to create bundled version of the certificate
	CreateBundledVersion := true
	if cacert.Issuer.String() == cacert.Subject.String() { //if true, it means this CA is Root
		CreateBundledVersion = false
	}
	if CreateBundledVersion {
		certBundleFileName := path.Join(TargetFolder, strings.Trim(cert.Subject.CommonName, "\n\r .?!@#$%^")+".bundle.cert")
		caBytes := cacert.Raw
		caPEM := new(bytes.Buffer)
		err = pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caBytes,
		})
		if err != nil {
			return nil, err
		}
		byteBundle := make([]byte, len(certPEM.Bytes())+len(caPEM.Bytes()))
		copy(byteBundle, certPEM.Bytes()[:])
		copy(byteBundle[len(certPEM.Bytes()):], caPEM.Bytes()[:])
		ioutil.WriteFile(certBundleFileName, byteBundle, os.ModePerm)
		if err != nil {
			return nil, err
		}
		ListOfFilesCreated = append(ListOfFilesCreated, certBundleFileName)
	}
	return ListOfFilesCreated, nil
}

func SignPeerCSRPEM(csrPEM []byte, NotAfterNumberOfYears uint8, cacert *x509.Certificate, caprivateKey *rsa.PrivateKey) ([]byte, error) {

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("PEM Decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	notebefore := time.Now()
	if NotAfterNumberOfYears == 0 {
		NotAfterNumberOfYears = 5
	}
	notafter := time.Now().AddDate(int(NotAfterNumberOfYears), 0, 0)
	// Cryptographically secure.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{
		SerialNumber:       n,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		NotBefore:          notebefore,
		NotAfter:           notafter,
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		// SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cacert, &caprivateKey.PublicKey, caprivateKey)
	if err != nil {
		return nil, err
	}
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

/*
//Testing
func createInitialCertificates() {
	mainfolder := "certs"
	rootfolder := path.Join(mainfolder, "root")
	intermediatefolder := path.Join(mainfolder, "intermediate")
	serverfolder := path.Join(mainfolder, "server")
	clientsfolder := path.Join(mainfolder, "clients")
	root := certtools.RootCA{
		CommonName:   "Khalefa RootCA",
		Organization: "Khalefa Company",
	}
	_, err := root.CreateNewRootCA(rootfolder)
	if err != nil {
		panic(err)
	}
	intermediate := certtools.IntermediateCert{
		CommonName:   "Khalefa IntermediateCA",
		Organization: "Khalefa Company",
	}
	_, err = intermediate.CreateNewSignedIntermediateCA(intermediatefolder, root.CACert, root.CAPrivate)
	if err != nil {
		panic(err)
	}
	// intermediate.LoadIntermediateCAFromFiles("certs/intermediate/intermediate.cert", "certs/intermediate/intermediate.key")
	server := certtools.ServerCert{
		CommonName:   "ptt.do7a.io",
		Organization: "Ptt Qatar",
		Country:      "QA",
		Province:     "DOHA",
		DNSNames:     []string{"web.do7a.io"},
		IPAddresses:  []net.IP{net.IP{127, 0, 0, 1}, net.IPv6loopback},
	}
	_, err = server.CreateAndSignNewServerCert(serverfolder, intermediate.CACert, intermediate.CAPrivate)
	if err != nil {
		panic(err)
	}
	//lets create some clients
	client1 := certtools.ClientCert{
		CommonName: "Client1",
	}
	client2 := certtools.ClientCert{
		CommonName: "Client2",
	}
	client3 := certtools.ClientCert{
		CommonName: "Client3",
	}
	client4 := certtools.ClientCert{
		CommonName: "Client4",
	}
	_, err = client1.CreateAndSignNewClientCert(clientsfolder, intermediate.CACert, intermediate.CAPrivate)
	if err != nil {
		panic(err)
	}
	_, err = client2.CreateAndSignNewClientCert(clientsfolder, intermediate.CACert, intermediate.CAPrivate)
	if err != nil {
		panic(err)
	}
	_, err = client3.CreateAndSignNewClientCert(clientsfolder, intermediate.CACert, intermediate.CAPrivate)
	if err != nil {
		panic(err)
	}
	_, err = client4.CreateAndSignNewClientCert(clientsfolder, intermediate.CACert, intermediate.CAPrivate)
	if err != nil {
		panic(err)
	}
}

*/
