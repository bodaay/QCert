package certtools

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func StartWebCertTool(address string) {
	e := echo.New()
	configureWebServer(e)
	configureAllRoutes(e)
	e.Start(address)
}
func configureWebServer(e *echo.Echo) {
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit("100M"))
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		// AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))
	// mime.AddExtensionType(".js", "application/javascript") //This will solve some windows shit issue, when it will serve javascript file as text/plain, read more about it at:https://github.com/labstack/echo/issues/1038

}

func configureAllRoutes(e *echo.Echo) {
	rootCreateNewCertificateRoute(e)
}

//Root Routes
type rootCARequest struct {
	CommonName            string `json:"CommonName"`
	Organization          string `json:"Organization"`
	NotAfterNumberOfYears uint8  `json:"NotAfterNumberOfYears"`
}

func rootCreateNewCertificateRoute(e *echo.Echo) {
	e.POST("/root/new", func(c echo.Context) error {
		r := new(rootCARequest)
		if err := c.Bind(r); err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		if r.CommonName == "" {
			return c.String(http.StatusBadRequest, "CommonName Cannot be empty")
		}
		if r.Organization == "" {
			return c.String(http.StatusBadRequest, "Organization Cannot be empty")
		}
		rr := RootCA{
			CommonName:            r.CommonName,
			Organization:          r.Organization,
			NotAfterNumberOfYears: r.NotAfterNumberOfYears,
		}
		tmepFolderName := path.Join("Out", "rootca")
		os.Remove(tmepFolderName)
		os.MkdirAll(tmepFolderName, os.ModePerm)
		err := rr.CreateNewRootCA(tmepFolderName)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		zipfile := path.Join(tmepFolderName, "rootca.zip")
		os.Remove(zipfile)
		flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		file, err := os.OpenFile(zipfile, flags, 0644)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		defer file.Close()
		certFile := path.Join(tmepFolderName, "rootca.cert")
		certPriv := path.Join(tmepFolderName, "rootca.key")
		certPub := path.Join(tmepFolderName, "rootca.pub.key")
		var files = []string{certFile, certPriv, certPub}

		zipw := zip.NewWriter(file)
		defer zipw.Close()

		for _, filename := range files {
			if err := appendFiles(filename, zipw); err != nil {
				return c.String(http.StatusBadRequest, err.Error())
			}
		}
		zipw.Close()
		os.Remove(certFile)
		os.Remove(certPriv)
		os.Remove(certPub)
		return c.Attachment(zipfile, "rootca.zip")
	})
}

// //Intermediate
// func intermediateCreateNewSignedCertificateRoute(e *echo.Echo) {
// 	e.POST("/int/new", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func intermediateGetCSRRoute(e *echo.Echo) {
// 	e.POST("/int/csr", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func intermediateSignCSRRoute(e *echo.Echo) {
// 	e.POST("/int/sign", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }

// //Server
// func serverCreateNewSignedCertificateRoute(e *echo.Echo) {
// 	e.POST("/server/new", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func serverGetCSRRoute(e *echo.Echo) {
// 	e.POST("/server/csr", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func serverSignCSRRoute(e *echo.Echo) {
// 	e.POST("/server/sign", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }

// //Client
// func clientCreateNewSignedCertificateRoute(e *echo.Echo) {
// 	e.POST("/client/new", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func clientGetCSRRoute(e *echo.Echo) {
// 	e.POST("/client/csr", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func clientSignCSRRoute(e *echo.Echo) {
// 	e.POST("/client/sign", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }

// //Peer
// func peerCreateNewSignedCertificateRoute(e *echo.Echo) {
// 	e.POST("/client/new", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func peerGetCSRRoute(e *echo.Echo) {
// 	e.POST("/client/csr", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }
// func peerSignCSRRoute(e *echo.Echo) {
// 	e.POST("/client/sign", func(c echo.Context) error {

// 		return c.JSONPretty(http.StatusOK, clientList, " ")
// 	})
// }

//from: https://www.golangprograms.com/go-program-to-compress-list-of-files-into-zip.html
func appendFiles(filename string, zipw *zip.Writer) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %s", filename, err)
	}
	defer file.Close()

	wr, err := zipw.Create(filename)
	if err != nil {
		msg := "Failed to create entry for %s in zip file: %s"
		return fmt.Errorf(msg, filename, err)
	}

	if _, err := io.Copy(wr, file); err != nil {
		return fmt.Errorf("Failed to write %s to zip: %s", filename, err)
	}

	return nil
}
