// Test-only loopback admin adapter. Copy into cmd/monad-characterization in the
// pinned disposable clone so Go's internal package boundary remains intact.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/lescuer97/nutmix/api/cashu"
	"github.com/lescuer97/nutmix/internal/database/postgresql"
	"github.com/lescuer97/nutmix/internal/mint"
	"github.com/lescuer97/nutmix/internal/routes"
	localsigner "github.com/lescuer97/nutmix/internal/signer/local_signer"
)

func main() {
	ctx := context.Background()
	db, err := postgresql.DatabaseSetup(ctx, "")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	config, notifications, err := mint.SetUpConfigDB(ctx, db)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := localsigner.SetupLocalSigner(db)
	if err != nil {
		log.Fatal(err)
	}
	m, err := mint.SetUpMint(ctx, config, notifications, db, &signer)
	if err != nil {
		log.Fatal(err)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	routes.V1Routes(r, m)
	r.POST("/_test/rotate", func(c *gin.Context) {
		if err := m.Signer.RotateKeyset(cashu.Sat, 0, 0); err != nil {
			c.Status(500)
			return
		}
		c.JSON(200, gin.H{"rotated": true})
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:"+os.Getenv("MONAD_CHARACTERIZATION_PORT"), r))
}
