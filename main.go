package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"hash/fnv"
	"os"
	"strconv"
	"time"
)

type SecretResponse struct {
	hash           string
	secretText     string
	createdAt      time.Time
	expiresAt      time.Time
	remainingViews int
}

type SecretForm struct {
	secret           string `form:"secret" binding:"required"`
	expireAfterViews int    `form:"expireAfterViews" binding:"required"`
	expireAfter      int    `form:"expireAfter" binding:"required"`
}

func main() {
	port := os.Getenv("PORT")
	secretLocal := make(map[string]map[string]interface{})

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*",
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return origin == "https://github.com"
		},
		MaxAge: 12 * time.Hour,
	}))

	v1 := router.Group("/v1")
	{
		v1.GET("/secret/:hash", func(c *gin.Context) {
			hash := c.Param("hash")
			if secretLocal[hash] == nil {
				c.JSON(404, gin.H{
					"message": "Not found",
				})
				return
			} else {
				secret := secretLocal[hash]

				if secret["remainingViews"] == 0 {
					c.JSON(404, gin.H{
						"message": "Not found (No remaining views)",
					})
					return
				} else if secret["expiresAfter"] != 0 && time.Now().After(secret["createdAt"].(time.Time).Add(time.Duration(secret["expiresAfter"].(int))*time.Minute)) {
					c.JSON(404, gin.H{
						"message": "Not found (Expired)",
					})
					return
				} else {
					secret["remainingViews"] = secret["remainingViews"].(int) - 1
				}

				secretObject := make(map[string]interface{})
				secretObject["hash"] = secret["hash"]
				secretObject["secretText"] = secret["secretText"]
				secretObject["createdAt"] = secret["createdAt"]
				secretObject["expiresAt"] = secret["createdAt"].(time.Time).Add(time.Duration(secret["expiresAfter"].(int)) * time.Minute)
				secretObject["remainingViews"] = secret["remainingViews"]
				c.JSON(200, secretObject)
			}
		})

		v1.POST("/secret", func(c *gin.Context) {
			var secretForm SecretForm

			var secret string
			var expireAfterViews int
			var expireAfter int

			if c.ShouldBind(&secretForm) == nil {
				secret = c.PostForm("secret")
				if expireAfterViews_, err := strconv.Atoi(c.PostForm("expireAfterViews")); err == nil {
					expireAfterViews = expireAfterViews_
				} else {
					c.JSON(405, gin.H{"error": "invalid expireAfterViews"})
					return
				}
				if expireAfter_, err := strconv.Atoi(c.PostForm("expireAfter")); err == nil {
					expireAfter = expireAfter_
				} else {
					c.JSON(405, gin.H{"error": "invalid expireAfter"})
					return
				}
			} else {
				c.JSON(405, gin.H{
					"error": "bad request",
				})
				return
			}

			if expireAfterViews <= 0 {
				if c.Request.Header.Get("Content-Type") == "application/json" {
					c.JSON(405, gin.H{"error": "expireAfterViews must be greater than 0"})
				} else if c.Request.Header.Get("Content-Type") == "application/xml" {
					c.XML(405, gin.H{"error": "expireAfterViews must be greater than 0"})
				} else {
					c.String(405, "expireAfterViews must be greater than "+string(expireAfter)+" "+string(expireAfterViews)+" "+string(secret))
				}
				return
			}

			//generate hash function
			hash := fnv.New32a()
			hash.Write([]byte(secret))
			hashInt := hash.Sum32()
			hashString := strconv.Itoa(int(hashInt))

			secretMap := make(map[string]interface{})

			secretMap["hash"] = hashString
			secretMap["secretText"] = secret
			secretMap["createdAt"] = time.Now()
			secretMap["neverExpires"] = expireAfterViews == 0
			secretMap["remainingViews"] = expireAfterViews
			secretMap["expiresAfter"] = expireAfter

			secretObject := make(map[string]interface{})
			secretObject["hash"] = hashString
			secretObject["secretText"] = secret
			secretObject["createdAt"] = secretMap["createdAt"]
			secretObject["expiresAt"] = time.Now().Add(time.Duration(expireAfter) * time.Minute)
			secretObject["remainingViews"] = expireAfterViews

			secretLocal[hashString] = secretMap
			if c.Request.Header.Get("Accept") == "application/xml" {
				c.XML(200, secretObject)
			} else {
				c.JSON(200, secretObject)
			}
		})
	}

	router.Run(":" + port)
}
