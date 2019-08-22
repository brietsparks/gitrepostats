package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	isHttps := os.Getenv("IS_SSL") == "true"
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	port := os.Getenv("PORT")

	loginUrl := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?scope=user:email&client_id=%s",
		clientID,
	)

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		Scopes: []string{
			// scopes match v4 explorer: https://developer.github.com/v4/guides/forming-calls
			"user", "email", "public_repo", "repo", "repo_deployment", "repo:status",
			"read:repo_work", "read:org", "read:public_key", "read:gpg_key",
		},
	}

	r := gin.Default()

	r.GET("/app", func(c *gin.Context) {
		_, err := extractToken(c)

		if err != nil {
			c.Redirect(http.StatusFound, loginUrl)
			c.Abort()
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	r.GET("/auth-callback", func(c *gin.Context) {
		code := c.Request.URL.Query().Get("code")

		if code == "" {
			message := "authorization code missing"
			log.Println(message)
			c.JSON(http.StatusBadRequest, gin.H{"message": message})
			return
		}

		token, err := conf.Exchange(c, code)
		if err != nil {
			message := "unable to get token from github oauth server"
			log.Println(fmt.Sprintf("%s: %s", message, err))
			c.JSON(http.StatusInternalServerError, gin.H{"message": message})
			return
		}

		tokenStr, err := tokenToJSON(token)
		if err != nil {
			message := "unable store token in cookie"
			log.Println(fmt.Sprintf("%s: %s", message, err))
			c.JSON(http.StatusInternalServerError, gin.H{"message": message})
			return
		}

		c.SetCookie("token", tokenStr, 60*60*7, "/", "localhost", isHttps, true)

		c.Redirect(http.StatusFound, "/app")
	})

	api := r.Group("/api")
	api.Use(apiAuthGuard)

	api.GET("/check-token", func(c *gin.Context) {
		_, err := extractToken(c)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "bad token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	api.GET("repos/:owner/:name", func(c *gin.Context) {
		token, _ := extractToken(c)

		src := oauth2.StaticTokenSource(token)
		httpClient := oauth2.NewClient(c, src)
		client := githubv4.NewClient(httpClient)

		owner := c.Param("owner")
		name := c.Param("name")

		var query struct {
			Repository struct {
				Name             string
				CreatedAt        time.Time
				Forks            struct{ TotalCount int32 }
				Stargazers       struct{ TotalCount int32 }
				Watchers         struct{ TotalCount int32 }
				AssignableUsers  struct{ TotalCount int32 }
				Issues           struct{ TotalCount int32 }
				OpenIssues       struct{ TotalCount int32 } `graphql:"openIssues: issues(states: OPEN)"`
				PullRequests     struct{ TotalCount int32 }
				OpenPullRequests struct{ TotalCount int32 } `graphql:"openPullRequests: pullRequests(states: OPEN)"`
				PushedAt         time.Time
			} `graphql:"repository(owner: $owner, name: $name)"`
		}

		variables := map[string]interface{}{
			"owner": githubv4.String(owner),
			"name":  githubv4.String(name),
		}

		err := client.Query(c, &query, variables)
		if err != nil {
			log.Println(fmt.Sprintf("error executing query: %s", err))
			c.JSON(400, gin.H{"error": "Query error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": query.Repository})
	})

	if port == "" {
		port = "3000"
	}

	portStr := fmt.Sprintf(":%s", port)

	err = r.Run(portStr)

	if err != nil {
		log.Fatal(fmt.Sprintf("unable to start http server: %s", err))
	}
}

func apiAuthGuard(c *gin.Context) {
	_, err := extractToken(c)

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"message": "Authentication required"})
		return
	}

	c.Next()
}

func extractToken(c *gin.Context) (*oauth2.Token, error) {
	t, err := c.Cookie("token")
	if err != nil {
		return nil, errors.New("token not found")
	}

	token, err := tokenFromJSON(t)
	if err != nil {
		return nil, errors.New("token invalid")
	}

	return token, nil
}

func tokenToJSON(token *oauth2.Token) (string, error) {
	if d, err := json.Marshal(token); err != nil {
		return "", err
	} else {
		return string(d), nil
	}
}

func tokenFromJSON(jsonStr string) (*oauth2.Token, error) {
	var token oauth2.Token
	if err := json.Unmarshal([]byte(jsonStr), &token); err != nil {
		return nil, err
	}
	return &token, nil
}
