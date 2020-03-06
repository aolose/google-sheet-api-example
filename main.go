package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
)

var tokFile string
var ctx context.Context
var px string

// todo copy your clientSecret here
const clientSecret = `{"installed":{"client_id":"-.apps.googleusercontent.com","project_id":"decisive-clover-","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"-","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}`

func getClient(config *oauth2.Config) *http.Client {
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	urlI := url.URL{}
	urlProxy, _ := urlI.Parse(px)
	transport := http.Transport{}
	if strings.HasPrefix(px, "socks") {
		l := strings.Index(px, "://")
		dialSocksProxy, err := proxy.SOCKS5("tcp", px[l+3:], nil, proxy.Direct)
		if err != nil {
			fmt.Println("Error connecting to proxy:", err)
		}
		transport.Dial = dialSocksProxy.Dial
	} else {
		transport.Proxy = http.ProxyURL(urlProxy)
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &transport,
	})
	return config.Client(ctx, tok)
}

func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(token)
}

func CheckIfError(err error) {
	if err == nil {
		return
	}

	fmt.Printf("\x1b[31;1m%s\x1b[0m\n", fmt.Sprintf("error: %s", err))
	os.Exit(1)
}

func Info(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func LatestCommit(cIter object.CommitIter, name string, before *object.Commit) (*object.Commit, *object.Commit) {
	c, err := cIter.Next()
	if err != nil {
		return before, nil
	}
	if c.Author.Name != name {
		return LatestCommit(cIter, name, before)
	} else if before != nil {
		return before, c
	} else {
		return LatestCommit(cIter, name, c)
	}
}

func GetRange(i int) string {
	v := strconv.Itoa(i)
	return "A" + v + ":F" + v
}

func GoogleSheetWrite(a, b, c, d string) {
	config, err := google.ConfigFromJSON([]byte(clientSecret), sheets.SpreadsheetsScope)
	CheckIfError(err)
	client := getClient(config)
	CheckIfError(err)
	srv, err := sheets.NewService(
		ctx,
		option.WithHTTPClient(client),
		option.WithScopes(sheets.SpreadsheetsScope),
	)
	CheckIfError(err)
	spreadsheetId := "your Id aaaaRCcccUX5OvBVAWEA16tgVTowKI2QV0G"
	ss := srv.Spreadsheets.Values
	cells, err := ss.Get(spreadsheetId, "A1:F9999").Do()
	CheckIfError(err)
	if len(cells.Values) == 0 {
		Info("No data found.")
	} else {
		Info("Sheet Found.")
	}
	l := len(cells.Values)
	vr := &sheets.ValueRange{}
	vr.Values = append(vr.Values, []interface{}{b, "git committed", c, 0, a, d})
	r := ss.Append(
		spreadsheetId,
		GetRange(l+1),
		vr,
	)
	_, err = r.ValueInputOption("USER_ENTERED").Do()
	CheckIfError(err)
	Info("%s\n%s\n%s\n%s", a, b, c, d)
}

func ReadGit(path, name string) (string, string, string) {
	r, err := git.PlainOpen(path)
	CheckIfError(err)
	ref, err := r.Head()
	CheckIfError(err)
	cIter, err := r.Log(&git.LogOptions{From: ref.Hash()})
	CheckIfError(err)
	c, cc := LatestCommit(cIter, name, nil)
	t, _ := c.Tree()
	tt, _ := cc.Tree()
	ch, _ := t.Diff(tt)
	a := fmt.Sprintf("Hash:%s; %d files committed.", c.Hash.String()[:8], ch.Len())
	CheckIfError(err)

	return strings.ReplaceAll(c.Message, "\n", ""), c.Author.When.Format("2006-01-02 15:04:05"), a
}
func usage() {
	_, _ = fmt.Fprintf(os.Stderr, `dailyReport version: 1.0.0
Usage: dailyReport [-h help] [-D git_project_dir] [-U userName] [-P Proxy]

Options:
`)
	flag.PrintDefaults()
}
func main() {
	u, _ := user.Current()
	tokFile = u.HomeDir + "/token.json"
	Info("Auto Work report...")
	var pa, usr string
	h := false
	flag.StringVar(&px, "P", "socks://127.0.0.1:8082", "set local http proxy addr")
	flag.StringVar(&pa, "D", "D:/sd", "your git local path")
	flag.StringVar(&usr, "U", "tom", "filter git user name")
	flag.BoolVar(&h, "h", false, "show help")
	flag.Parse()
	if h {
		usage()
	} else {
		a, b, c := ReadGit(pa, usr)
		GoogleSheetWrite(usr, a, b, c)
	}
}
