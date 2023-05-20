package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/cristalhq/acmd"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
)

var concurrentSites = 5
var threads = 5

func RandomString(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func Log(msg string, a ...interface{}) {
	timestamp := time.Now().Format("2006-01-02_15:04:05.000000000")

	fmt.Printf("[navgix "+timestamp+"] "+msg+"\n", a...)
}

func InSlice(slice []string, word string) bool {
	for _, element := range slice {
		if element == word {
			return true
		}
	}
	return false
}

func MakeGET(url string) (string, int, string) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 8 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "Error: " + err.Error(), 9999, ""

	}
	defer resp.Body.Close()

	// read response to string
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	location := resp.Header.Get("Location")

	return string(body), resp.StatusCode, location
}

func MakeGETRetry(url string) (string, int, string) {
	retry := 2
	for i := 0; i < retry; i++ {
		body, status, location := MakeGET(url)
		if status != 9999 {
			return body, status, location
		}
	}
	return "", 9999, ""
}

func CheckFolderForTraversal(url string, folder string) bool {
	_, statusCurrent, locationCurrent := MakeGETRetry(url + folder + ".")

	if statusCurrent == 404 {
		return false
	}

	if statusCurrent == 301 || statusCurrent == 302 {
		if strings.HasSuffix(locationCurrent, folder+"./") {
			_, statusTraversal, locationTraversal := MakeGETRetry(url + folder + "..")
			if statusTraversal == 301 || statusTraversal == 302 {
				if strings.HasSuffix(locationTraversal, folder+"../") {
					respNotFound, statusNotFound, _ := MakeGETRetry(url + folder + "." + RandomString(4))
					if statusNotFound == 404 || strings.Contains(strings.ToLower(respNotFound), "not found") {
						respNotFound2, statusNotFound2, _ := MakeGETRetry(url + folder + "z")
						if statusNotFound2 == 404 || strings.Contains(strings.ToLower(respNotFound2), "not found") {
							// vulnerable

							_, statusNotFound3, _ := MakeGETRetry(url + folder + "z..")
							if statusNotFound3 != 302 && statusNotFound3 != 301 {
								// vulnerable
								Log("Vulnerable: %s", url+folder+"../")
								return true
							}

						}

					}
				}

			}
		}

	}
	return false
}

func CheckFoldersForTraversal(url string, folders []string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threads)

	// Use a bounded semaphore with a capacity of 'threads'
	for i := 0; i < threads; i++ {
		semaphore <- struct{}{}
	}

	for _, word := range folders {
		wg.Add(1)
		// Acquire a token from the semaphore channel
		<-semaphore
		go func(word string) {
			CheckFolderForTraversal(url, word)
			// Release the token back to the semaphore channel
			semaphore <- struct{}{}
			wg.Done()
		}(word)
	}

	wg.Wait()
}
func MakeFolderEndpointsFromPath(path string) []string {
	// remove query string
	// "/img/media/a.jpg" -> ["img", "img/media"]
	var endpoints []string
	var endpoint string

	// check if begins with https:// or http:// or //
	if strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "//") {
		// get path
		u, err := url.Parse(path)
		if err != nil {
			log.Fatal(err)
		}
		path = u.Path
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}

	}

	for _, word := range strings.Split(path, "/") {
		if word != "" {
			// check if last
			if word == strings.Split(path, "/")[len(strings.Split(path, "/"))-1] {
				break
			}
			// remove query string
			if strings.Contains(word, "?") {
				word = strings.Split(word, "?")[0]
			}

			endpoint = endpoint + word + "/"
			endpointNoSlash := strings.TrimSuffix(endpoint, "/")
			if !InSlice(endpoints, endpointNoSlash) {
				endpoints = append(endpoints, endpointNoSlash)
			}

		}

	}
	return endpoints

}

func findEndpoints(url string) []string {
	html, _, _ := MakeGETRetry(url)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		log.Fatal(err)
	}
	var foundEndpoints []string
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			for _, endpoint := range foundEndpoints {
				//check if endpoint already exists
				if endpoint == src {
					return
				}
			}
			foundEndpoints = append(foundEndpoints, src)

		}
	})
	finalDirectoryEndpoints := []string{}
	for _, endpoint := range foundEndpoints {
		directoryEndpoints := MakeFolderEndpointsFromPath(endpoint)
		for _, directoryEndpoint := range directoryEndpoints {
			if !InSlice(finalDirectoryEndpoints, directoryEndpoint) {
				finalDirectoryEndpoints = append(finalDirectoryEndpoints, directoryEndpoint)
			}
		}
	}

	return finalDirectoryEndpoints

}

func CheckTarget(url string) {
	if url[len(url)-1:] != "/" {
		url = url + "/"
	}
	// Check for alias traversal vulnerability (bruteforce)
	var dictionary = []string{
		"static",
		"js",
		"images",
		"img",
		"css",
		"assets",
		"media",
		"lib",
	}
	CheckFoldersForTraversal(url, dictionary)
	// Check for alias traversal vulnerability (endpoint finding)
	CheckFoldersForTraversal(url, findEndpoints(url))
	// Check for directory listing
	// Check for file existence
	// Check for file contents
}

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			os.Exit(1)
		}
	}()

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	cmds := []acmd.Command{
		{
			Name:        "scan",
			Description: "Scans URL(s) for the nginx alias traversal vulnerability",
			ExecFunc: func(ctx context.Context, args []string) error {
				URLInput := ""
				fs := flag.NewFlagSet("navgix scan", flag.ContinueOnError)
				fs.StringVar(&URLInput, "u", "", "Single URL or file containing URLs to scan")
				fs.IntVar(&threads, "t", 10, "Number of threads to use for each site")
				fs.IntVar(&concurrentSites, "c", 20, "Number of concurrent sites to scan")

				if err := fs.Parse(args); err != nil {
					return err
				}

				if len(args) == 0 {
					fs.Usage()
					return nil
				}

				if URLInput == "" {
					fs.Usage()
					fmt.Println("Error: No URL(s) specified")
					return nil
				}

				// check if file
				if _, err := os.Stat(URLInput); err == nil {
					// file exists
					file, err := os.Open(URLInput)
					if err != nil {
						log.Fatal(err)
					}
					defer file.Close()

					scanner := bufio.NewScanner(file)
					targets := []string{}
					for scanner.Scan() {
						targets = append(targets, scanner.Text())
					}

					if err := scanner.Err(); err != nil {
						log.Fatal(err)
					}
					var wg sync.WaitGroup
					semaphore := make(chan struct{}, threads)

					// Use a bounded semaphore with a capacity of 'threads'
					for i := 0; i < threads; i++ {
						semaphore <- struct{}{}
					}
					Log("starting scan on " + strconv.Itoa(len(targets)) + " targets")

					for _, target := range targets {
						wg.Add(1)
						// Acquire a token from the semaphore channel
						<-semaphore
						go func(word string) {
							CheckTarget(word)
							// Release the token back to the semaphore channel
							semaphore <- struct{}{}
							wg.Done()
						}(target)
					}

					wg.Wait()
					pprof.StopCPUProfile()

					return nil
				} else {
					Log("starting scan on " + URLInput)
					CheckTarget(URLInput)
				}

				return nil
			},
		},
	}

	r := acmd.RunnerOf(cmds, acmd.Config{
		AppName:        "navgix",
		AppDescription: "Navgix is a tool for mass scanning URLs for the nginx alias traversal vulnerability.",
		Version:        "0.0.1",
	})

	if err := r.Run(); err != nil {
		r.Exit(err)
	}
}
