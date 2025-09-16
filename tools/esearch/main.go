package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	esURL := "http://localhost:9200" 

	resp, err := http.Get(esURL)
	if err != nil {
		fmt.Println("Elasticsearch is not on", esURL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Println("Elasticsearch accesible but send code:", resp.StatusCode)
		return
	}

	fmt.Println("Elasticsearch is not on", esURL)
	indicesResp, err := http.Get(esURL + "/_cat/indices?format=json")
	if err != nil {
		fmt.Println("err with get index:", err)
		return
	}
	defer indicesResp.Body.Close()

	body, _ := ioutil.ReadAll(indicesResp.Body)

	var indices []map[string]interface{}
	if err := json.Unmarshal(body, &indices); err != nil {
		fmt.Println("err witch json decode:", err)
		return
	}

	fmt.Println("index:")
	for _, idx := range indices {
		if name, ok := idx["index"]; ok {
			fmt.Println("-", name)
		}
	}
}
