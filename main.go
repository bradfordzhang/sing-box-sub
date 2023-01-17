package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Node struct {
	Type     string
	Security string
	Pass     string
	Server   string
	Port     int
	Name     string
}

func analysis(node string) Node {
	var nodeInfo Node
	nodeInfo.Type = strings.Split(node, "://")[0]
	node = strings.TrimPrefix(node, nodeInfo.Type+"://")
	Pass, _ := base64.StdEncoding.DecodeString(strings.Split(node, "@")[0])
	if nodeInfo.Type == "ss" {
		tmp := string(Pass[:])
		nodeInfo.Security = strings.Split(tmp, ":")[0]
		nodeInfo.Pass = strings.Split(tmp, ":")[1]
	}
	node = strings.TrimPrefix(node, strings.Split(node, "@")[0]+"@")
	nodeInfo.Server = strings.Split(node, ":")[0]
	node = strings.TrimPrefix(node, nodeInfo.Server+":")
	nodeInfo.Port, _ = strconv.Atoi(strings.Split(node, "#")[0])
	node = strings.TrimPrefix(node, strconv.Itoa(nodeInfo.Port)+"#")
	nodeInfo.Name = node
	return nodeInfo
}

func main() {
	nodeType := make(map[string]string)
	nodeType["socks4"] = "socks"
	nodeType["socks4a"] = "socks"
	nodeType["socks5"] = "socks"
	nodeType["http"] = "http"
	nodeType["ss"] = "shadowsocks"
	nodeType["vmess"] = "vmess"
	nodeType["trojan"] = "trojan"
	nodeType["wireguard"] = "wireguard"
	nodeType["hysteria"] = "hysteria"
	nodeType["ssr"] = "shadowsocksr"
	nodeType["vless"] = "vless"

	var nodeList []string

	var subUrl string
	for k, v := range os.Args {
		if k == 1 {
			subUrl = v
		}
	}
	if subUrl == "" {
		fmt.Println("sub url not found")
	}

	resp, err := http.Get(subUrl)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	plainByte, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		fmt.Println(err)
		return
	}
	plain := strings.Fields(string(plainByte[:]))
	for _, node := range plain {
		node, err := url.PathUnescape(node)
		if err != nil {
			log.Fatal(err)
		}
		nodeInfo := analysis(node)
		outbound := "{\n" +
			"\t\"type\": \"" + nodeType[nodeInfo.Type] + "\",\n" +
			"\t\"tag\": \"" + nodeInfo.Name + "\",\n" +
			"\t\"server\": \"" + nodeInfo.Server + "\",\n" +
			"\t\"server_port\": \"" + strconv.Itoa(nodeInfo.Port) + "\",\n" +
			"\t\"method\": \"" + nodeInfo.Security + "\",\n" +
			"\t\"password\": \"" + nodeInfo.Pass + "\"\n" +
			"},"
		fmt.Println(outbound)
		nodeList = append(nodeList, nodeInfo.Name)
	}
	fmt.Println("{\n" + "\t\"type\": \"direct\"\n" + "\t\"tag\": \"direct\"\n" + "},\n" + "{\n" + "\t\"type\": \"block\"\n" + "\t\"tag\": \"block\"\n" + "}")

	fmt.Println("Node List:")
	for _, nodeName := range nodeList {
		fmt.Printf("\"%s\",\n", nodeName)
	}
}
