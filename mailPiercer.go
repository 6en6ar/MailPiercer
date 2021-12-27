package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

type ipinfo struct {
	Country string
	City    string
	Isp     string
}

func main() {
	var banner = `
	_______ _______ _____              _____  _____ _______  ______ _______ _______  ______
	|  |  | |_____|   |   |           |_____]   |   |______ |_____/ |       |______ |_____/
	|  |  | |     | __|__ |_____      |       __|__ |______ |    \_ |_____  |______ |    \_
																						   `

	color.HiRed(banner)
	fmt.Println()
	fmt.Println()
	var spf, dkim, dmarc = false, false, false
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	msg, _ := mail.ReadMessage(file)
	defer file.Close()
	re := regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	re2 := regexp.MustCompile(`does not designate`)
	spfre := regexp.MustCompile(`spf=pass`)
	dkimre := regexp.MustCompile(`dkim=pass`)
	dmarcre := regexp.MustCompile(`dmarc=pass`)
	var ip []string
	var spoofed = false
	for i, _ := range msg.Header {
		if strings.EqualFold(msg.Header.Get(i), strings.ToLower(msg.Header.Get("authentication-results"))) {
			match := re.FindAllString(msg.Header.Get(i), -1)
			ip = match
			if re2.FindAllString(msg.Header.Get(i), -1) != nil {
				spoofed = true
			}
			if spfre.FindAllString(msg.Header.Get(i), -1) != nil {
				spf = true
			}
			if dkimre.FindAllString(msg.Header.Get(i), -1) != nil {
				dkim = true
			}
			if dmarcre.FindAllString(msg.Header.Get(i), -1) != nil {
				dmarc = true
			}
		}
	}
	color.HiRed("######## MAIL HEADERS ########\n\n")
	color.HiGreen("From: %v\n", msg.Header.Get("From"))
	color.HiGreen("To: %v\n", msg.Header.Get("To"))
	color.HiGreen("Subject: %v\n", msg.Header.Get("Subject"))
	color.HiGreen("Date: %v\n", msg.Header.Get("Date"))
	if !spf {
		color.Red("[ - ] SPF record: NOT FOUND")
	} else {
		color.HiGreen("[ + ] SPF record: PASS")
	}
	if !dkim {
		color.Red("[ - ] DKIM: FAIL")
	} else {
		color.HiGreen("[ + ] DKIM: PASS")
	}
	if !dmarc {
		color.Red("[ - ] DMARC record: NOT FOUND")
	} else {
		color.HiGreen("[ + ] DMARC record: PASS")
	}
	if spoofed && !spf && !dkim && !dmarc {
		color.Red("[ - ] Mail was spoofed\n\n")
	} else {
		color.HiCyan("[ + ] Mail doesn't look like it was spoofed\n\n")
	}
	color.HiRed("######## IP INFORMATION ########\n\n")
	color.HiYellow("Sender IP: %v\n", ip[0])
	var url = "http://ip-api.com/json/" + string(ip[0]) //+ "?" + "fields=country,city,isp"
	client := http.Client{}
	req1, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error %s", err)
		return
	}
	defer req1.Body.Close()
	co, _ := ioutil.ReadAll(req1.Body)
	var info ipinfo
	json.Unmarshal([]byte(co), &info)
	color.HiYellow("[ + ] Country : %s \n[ + ] City : %s \n[ + ] ISP : %s", info.Country, info.City, info.Isp)
}
