package main

import (
	"os"
	"fmt"
	. "csvTodb/util"
	. "csvTodb/def"
	"github.com/astaxie/beego"
	"strings"
	"time"
)

var DIR string
var TABLE string

func main() {
	os.Mkdir("log", os.ModeDir)
	beego.SetLogger("file", `{"filename":"log/recsv2db.log"}`)
	ReCsv2Db()
}

func ReCsv2Db() {
	files := DirTree("./", ".csv", 10000000)
	Debug(files)
	for _, file := range files {
		for _, f := range file {
			path := f.(string)
			fmt.Println(path)
			if strings.HasSuffix(path, ".csv") {
				Debug(path)
				fmt.Println(1)
				if strings.HasPrefix(path, "bandwidth") {
					fmt.Println(2)
					err := Csv2Db(path, "bandwidth")
					time.Sleep(time.Second * 1)
					if err == nil {
						DeleteFile(path)
						Debug("DeleteFile ", path)
					} else {
						Debug(err)
					}
				} else if strings.HasPrefix(path, "flow") {
					err := Csv2Db(path, "flow")
					time.Sleep(time.Second * 1)
					if err == nil {
						DeleteFile(path)
						Debug("DeleteFile ", path)
					} else {
						Debug(err)
					}
				} else if strings.HasPrefix(path, "dispatch") {
					err := Csv2Db(path, "access")
					time.Sleep(time.Second * 1)
					if err == nil {
						DeleteFile(path)
						Debug("DeleteFile ", path)
					} else {
						Debug(err)
					}
				} else {
					Debug(path, "文件入库失败")
				}
			}
		}
	}
}
func Csv2Db(file string, table string) error {
	Debug("Csv2Db", file)
	pg := Postgre{}
	_, e := pg.LoadCsv(file, table, ",")
	return e
}
func initConf() {
	var conf Conf
	confMap := conf.InitConfig("./", "csvTodb.ini", "csvTodb")
	DIR = confMap["dir"]
	TABLE = confMap["table"]
}
