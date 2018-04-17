package util

import (
	"bufio"
	"bytes"
	"code.google.com/p/mahonia"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/cache"
	"github.com/clbanning/mxj"
	"gopkg.in/mgo.v2/bson"
	"hash"
	"io"
	"io/ioutil"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var localCache cache.Cache

func InitCache() {
	c, err := cache.NewCache("memory", `{"interval":60}`)
	//c, err := cache.NewCache("file", `{"CachePath":"./dhcache","FileSuffix":".cache","DirectoryLevel":2,"EmbedExpiry":120}`)
	if err != nil {
		Error(err)
	} else {
		localCache = c
	}
}

type P map[string]interface{}

func (p *P) Copy() P {
	pn := make(P)
	for k, v := range *p {
		pn[k] = v
	}
	return pn
}

func (p P) CopyFrom(from P) {
	for k, v := range from {
		p[k] = v
	}
}

func (p *P) ToInt(s ...string) {
	for _, k := range s {
		v := ToString((*p)[k])
		if !IsEmpty(v) {
			(*p)[k] = ToInt(v)
		}
	}
}

func (p *P) ToOid(s ...string) {
	for _, k := range s {
		v := ToString((*p)[k])
		if !IsEmpty(v) {
			if !IsOid(v) {
				Unset(*p, k)
				continue
			}
			(*p)[k] = ToOid(v)
		}
	}
}

func (p *P) Like(s ...string) {
	for _, k := range s {
		v := ToString((*p)[k])
		if !IsEmpty(v) {
			(*p)[k] = &bson.RegEx{Pattern: v, Options: "i"}
		}
	}
}

func (p *P) ToP(s ...string) (r P) {
	for _, k := range s {
		v := ToString((*p)[k])
		r = *JsonDecode([]byte(v))
		(*p)[k] = r
		Debug("ToP", k, (*p)[k])
	}
	return
}

func (p *P) Get(k string, def interface{}) interface{} {
	r := (*p)[k]
	if r == nil {
		r = def
	}
	return r
}

func ToInt(s interface{}, default_v ...int) int {
	i, e := strconv.Atoi(ToString(s))
	if e != nil && len(default_v) > 0 {
		return default_v[0]
	}
	return i
}

func ToInt64(s interface{}, default_v ...int64) int64 {
	switch s.(type) {
	case int64:
		return s.(int64)
	case int:
		return int64(s.(int))
	case float64:
		return int64(s.(float64))
	}
	i64, e := strconv.ParseInt(ToString(s), 10, 64)
	if e != nil && len(default_v) > 0 {
		return default_v[0]
	}
	return i64
}

func ToFloat(s interface{}, default_v ...float64) float64 {
	f64, e := strconv.ParseFloat(ToString(s), 64)
	if e != nil && len(default_v) > 0 {
		return default_v[0]
	}
	return f64
}

func IsInt(s interface{}) bool {
	_, e := strconv.ParseInt(ToString(s), 10, 64)
	return e == nil
}

func IsFloat(s interface{}) bool {
	_, e := strconv.ParseFloat(ToString(s), 64)
	return e == nil
}

func Md5(s ...interface{}) (r string) {
	return Hash("md5", s...)
}

func Hash(algorithm string, s ...interface{}) (r string) {
	var h hash.Hash
	switch algorithm {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha2", "sha256":
		h = sha256.New()
	}
	for _, value := range s {
		switch value.(type) {
		case []byte:
			h.Write(value.([]byte))
		default:
			h.Write([]byte(ToString(value)))
		}
	}
	r = hex.EncodeToString(h.Sum(nil))
	return
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(s string) []byte {
	r, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		Error(e)
	}
	return r
}

func Timestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func DateTimeStr() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

func ToTime(s string) (t time.Time, e error) {
	fmt := []string{"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"02/Jan/2006:15:04:05 -0700",
		"2006/01/02 15:04:05",
		"15:04:05",
		"15:04",
		"2006/01/02",
		"2006-01-02",
		"01-02-2006",
		"01-02-06",
		"2006-01-02 15:04:05 +0800 CST",
		"2006年01月02日 15:04:05",
		"2006年01月02日"}
	for _, f := range fmt {
		t, e = time.Parse(f, s)
		if e == nil {
			return t, e
		}
	}
	return
}

func InArray(s string, a []string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func StartsWith(s string, a ...string) bool {
	for _, x := range a {
		if strings.HasPrefix(s, x) {
			return true
		}
	}
	return false
}

func EndsWith(s string, a ...string) bool {
	for _, x := range a {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func Unset(p P, keys ...string) {
	for _, x := range keys {
		delete(p, x)
	}
}

func ReadFile(path string) string {
	return string(ReadFileBytes(path))
}

func ReadFileBytes(path string) []byte {
	c, err := ioutil.ReadFile(path)
	if err != nil {
		Error("ReadFile", err)
	}
	return c
}

func WriteFile(path string, body []byte) {
	err := ioutil.WriteFile(path, body, 0644)
	if err != nil {
		Error(err)
	}
}

func DeleteFile(path string) {
	err := os.Remove(path)
	if err != nil {
		Error(err)
	}
}

func ReadLine(fileName string, lineCount int) (r string, e error) {
	f, err := os.Open(fileName)
	if err != nil {
		e = err
		return
	}
	buf := bufio.NewReader(f)
	for i := 0; i < lineCount; i++ {
		line, err := buf.ReadString('\n')
		r += line
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
	}
	return
}

func Rand(start int, end int) int {
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(end)
	if r < start {
		r = start + rand.Intn(end-start)
	}
	//time.Sleep(1 * time.Nanosecond)
	return r
}

func JsonDecode(b []byte) (p *P) {
	p = &P{}
	err := json.Unmarshal(b, p)
	if err != nil {
		Error("JsonDecode", string(b), err)
	}
	return
}

func JsonEncode(v interface{}) (r string) {
	b, err := json.Marshal(v)
	if err != nil {
		Error(err)
	}
	r = string(b)
	return
}

func IsJson(b []byte) bool {
	var j json.RawMessage
	return json.Unmarshal(b, &j) == nil
}

func JsonDecodeArray(b []byte) (p []*P, e error) {
	p = []*P{}
	e = json.Unmarshal(b, &p)
	if e != nil {
		Error("JsonDecodeArray", e)
	}
	return
}

func JsonDecodeArrays(b []byte) (p *[]P) {
	p = &[]P{}
	e := json.Unmarshal(b, p)
	if e != nil {
		Error(e)
	}
	return
}

func JsonDecodeStrings(s string) (r []string) {
	r = []string{}
	e := json.Unmarshal([]byte(s), &r)
	if e != nil {
		Error(e, s)
	}
	return
}

func JoinStr(val ...interface{}) (r string) {
	for _, v := range val {
		r += ToString(v)
	}
	return
}

func Replace(src string, find []string, r string) string {
	for _, v := range find {
		src = strings.Replace(src, v, r, -1)
	}
	return src
}

func Pathinfo(url string) P {
	p := P{}
	url = strings.Replace(url, "\\", "/", -1)
	if strings.Index(url, "/") < 0 {
		url = JoinStr("./", url)
	}
	re := regexp.MustCompile("(.*)/([^/]*)\\.([^.]*)")
	match := re.FindAllStringSubmatch(url, -1)
	if len(match) > 0 {
		m0 := match[0]
		fmt.Println(m0)
		if len(m0) == 4 {
			p["basename"] = m0[0]
			p["dirname"] = m0[1]
			p["filename"] = m0[2]
			p["extension"] = strings.ToLower(m0[3])
		}
	}
	return p
}

func HttpGet(url string, header *P, param *P) (body string, e error) {
	r, err := HttpGetBytes(url, header, param)
	if err != nil {
		Error(err)
	}
	e = err
	body = string(r)
	return
}

func HttpGetBytes(url string, header *P, param *P) (body []byte, e error) {
	return HttpDo("GET", url, header, param)
}

func HttpPost(url string, header *P, param *P) (body string, err error) {
	r, e := HttpDo("POST", url, header, param)
	if e != nil {
		Error("HttpPost", e)
		body = e.Error()
	} else {
		body = string(r)
	}
	return
}

func HttpDelete(url string, header *P, param *P) (body []byte, e error) {
	return HttpDo("DELETE", url, header, param)
}

func HttpDo(method string, httpurl string, header *P, param *P) (body []byte, err error) {
	client := &http.Client{Timeout: time.Duration(10 * time.Second)}
	var req *http.Request
	vs := url.Values{}
	if param != nil {
		for k, v := range *param {
			key := ToString(k)
			if IsArray(v) {
				a, _ := v.([]interface{})
				for i, iv := range a {
					if i == 0 {
						vs.Set(key, ToString(iv))
					} else {
						vs.Add(key, ToString(iv))
					}
				}
			} else {
				vs.Set(key, ToString(v))
			}
		}
	}
	method = strings.ToUpper(method)
	req, err = http.NewRequest(method, httpurl, strings.NewReader(vs.Encode()))
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if header != nil {
		for k, v := range *header {
			req.Header.Set(ToString(k), ToString(v))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return []byte(ToString(resp)), err
	}
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	body, err = ioutil.ReadAll(resp.Body)
	return
}

func Upload(url, file string) (body []byte, err error) {
	// Prepare a form that you will submit to that URL.
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// Add your file
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	fw, err := w.CreateFormFile("bin", file)
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, f); err != nil {
		return
	}
	// Add the other fields
	if fw, err = w.CreateFormField("key"); err != nil {
		return
	}
	if _, err = fw.Write([]byte("KEY")); err != nil {
		return
	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", url, &b)
	if err != nil {
		return
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())

	// Submit the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return []byte(ToString(res)), err
	}
	defer func() {
		if res != nil {
			res.Body.Close()
		}
	}()
	body, err = ioutil.ReadAll(res.Body)
	return
}

func ToString(v interface{}, def ...string) string {
	if v != nil {
		switch v.(type) {
		case bson.ObjectId:
			return v.(bson.ObjectId).Hex()
		case []byte:
			return string(v.([]byte))
		case *P, P:
			var p P
			switch v.(type) {
			case *P:
				if v.(*P) != nil {
					p = *v.(*P)
				}
			case P:
				p = v.(P)
			}
			var keys []string
			for k := range p {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			r := "P{"
			for _, k := range keys {
				r = JoinStr(r, k, ":", p[k], " ")
			}
			r = JoinStr(r, "}")
			return r
		case map[string]interface{}:
			return JsonEncode(v)
		case int64:
			return strconv.FormatInt(v.(int64), 10)
		case []string:
			s := ""
			for _, j := range v.([]string) {
				s = JoinStr(s, ",", j)
			}
			if len(s) > 0 {
				s = s[1:]
			}
			return s
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	if len(def) > 0 {
		return def[0]
	} else {
		return ""
	}
}

func ToP(v interface{}) P {
	if v != nil {
		switch v.(type) {
		case P:
			return v.(P)
		case string:
			return *JsonDecode([]byte(v.(string)))
		case map[string]interface{}:
			return v.(map[string]interface{})
		}
	}
	return P{}
}

func ToStrings(v interface{}) []string {
	strs := []string{}
	if v != nil {
		switch v.(type) {
		case []interface{}:
			for _, i := range v.([]interface{}) {
				strs = append(strs, ToString(i))
			}
		}
	}
	return strs
}

// 记录debug信息
func Debug(v ...interface{}) {
	beego.Debug(v)
}

// 记录err信息
func Error(v ...interface{}) {
	beego.Error(v)
}

func IsEmpty(v interface{}) bool {
	if v == nil {
		return true
	}
	switch v.(type) {
	case P:
		return len(v.(P)) == 0
	case []interface{}:
		return len(v.([]interface{})) == 0
	case []P:
		return len(v.([]P)) == 0
	case []*P:
		return len(v.([]*P)) == 0
	case *[]P:
		return len(*v.(*[]P)) == 0
	}
	return ToString(v) == ""
}

func Trim(str string) string {
	return strings.TrimSpace(str)
}

func Ip2Int(ip string) int64 {
	sec := strings.Split(ip, ".")
	if len(sec) == 4 {
		return int64(ToInt(sec[0]))<<24 + int64(ToInt(sec[1]))<<16 + int64(ToInt(sec[2]))<<8 + int64(ToInt(sec[3]))
	}
	return 0
}

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func Xml2Json(src string) (s string, err error) {
	m, err := mxj.NewMapXml([]byte(src))
	return JsonEncode(m), err
}

func UrlEncoded(str string) (string, error) {
	str = strings.Replace(str, "%", "%25", -1)
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func GetCronStr(sec int) (str string) {
	ss := sec % 60
	ii := sec / 60
	hh := sec / 3600
	if ii == 0 && hh == 0 {
		str = fmt.Sprintf("0/%v * * * * *", sec)
	} else if ii > 0 && hh == 0 {
		str = fmt.Sprintf("%v */%v * * * *", ss, ii)
	} else if hh > 0 {
		str = fmt.Sprintf("%v %v */%v * * *", ss, ii%60, hh)
	} else {
		str = "0/60 * * * * *"
	}
	return
}

func Gbk2Utf(str string) string {
	enc := mahonia.NewDecoder("gbk")
	return enc.ConvertString(str)
}

func RenderTpl(tpl string, data interface{}) string {
	var bb bytes.Buffer
	//t, err := template.ParseFiles(tpl)
	t, err := template.New(Md5(tpl)).Parse(tpl)
	if err != nil {
		Error(err)
	}
	t.Execute(&bb, data)
	return bb.String()
}

func Mkdir(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}

func AddInOid(oids *[]bson.ObjectId, nid bson.ObjectId) {
	for _, oid := range *oids {
		if oid.Hex() == nid.Hex() {
			return
		}
	}
	*oids = append(*oids, nid)
	return
}

// 缓存接口，存 S("key", value)，取 S("key")
func S(key string, p ...interface{}) (v interface{}) {
	md5 := Md5(key)
	if len(p) == 0 {
		return localCache.Get(md5)
	} else {
		if len(p) == 2 {
			var ttl int64
			switch p[1].(type) {
			case int:
				ttl = int64(p[1].(int))
			case int64:
				ttl = p[1].(int64)
			}
			localCache.Put(md5, p[0], time.Duration(ttl)*time.Second)
		} else if len(p) == 1 {
			localCache.Put(md5, p[0], 60*time.Second)
		}
		return p[0]
	}
}

func ExtractFile(path string, target string, ext string) {
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		Debug(path)
		//if !f.IsDir() {
		if strings.HasSuffix(f.Name(), ext) {
			Copy(path, target+"/"+f.Name())
		}
		//}
		return nil
	})
	Debug("filepath.Walk() %v\n", err)
}

func DirTree(path string, ext string, limit int) (files []P) {
	files = []P{}
	i := 0
	filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		//Debug(path)
		if i >= limit {
			return errors.New("reach limit")
		}
		i++
		if f != nil && !f.IsDir() {
			if strings.HasSuffix(f.Name(), ext) {
				files = append(files, P{"file": path})
			}
		}
		return nil
	})
	return
}

func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		return err
	}
	return cerr
}

func RegSplit(text string, delimeter string) []string {
	reg := regexp.MustCompile(delimeter)
	indexes := reg.FindAllStringIndex(text, -1)
	laststart := 0
	result := make([]string, len(indexes)+1)
	for i, element := range indexes {
		result[i] = text[laststart:element[0]]
		laststart = element[1]
	}
	result[len(indexes)] = text[laststart:len(text)]
	return result
}

func ToFields(s string, div string) (r []string) {
	tmp := strings.Split(s, div)
	r = []string{}
	state := ""
	seg := ""
	for i, v := range tmp {
		if (strings.Index(v, "(") > -1 && strings.Index(v, ")") < 0) || (StartsWith(v, `"`) && !EndsWith(v, `"`)) {
			state = "("
			seg = v
		} else if (strings.Index(v, "(") < 0 && strings.Index(v, ")") > -1) || (!StartsWith(v, `"`) && EndsWith(v, `"`)) {
			state = ")"
		}
		if state == "(" {
			if i+1 < len(tmp) {
				seg = JoinStr(seg, ",", tmp[i+1])
				seg = TransFunc(seg)
			}
		} else if state == ")" {
			seg = TransFunc(seg)
			r = append(r, seg)
			seg = ""
			state = ""
		} else {
			v = TransFunc(v)
			r = append(r, v)
		}
	}
	return
}

func TransFunc(o string) (n string) {
	if StartsWith(o, "to_date(") {
		o = Trim(Replace(o, []string{"to_date(", ")"}, ""))
		tmp := strings.Split(o, " as ")
		field := ""
		as := ""
		field = tmp[0]
		if len(tmp) > 1 {
			as = tmp[1]
		}
		tmp = strings.Split(field, ",")
		if len(tmp) > 1 {
			if !IsEmpty(as) {
				n = JoinStr(n, " as ", as)
			}
		}
	} else if StartsWith(o, `"`) && EndsWith(o, `"`) {
		n = o[1 : len(o)-1]
	} else {
		n = o
	}
	return
}

func Exec(cmd string) (str string, e error) {
	osname := runtime.GOOS
	var r *exec.Cmd
	Debug("Exec:", cmd)
	if osname == "windows" {
		r = exec.Command("cmd", "/c", cmd)
	} else {
		r = exec.Command("/bin/bash", "-c", cmd)
	}
	output, err := r.CombinedOutput()
	if err != nil {
		Error(err, string(output))
		return string(output), err
	} else {
		str = string(output)
		Debug("Exec output:", str)
		return
	}
}

func Cwd() string {
	cwd, _ := os.Getwd()
	return cwd
}

func FileRemoveLine(file string, start int, lines int) {
	cmd := fmt.Sprintf("sed -i '%v,%vd' %v", start, lines, file)
	Exec(cmd)
}

func FileInsertLine(file string, start int, txt string) {
	cmd := fmt.Sprintf("sed -i '%vi %v' %v", start, txt, file)
	Exec(cmd)
}
func ToOid(id interface{}) (oid bson.ObjectId) {
	s := ToString(id)
	if bson.IsObjectIdHex(s) {
		oid = bson.ObjectIdHex(s)
	}
	return
}

func ToOids(ids interface{}) (oids []bson.ObjectId) {
	oids = []bson.ObjectId{}
	switch ids.(type) {
	case []string:
		for _, id := range ids.([]string) {
			if bson.IsObjectIdHex(id) {
				oids = append(oids, ToOid(id))
			}
		}
	case []interface{}:
		for _, id := range ids.([]interface{}) {
			if IsOid(ToString(id)) {
				oids = append(oids, ToOid(ToString(id)))
			}
		}
	}
	return
}

func NewId() bson.ObjectId {
	return bson.NewObjectId()
}

func IsOid(id string) bool {
	return bson.IsObjectIdHex(id)
}

func IsArray(v interface{}) bool {
	switch reflect.TypeOf(v).Kind() {
	case reflect.Array, reflect.Slice:
		return true
	default:
		return false
	}
}

func Invoke(any interface{}, name string, args ...interface{}) {
	inputs := make([]reflect.Value, len(args))
	for i, _ := range args {
		inputs[i] = reflect.ValueOf(args[i])
	}
	reflect.ValueOf(any).MethodByName(name).Call(inputs)
}

func AppendFile(file string, text string) {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	if err != nil {
		Error(err)
	}
	if _, err = f.WriteString(text); err != nil {
		Error(err)
	}
}
