// Copyright 2016 The Go Authors. All rights reserved.

/*
Golang SDK for 新浪云存储

 S3官方API接口文档地址:

 	http://open.sinastorage.com/doc/scs/api
 Contact:
 	s3storage@sina.com

*/
package sinastoragegosdk

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SCS struct {
	AccessKey string
	SecretKey string
	EndPoint  string
}

type Bucket struct {
	*SCS
	Name string
}

// 新创建一个SCS类
func NewSCS(accessKey, secretKey, endPoint string) (scs *SCS) {
	return &SCS{accessKey, secretKey, endPoint}
}

// 返回一个名为name的Bucket类
func (scs *SCS) Bucket(name string) *Bucket {
	name = strings.ToLower(name)
	return &Bucket{scs, name}
}

/*
 快捷ACL

 	private 		Bucket和Object 	Owner权限 = FULL_CONTROL，其他人没有任何权限
 	public-read 		Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ
 	public-read-write 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ + WRITE
 	authenticated-read 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS0000000CANONICAL权限 = READ

 	GRPS0000000CANONICAL：此组表示所有的新浪云存储注册帐户。所有的请求必须签名（认证），如果签名认证通过，即可按照已设置的权限规则进行访问。
 	GRPS000000ANONYMOUSE：匿名用户组，对应的请求可以不带签名。
 	SINA000000000000IMGX：图片处理服务，将您的bucket的ACL设置为对SINA000000000000IMGX的读写权限，在您使用图片处理服务的时候可以免签名。
*/
type ACL string

const (
	Private           = ACL("private")
	PublicRead        = ACL("public-read")
	PublicReadWrite   = ACL("public-read-write")
	AuthenticatedRead = ACL("authenticated-read")
)

// 列出用户账户下所有的buckets
func (b *Bucket) ListBucket() (data []byte, err error) {
	req := &request{
		path:   "/",
		params: map[string][]string{"formatter": {"json"}},
	}
	data, err = b.query(req)
	return data, err
}

//列出Bucket下的所有objects
func (b *Bucket) ListObject(prefix, delimiter, marker string, maxKeys int) (data []byte, err error) {
	var params = make(map[string][]string)
	if prefix != "" {
		params["prefix"] = []string{prefix}
	}
	if delimiter != "" {
		params["delimiter"] = []string{delimiter}
	}
	if marker != "" {
		params["marker"] = []string{marker}
	}
	if maxKeys != 0 {
		params["max-keys"] = []string{strconv.Itoa(maxKeys)}
	}
	params["formatter"] = []string{"json"}
	req := &request{
		bucket: b.Name,
		params: params,
	}
	data, err = b.query(req)
	return data, err
}

// 获取bucket的meta或acl信息，"info"值为"meta" or "acl"
func (b *Bucket) GetBucketInfo(info string) (data []byte, err error) {
	info = strings.ToLower(info)
	var params = make(map[string][]string)
	if info == "acl" {
		params["acl"] = []string{""}
	} else {
		params["meta"] = []string{""}
	}
	params["formatter"] = []string{"json"}
	req := &request{
		bucket: b.Name,
		params: params,
	}
	data, err = b.query(req)
	return data, err
}

// 创建bucket
func (b *Bucket) PutBucket(acl ACL) error {
	header := map[string][]string{
		"x-amz-acl": []string{string(acl)},
	}
	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    "/",
		headers: header,
	}
	_, err := b.query(req)
	return err
}

// 删除bucket
func (b *Bucket) DelBucket() error {
	req := &request{
		method: "DELETE",
		bucket: b.Name,
		path:   "/",
	}
	_, err := b.query(req)
	return err
}

// 获取object的meta或acl信息，"info"值为"meta" or "acl"
func (b *Bucket) GetInfo(object string, info string) (data []byte, err error) {
	var params = make(map[string][]string)
	info = strings.ToLower(info)
	if info == "acl" {
		params["acl"] = []string{""}
	} else {
		params["meta"] = []string{""}
	}
	params["formatter"] = []string{"json"}
	req := &request{
		params: params,
		bucket: b.Name,
		path:   object,
	}
	data, err = b.query(req)
	return data, err

}

// 下载object
func (b *Bucket) Get(object string) (data []byte, err error) {
	req := &request{
		bucket: b.Name,
		path:   object,
	}
	data, err = b.query(req)
	return data, err
}

// 过拷贝方式创建object（不上传具体的文件内容,而是通过COPY方式对系统内另一文件进行复制）
func (b *Bucket) Copy(dstObject, srcBucket, srcObject string) error {
	header := map[string][]string{
		"x-amz-copy-source": []string{fmt.Sprintf("/%s/%s", srcBucket, srcObject)},
	}
	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		headers: header,
		path:    dstObject,
	}
	_, err := b.query(req)
	return err
}

// 上传object
func (b *Bucket) Put(object, uploadFile string, acl ACL) error {
	if acl == "" {
		acl = Private
	}
	data, err := ioutil.ReadFile(uploadFile)
	if err != nil {
		return err
	}
	err = b.put(object, data, acl, "")
	return err
}

// 文件上传并添加过期时间
func (b *Bucket) PutExpire(object, uploadFile string, acl ACL, expire time.Time) error {
	expires := expire.UTC().Format(time.RFC1123)
	if acl == "" {
		acl = Private
	}
	data, err := ioutil.ReadFile(uploadFile)
	if err != nil {
		return err
	}
	err = b.put(object, data, acl, expires)
	return err
}

func (b *Bucket) put(path string, data []byte, acl ACL, expires string) error {
	body := bytes.NewBuffer(data)
	md5 := contMd5(data)
	contType := http.DetectContentType(data)
	header := map[string][]string{
		"Content-Length":            {strconv.FormatInt(int64(len(data)), 10)},
		"Content-Type":              {contType},
		"Content-MD5":               {md5},
		"x-amz-acl":                 {string(acl)},
		"x-amz-meta-uploadlocation": {"/" + b.Name},
	}
	if expires != "" {
		header["x-sina-expire"] = []string{expires}
	}

	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    path,
		headers: header,
		body:    body,
	}
	_, err := b.query(req)
	return err
}

// 以ssk的方式上传object
func (b *Bucket) PutSsk(object, uploadFile string, acl ACL) (string, error) {
	if acl == "" {
		acl = Private
	}
	data, err := ioutil.ReadFile(uploadFile)
	if err != nil {
		return "", err
	}
	ssk, err := b.putSsk(object, data, acl)
	return ssk, err
}

func (b *Bucket) putSsk(path string, data []byte, acl ACL) (string, error) {
	body := bytes.NewBuffer(data)
	md5 := contMd5(data)
	contType := http.DetectContentType(data)
	header := map[string][]string{
		"Content-Length":            {strconv.FormatInt(int64(len(data)), 10)},
		"Content-Type":              {contType},
		"Content-MD5":               {md5},
		"x-amz-acl":                 {string(acl)},
		"x-amz-meta-uploadlocation": {"/" + b.Name},
		//"x-sina-expire":             {time.Now().Add(10 * time.Second).Format(time.RFC1123)},
	}
	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		path:    fmt.Sprintf("ssk/%s/", path),
		headers: header,
		body:    body,
	}
	err := b.SCS.prepare(req)
	if err != nil {
		return "", err
	}
	hresp, err := b.SCS.run(req)
	if err != nil || hresp == nil {
		return "", err
	}
	var ssk string
	if v, ok := hresp.Header["X-Sina-Serverside-Key"]; ok {
		ssk = v[0]
	} else {
		return "", nil
	}
	return ssk, nil

}

// 通过“秒传”方式创建Object（不上传具体的文件内容，而是通过SHA-1值对系统内文件进行复制）
func (b *Bucket) Relax(object, uploadFile string, acl ACL) error {
	if acl == "" {
		acl = Private
	}
	data, err := ioutil.ReadFile(uploadFile)
	if err != nil {
		return err
	}
	sha := sha1.New()
	sha.Write(data)
	sha1F := fmt.Sprintf("%x", sha.Sum(nil))
	contType := http.DetectContentType(data)
	header := map[string][]string{
		"s-sina-length": {strconv.FormatInt(int64(len(data)), 10)},
		"Content-Type":  {contType},
		"s-sina-sha1":   {sha1F},
		"x-amz-acl":     {string(acl)},
		"Content-MD5":   {sha1F},
	}
	params := map[string][]string{"relax": []string{""}}
	req := &request{
		method:  "PUT",
		bucket:  b.Name,
		params:  params,
		headers: header,
		path:    object,
	}
	_, err = b.query(req)
	return err
}

// 更新一个已经存在的object的附加meta信息
// meta 格式举例： meta := map[string]string{"x-amz-meta-name": "sandbox", "x-amz-meta-age": "13"}
// 注意：这个接口无法更新文件的基本信息，如文件的大小和类型等
func (b *Bucket) PutMeta(object string, meta map[string]string) error {
	var header = make(map[string][]string)
	if len(meta) > 0 {
		params := map[string][]string{"meta": []string{""}}
		for k, v := range meta {
			header[k] = []string{v}
		}
		req := &request{
			bucket:  b.Name,
			path:    object,
			method:  "PUT",
			params:  params,
			headers: header,
		}
		_, err := b.query(req)
		return err
	}
	return nil
}

// 设置指定object 的ACL
// ACL 格式举例： acl := map[string][]string{"GRPS000000ANONYMOUSE": []string{"read", "read_acp", "write", "write_acp"}}
func (b *Bucket) PutAcl(object string, acl map[string][]string) error {
	if len(acl) > 0 {
		aclJ, err := json.Marshal(acl)
		if err != nil {
			return err
		}
		params := map[string][]string{
			"acl":       {""},
			"formatter": {"json"},
		}
		header := map[string][]string{"Content-Length": {strconv.FormatInt(int64(len(aclJ)), 10)}}
		req := &request{
			method:  "PUT",
			bucket:  b.Name,
			path:    object,
			params:  params,
			body:    bytes.NewReader(aclJ),
			headers: header,
		}
		_, err = b.query(req)
		return err
	}
	return nil
}

// 删除object
func (b *Bucket) Del(object string) error {
	req := &request{
		method: "DELETE",
		bucket: b.Name,
		path:   object,
	}
	_, err := b.query(req)
	return err
}

type request struct {
	method   string
	bucket   string
	path     string
	signpath string
	params   url.Values
	headers  http.Header
	baseuri  string
	prepared bool
	body     io.Reader
}

func (b *Bucket) URL(object string) string {
	req := &request{
		bucket: b.Name,
		path:   object,
	}
	err := b.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.urlencode()
	if err != nil {
		panic(err)
	}
	u.RawQuery = ""
	return u.String()
}

func (b *Bucket) SignURL(object string, expires time.Time) string {
	params := map[string][]string{
		"Expires": {strconv.FormatInt(expires.Unix(), 10)},
	}
	req := &request{
		bucket: b.Name,
		path:   object,
		params: params,
	}
	err := b.prepare(req)
	if err != nil {
		panic(err)
	}
	u, err := req.urlencode()
	if err != nil {
		panic(err)
	}
	return u.String()
}

var sigleParams = map[string]bool{
	"acl":       true,
	"meta":      true,
	"multipart": true,
	"relax":     true,
}

func (req *request) urlencode() (*url.URL, error) {
	var sigleArray []string
	var value = url.Values{}
	u, err := url.Parse(req.baseuri)
	if err != nil {
		return nil, fmt.Errorf("bad S3 endpoint URL %q: %v", req.baseuri, err)
	}
	for k, v := range req.params {
		if sigleParams[k] {
			sigleArray = append(sigleArray, k)
		} else {
			value.Add(k, v[0])
		}
	}
	switch {
	case len(sigleArray) > 0 && len(value) > 0:
		u.RawQuery = strings.Join(sigleArray, "&") + "&" + value.Encode()
	case len(sigleArray) <= 0:
		u.RawQuery = value.Encode()
	default:
		u.RawQuery = strings.Join(sigleArray, "&")
	}
	re := regexp.MustCompile(req.bucket)
	if re.MatchString(u.Host) {
		u.Path = req.path
	} else {
		u.Path = req.signpath
	}
	return u, nil
}

func (scs *SCS) query(req *request) (data []byte, err error) {
	err = scs.prepare(req)
	if err != nil {
		return nil, err
	}
	hresp, err := scs.run(req)
	if err != nil || hresp == nil {
		return nil, err
	}
	data, err = ioutil.ReadAll(hresp.Body)
	hresp.Body.Close()
	return data, err
}

func (scs *SCS) prepare(req *request) error {
	if !req.prepared {
		req.prepared = true
		if req.method == "" {
			req.method = "GET"
		}
		// Copy so they can be mutated without affecting on retries.

		params := make(url.Values)
		headers := make(http.Header)
		for k, v := range req.params {
			params[k] = v
		}
		for k, v := range req.headers {
			headers[k] = v
		}
		req.params = params
		req.headers = headers
		if !strings.HasPrefix(req.path, "/") {
			req.path = "/" + req.path
		}
		req.signpath = req.path
		if req.bucket != "" {
			if strings.IndexAny(req.bucket, "/:@") >= 0 {
				return fmt.Errorf("bad S3 bucket: %q", req.bucket)
			}
			req.signpath = "/" + req.bucket + req.signpath
		}
		req.baseuri = scs.EndPoint
		req.baseuri = strings.Replace(req.baseuri, "$", req.bucket, -1)
	}
	u, err := url.Parse(req.baseuri)
	if err != nil {
		return fmt.Errorf("bad S3 endpoint URL %q: %v", req.baseuri, err)
	}
	req.headers["Host"] = []string{u.Host}
	req.headers["Date"] = []string{time.Now().In(time.UTC).Format(time.RFC1123)}
	req.headers["User-Agent"] = []string{"s3gosdk-1.0"}
	sign(*scs, req.method, req.signpath, req.params, req.headers)
	return nil
}

func (scs *SCS) run(req *request) (hresp *http.Response, err error) {
	u, err := req.urlencode()
	if err != nil {
		return nil, err
	}
	hreq := http.Request{
		URL:    u,
		Method: req.method,
		Header: req.headers,
		Close:  true,
	}
	if v, ok := req.headers["Content-Length"]; ok {
		hreq.ContentLength, _ = strconv.ParseInt(v[0], 10, 64)
		delete(req.headers, "Content-Length")
	}
	htCli := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, time.Second*5) //设置建立连接超时时间
				if err != nil {
					return nil, err
				}
				return c, nil
			},
		},
	}
	if req.body != nil {
		hreq.Body = ioutil.NopCloser(req.body)
	}
	hresp, err = htCli.Do(&hreq)
	if err != nil {
		return nil, err
	}
	if hresp.StatusCode != 200 && hresp.StatusCode != 204 {
		return nil, buildError(hresp)
	}
	return hresp, nil
}

type Error struct {
	StatusCode int
	RequestId  string
	ErrorCode  string
	Date       string
}

func (e *Error) Error() string {
	return e.ErrorCode
}

func buildError(r *http.Response) error {
	var err Error
	err.StatusCode = r.StatusCode
	err.RequestId = r.Header["X-Requestid"][0]
	if ErrCode, ok := r.Header["X-Error-Code"]; ok {
		err.ErrorCode = ErrCode[0]
	} else {
		err.ErrorCode = strconv.FormatInt(int64(r.StatusCode), 10)
	}
	err.Date = r.Header["Date"][0]
	return &err
}

func contMd5(data []byte) string {
	md := md5.New()
	md.Write(data)
	return base64.StdEncoding.EncodeToString(md.Sum(nil))
}
