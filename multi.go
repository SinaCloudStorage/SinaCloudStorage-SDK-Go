package sinastoragegosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
)

type Multi struct {
	Bucket   *Bucket
	Object   string
	UploadId string
}

type Part struct {
	PartNumber int
	ETag       string
}

//大文件分片上传初始化，返回Multi类
//注意：在初始化上传接口中要求必须进行用户认证，匿名用户无法使用该接口
//在初始化上传时需要给定文件上传所需要的meta绑定信息，在后续的上传中该信息将被保留，并在最终完成时写入云存储系统
func (b *Bucket) InitMulti(object string) (*Multi, error) {
	var bodyTmp interface{}
	params := map[string][]string{
		"multipart": {""},
		"formatter": {"json"},
	}
	req := &request{
		method: "POST",
		bucket: b.Name,
		path:   object,
		params: params,
	}
	body, err := b.query(req)
	json.Unmarshal(body, &bodyTmp)
	uploadId := bodyTmp.(map[string]interface{})["UploadId"].(string)
	return &Multi{Bucket: b, Object: object, UploadId: uploadId}, err
}

func (m *Multi) putPart(data []byte, contType string, acl ACL, number int) (Part, error) {
	body := bytes.NewBuffer(data)
	md5 := contMd5(data)
	header := map[string][]string{
		"Content-MD5":               {md5},
		"Content-Length":            {strconv.FormatInt(int64(len(data)), 10)},
		"x-amz-acl":                 {string(acl)},
		"x-amz-meta-uploadlocation": {fmt.Sprintf("/%s", m.Bucket.Name)},
		"Content-Type":              {contType},
		"Connection":                {"close"},
	}
	params := map[string][]string{
		"partNumber": {strconv.FormatInt(int64(number), 10)},
		"uploadId":   {m.UploadId},
	}
	req := &request{
		method:  "PUT",
		bucket:  m.Bucket.Name,
		path:    m.Object,
		headers: header,
		params:  params,
		body:    body,
	}
	_, err := m.Bucket.query(req)
	eTag, _ := base64.StdEncoding.DecodeString(md5)
	return Part{number, fmt.Sprintf("%x", eTag)}, err
}

type Job struct {
	Number     int
	PieceCount int
	Offset     int64
	PartSize   int
	Fd         *os.File
	Acl        ACL
	Minstance  *Multi
}

func newJob(i int, pieceCount int, offset int64, partSize int, fd *os.File, acl ACL, m *Multi) Job {
	return Job{
		Number:     i,
		PieceCount: pieceCount,
		Offset:     offset,
		PartSize:   partSize,
		Fd:         fd,
		Acl:        acl,
		Minstance:  m}
}

func doPut(job Job, JobResultChan chan Part, JobResultErrorChan chan error) {
	if job.Number > job.PieceCount {
		JobResultErrorChan <- nil
		return
	}
	ne, err := job.Fd.Seek(job.Offset, 0)
	if err != nil {
		JobResultErrorChan <- err
		return
	}
	data := make([]byte, job.PartSize)
	me, errR := job.Fd.ReadAt(data, ne)
	if me < len(data) {
		tmp := make([]byte, me)
		copy(tmp, data)
		data = data[0:0]
		data = tmp
	}
	contType := http.DetectContentType(data)
	part, err := job.Minstance.putPart(data, contType, job.Acl, job.Number)
	if err != nil {
		JobResultErrorChan <- err
		return
	}
	if errR != nil && errR != io.EOF {
		JobResultErrorChan <- err
		return
	}
	JobResultErrorChan <- nil
	JobResultChan <- part
}

//上传分片, 注意：分片数不能超过2048
func (m *Multi) PutPart(uploadFile string, acl ACL, partSize int) ([]Part, error) {
	fd, err := os.Open(uploadFile)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	var partInfo []Part
	var offset int64 = 0
	/*Calculating the number of pieces*/
	fi, err := fd.Stat()
	if err != nil {
		// Could not obtain stat, handle error
		return nil, err
	}
	fileSize := fi.Size()
	pieceCount := int(math.Ceil(float64(fileSize) / float64(partSize)))
	if pieceCount > 2048 {
		return nil, fmt.Errorf("too many pieces number, max 2048")
	}
	Concurrency := 5

	JobResultChan := make([]chan Part, pieceCount)
	JobResultErrotChan := make([]chan error, pieceCount)

	chLimit := make(chan bool, Concurrency)

	limitFunc := func(job Job, chLimit chan bool, ch chan Part, chError chan error) {
		doPut(job, ch, chError)
		<-chLimit
	}

	for i := 1; i <= pieceCount; i++ {
		JobResultChan[i-1] = make(chan Part, 1)
		JobResultErrotChan[i-1] = make(chan error, 1)
		chLimit <- true
		job := newJob(i, pieceCount, offset, partSize, fd, acl, m)
		go limitFunc(job, chLimit, JobResultChan[i-1], JobResultErrotChan[i-1])
		offset = offset + int64(partSize)
	}

	/*error*/
	for _, ch := range JobResultErrotChan {
		err := <-ch
		if err != nil {
			return nil, err
		}
	}

	/*result*/
	for _, ch := range JobResultChan {
		part := <-ch
		partInfo = append(partInfo, part)
	}

	return partInfo, nil
}

//列出已经上传的所有分片信息
func (m *Multi) ListPart() ([]Part, error) {
	var partsInfo []Part
	params := map[string][]string{
		"uploadId":  {m.UploadId},
		"formatter": {"json"},
	}
	req := &request{
		bucket: m.Bucket.Name,
		path:   m.Object,
		params: params,
	}
	parts, err := m.Bucket.query(req)
	if err != nil {
		return nil, err
	}
	var partsTmp interface{}
	json.Unmarshal(parts, &partsTmp)
	partstmp := partsTmp.(map[string]interface{})["Parts"].([]interface{})
	partsInfo = make([]Part, len(partstmp))
	for _, v := range partstmp {
		a := int(v.(map[string]interface{})["PartNumber"].(float64))
		b := v.(map[string]interface{})["ETag"].(string)
		partsInfo[a-1] = Part{a, b}
	}
	return partsInfo, nil
}

//大文件分片上传拼接（合并）
func (m *Multi) Complete(partInfo []Part) error {
	partsJ, err := json.Marshal(partInfo)
	if err != nil {
		return err
	}
	params := map[string][]string{
		"uploadId":  {m.UploadId},
		"formatter": {"json"},
	}
	req := &request{
		method:  "POST",
		bucket:  m.Bucket.Name,
		path:    m.Object,
		params:  params,
		body:    bytes.NewReader(partsJ),
		headers: map[string][]string{"Content-Length": {strconv.FormatInt(int64(len(partsJ)), 10)}},
	}
	_, err = m.Bucket.query(req)
	return err
}