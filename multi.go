package sinastoragegosdk

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

//上传分片, 注意：分片数不能超过2048
func (m *Multi) PutPart(uploadFile string, acl ACL, partSize int) ([]Part, error) {
	fd, err := os.Open(uploadFile)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	data := make([]byte, partSize)
	var partInfo []Part
	var offset int64 = 0
	var i int = 1
	for {
		ne, err := fd.Seek(offset, 0)
		if err != nil {
			return nil, err
		}
		me, errR := fd.ReadAt(data, ne)
		if me < len(data) {
			tmp := make([]byte, me)
			copy(tmp, data)
			data = data[0:0]
			data = tmp
		}
		contType := http.DetectContentType(data)
		part, err := m.putPart(data, contType, acl, i)
		if err != nil {
			return nil, err
		}
		partInfo = append(partInfo, part)
		if errR != nil {
			break
		}
		i++
		offset = offset + int64(me)
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