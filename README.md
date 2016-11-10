#Package sinastoragegosdk

    import "github.com/qwgxiaoxiao/sinastoragegosdk"

    Overview
    Index
    Examples

##Overview ▾
Golang SDK for 新浪云存储
```
	S3官方API接口文档地址:
		http://open.sinastorage.com/doc/scs/api
	Contact:		
		s3storage@sina.com
```

##Index ▾
```
func Display(dat []byte)
func GetUploadId(body []byte) string

type MultUpload
	func (mlud MultUpload) InitiateMultipartUpload() (statusCode int, respBody []uint8)
	func (mlud MultUpload) UploadPart(uploadId string, acl string) []part
	func (mlud MultUpload) ListParts(uploadId string) (statusCode int, listParts []map[string]interface{})
	func (mlud MultUpload) CompleteMultUpload(uploadId string, partInfo []part) (statusCode int, respBody []uint8)       
    
type SCS      
	func (scs SCS) GetBucketInfo(bucket string, info string) (statusCode int, respBody []uint8)
	func (scs SCS) GetObject(bucket, object string) (statusCode int, respBody []uint8)
	func (scs SCS) GetObjectInfo(bucket, object, info string) (statusCode int, respBody []uint8)
	func (scs SCS) ListBucket() (statusCode int, respBody []uint8)
	func (scs SCS) ListObject(bucket string, delimiter, prefix, marker string, maxKeys int) (statusCode int, respBody []uint8)
	func (scs SCS) ObjectCopy(dstbucket, dstobject, srcbucket, srcobject string) (statusCode int, respBody []uint8)
	func (scs SCS) PutBucket(bucket string, acl string) (statusCode int, respBody []uint8)
	func (scs SCS) PutObject(bucket, object string, uploadfile string, acl string) (statusCode int, respBody []uint8)
	func (scs SCS) PutObjectRelax(bucket, object string, uploadfile string) (statusCode int, respBody []uint8)
	func (scs SCS) SetBucketAcl(bucket string, acl map[string][]string) (statusCode int, respBody []uint8)
	func (scs SCS) SetObjectAcl(bucket, object string, acl map[string][]string) (statusCode int, respBody []uint8)
	func (scs SCS) SetObjectMeta(bucket, object string, meta map[string]string) (statusCode int, respBody []uint8)
	func (scs SCS) DeleteBucket(bucket string) (statusCode int, respBody []uint8)
	func (scs SCS) DeleteObject(bucket, object string) (statusCode int, respBody []uint8)
```

##Examples ▾

    MultUpload
    SCS.GetObject
    SCS.ListObject
    

###func Display
```
func Display(dat []byte)
```

结构化显示返回的json数据,主要用于response body的格式化显示。 eg:
```
{
	"ACL": {
		"GRPS000000ANONYMOUSE": [
			"read"
		],
		"SINA000000RUIKUNTEST": [
			"read",
			"write",
			"read_acp",
			"write_acp"
		]
	},
	"Owner": "SINA000000OWNER"
}
```

###func GetUploadId
```
func GetUploadId(body []byte) string
```
用于大文件分片上传，从InitiateMultipartUpload() 返回的response body中拿出uploadId, 并返回。

###type MultUpload
```
type MultUpload struct {
    SCS
    Bucket     string // 需要上传的bucket
    Object     string // 需要上传的object
    UploadFile string // 上传文件
    SliceCount int    // 分片大小，单位字节
}
```
###大文件分片上传示例
```
Example:

scs := &SCS{"accessKey", "secretKey", "Uri"}
mlud := &MultUpload{*scs, "bucket", "object", "uploadFile", SliceCount}

status, body := mlud.InitiateMultipartUpload()
if status != 200 {
    log.Fatal("Initiate Multiple Upload Error !")
}
uploadId := GetUploadId(body)

partInfo := mlud.UploadPart(uploadId, "private")

statusList, listedParts := mlud.ListParts(uploadId)
if statusList != 200 {
    log.Fatal("List Multiple Parts Error !")
}

if len(partInfo) > 0 && len(partInfo) == len(listedParts) {
    for k, v := range partInfo {
        if v.ETag != listedParts[k]["ETag"].(string) {
            log.Fatal("Slice Etag Does not match !")
            break
        }
    }
}

statusCode, body := mlud.CompleteMultUpload(uploadId, partInfo)
if statusCode != 200 {
    log.Fatal("Complete Multiple Upload Failed !")
}

```
###func (MultUpload) InitiateMultipartUpload
```
func (mlud MultUpload) InitiateMultipartUpload() (statusCode int, respBody []uint8)
```
大文件分片上传初始化，返回uploadId。

注意：在初始化上传接口中要求必须进行用户认证，匿名用户无法使用该接口。

在初始化上传时需要给定文件上传所需要的meta绑定信息，在后续的上传中该信息将被保留，并在最终完成时写入云存储系统。
```
响应（示例）：

HTTP/1.1 200 OK
Date: Tue, 08 Apr 2014 02:59:47 GMT
Connection: keep-alive
X-RequestId: 00078d50-1404-0810-5947-782bcb10b128
X-Requester: Your UserId
{
   	"Bucket": "<Your-Bucket-Name>",
   	"Key": "<ObjectName>",
   	"UploadId": "7517c1c49a3b4b86a5f08858290c5cf6"
}
```

###func (MultUpload) UploadPart
```
func (mlud MultUpload) UploadPart(uploadId string, acl string) []part
```
上传分片, 注意：分片数不能超过2048。

acl 为快捷ACL。

返回 partInfo []part。
```
 type part struct {
	 PartNumber int		分片id, 从1开始累加
	 ETag       string	分片的md5值
 }
```

###func (MultUpload) ListParts
```
func (mlud MultUpload) ListParts(uploadId string) (statusCode int, listParts []map[string]interface{})
```
列出已经上传的所有分片信息。

成功返回状态码200，分片的Parts信息。

###func (MultUpload) CompleteMultUpload
```
func (mlud MultUpload) CompleteMultUpload(uploadId string, partInfo []part) (statusCode int, respBody []uint8)
```
大文件分片上传拼接（合并）。



###type SCS
```
type SCS struct {
    Accessk string
    Secretk string
    Uri     string
}
```
####快捷ACL
```
private 			Bucket和Object 	Owner权限 = FULL_CONTROL，其他人没有任何权限
public-read 		Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ
public-read-write 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ + WRITE
authenticated-read 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS0000000CANONICAL权限 = READ

GRPS0000000CANONICAL：此组表示所有的新浪云存储注册帐户。所有的请求必须签名（认证），如果签名认证通过，即可按照已设置的权限规则进行访问。
GRPS000000ANONYMOUSE：匿名用户组，对应的请求可以不带签名。
SINA000000000000IMGX：图片处理服务，将您的bucket的ACL设置为对SINA000000000000IMGX的读写权限，在您使用图片处理服务的时候可以免签名。
```

SCS 所有方法返回值均是Status Code 和Response Body, Response Body 均是json格式。

###func (SCS) GetBucketInfo
```
func (scs SCS) GetBucketInfo(bucket string, info string) (statusCode int, respBody []uint8)
```
获取bucket 的meta 或acl 信息，"info"值为 "meta" or "acl"。

bucket是一个链接项目时，无法获取具体信息。

返回status code 和response body， response body 是json格式。

###func (SCS) GetObject
```
func (scs SCS) GetObject(bucket, object string) (statusCode int, respBody []uint8)
```
获取object内容。

####下载文件示例
```
Example:

scs := &SCS{"accessKey", "secretKey", "Uri"}
status, body := scs.GetObject("bucket", "object")
if status != 200 {
    log.Fatal("Get Object Error !")
}
fd, errC := os.Create("/tmp/object")
if errC != nil {
    log.Fatal("Create File Error !")
}
n, errW := fd.Write(body)
if errw != nil {
    log.Fatal("write File Error !")
}
if n != len(body) {
    log.Fatal("Object Content Error!")
}
```

###func (SCS) GetObjectInfo
```
func (scs SCS) GetObjectInfo(bucket, object, info string) (statusCode int, respBody []uint8)
```
获取object 的meta 或acl 信息，"info"值为 "meta" or "acl"。

返回status code 和response body，response body 是json格式。

###func (SCS) ListBucket
```
func (scs SCS) ListBucket() (statusCode int, respBody []uint8)
```
列出用户账户下所有的bucket。

返回status code 和response body， response body 是json格式。

###func (SCS) ListObject
```
func (scs SCS) ListObject(bucket string, delimiter, prefix, marker string, maxKeys int) (statusCode int, respBody []uint8)
```
 列出Bucket 下的所有object。
```
delimiter 	折叠显示字符,通常使用：'/'
			"" 时，以"join/mailaddresss.txt" 这种”目录+object“的形式展示，
			"/" 时，以"join" 这种"目录"的形式展示，不会展开目录
prefix 		列出以指定字符为开头的Key,可为""空字符串
marker 		Key的初始位置，系统将列出比Key大的值，通常用作‘分页’的场景，可为""空字符串
max-keys 	返回值的最大Key的数量。
```
返回status code 和response body，response body 是json格式。

####列bucket下所有objects示例
```
Example:

scs := &SCS{"accessKey", "secretKey", "Uri"}
scs.ListObject("bucket", "", "", "", 400)
scs.ListObject("bucket", "/", "", "", 400)
scs.ListObject("bucket", "", "pict", "test.go", 400)

```
###func (SCS) ObjectCopy
```
func (scs SCS) ObjectCopy(dstbucket, dstobject, srcbucket, srcobject string) (statusCode int, respBody []uint8)
```
通过拷贝方式创建Object（不上传具体的文件内容。而是通过COPY方式对系统内另一文件进行复制）。

Copy 成功返回状态码200， 返回response body 为空。

###func (SCS) PutBucket
```
func (scs SCS) PutBucket(bucket string, acl string) (statusCode int, respBody []uint8)
```

创建bucket，acl 是快捷ACL。

acl 值为""，对应的快捷ACL 为private。

成功返回状态码200， 返回response body 为空。

###func (SCS) PutObject
```
func (scs SCS) PutObject(bucket, object string, uploadfile string, acl string) (statusCode int, respBody []uint8)
```
上传object, acl 是快捷ACL。

成功返回状态码200， 返回response body 为空。

###func (SCS) PutObjectRelax
```
func (scs SCS) PutObjectRelax(bucket, object string, uploadfile string) (statusCode int, respBody []uint8)
```
通过“秒传”方式创建Object（不上传具体的文件内容。而是通过SHA-1值对系统内文件进行复制）。

成功返回状态码200， 返回response body 为空。

###func (SCS) SetBucketAcl
```
func (scs SCS) SetBucketAcl(bucket string, acl map[string][]string) (statusCode int, respBody []uint8)
```
设置bucket 的ACL。
```
ACL 格式举例： acl := map[string][]string{"GRPS000000ANONYMOUSE": []string{"read", "read_acp", "write", "write_acp"}}
```
成功返回状态码200， 返回response body 为空。

###func (SCS) SetObjectAcl
```
func (scs SCS) SetObjectAcl(bucket, object string, acl map[string][]string) (statusCode int, respBody []uint8)
```
设置指定object 的ACL。
```
ACL 格式举例： acl := map[string][]string{"GRPS000000ANONYMOUSE": []string{"read", "read_acp", "write", "write_acp"}}
```
成功返回状态码200， 返回response body 为空。

###func (SCS) SetObjectMeta
```
func (scs SCS) SetObjectMeta(bucket, object string, meta map[string]string) (statusCode int, respBody []uint8)
```
更新一个已经存在的文件的附加meta信息。
```
meta 格式举例： meta := map[string]string{"x-amz-meta-name": "sandbox", "x-amz-meta-age": "13"}
```
注意：这个接口无法更新文件的基本信息，如文件的大小和类型等。

成功返回状态码200， 返回response body 为空。

###func (SCS) DeleteBucket
```
func (scs SCS) DeleteBucket(bucket string) (statusCode int, respBody []uint8)
```
删除bucket。

删除成功返回状态码204， 返回response body 为空。

###func (SCS) DeleteObject
```
func (scs SCS) DeleteObject(bucket, object string) (statusCode int, respBody []uint8)
```
删除object。

删除成功返回状态码204， 返回response body 为空。


Build version go1.2.
