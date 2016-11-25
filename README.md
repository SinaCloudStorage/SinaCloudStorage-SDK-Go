#<font color="#4682B4">PACKAGE DOCUMENTATION</font>


    import "github.com/SinaCloudStorage/SinaCloudStorage-SDK-Go"

    Golang SDK for 新浪云存储

	S3官方API接口文档地址:
		http://open.sinastorage.com/doc/scs/api
	Contact:
		s3storage@sina.com


##<font color="#4682B4">CONSTANTS</font>
```
const (
    Private           = ACL("private")
    PublicRead        = ACL("public-read")
    PublicReadWrite   = ACL("public-read-write")
    AuthenticatedRead = ACL("authenticated-read")
)
```

##<font color="#4682B4">TYPES</font>
```
type ACL string
```
```
快捷ACL

private 			Bucket和Object 	Owner权限 = FULL_CONTROL，其他人没有任何权限
public-read 		Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ
public-read-write 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS000000ANONYMOUSE权限 = READ + WRITE
authenticated-read 	Bucket和Object 	Owner权限 = FULL_CONTROL，GRPS0000000CANONICAL权限 = READ
GRPS0000000CANONICAL：此组表示所有的新浪云存储注册帐户。
					  所有的请求必须签名（认证），如果签名认证通过，即可按照已设置的权限规则进行访问。
GRPS000000ANONYMOUSE：匿名用户组，对应的请求可以不带签名。
SINA000000000000IMGX：图片处理服务，将您的bucket的ACL设置为对
					  SINA000000000000IMGX的读写权限，在您使用图片处理服务的时候可以免签名。
```

```
type SCS struct {
    AccessKey string
    SecretKey string
    EndPoint  string
}
```


```
type Bucket struct {
    *SCS
    Name string
}
```

##<font color="#4682B4"> BUCKETS AND OBJECTS OPERATIONS</font>

###<font color="#4682B4">func NewSCS</font>
```
func NewSCS(accessKey, secretKey, endPoint string) (scs *SCS)
```
创建一个SCS类

示例：
```
scs := NewSCS(ak, sk, "http://uri")
```

###<font color="#4682B4">func (scs *SCS) Bucket</font>
```
func (scs *SCS) Bucket(name string) *Bucket
```
返回一个名为name的Bucket类


###<font color="#4682B4">func (b *Bucket) ListBucket</font>
```
func (b *Bucket) ListBucket() (data []byte, err error)
```
列出用户账户下所有的buckets


###<font color="#4682B4">func (b *Bucket) ListObject</font>
```
func (b *Bucket) ListObject(prefix, delimiter, marker string, maxKeys int) (data []byte, err error)
```
列出Bucket下的所有objects

```
delimiter	折叠显示字符,通常使用：'/'
			"" 时，以"join/mailaddresss.txt" 这种”目录+object“的形式展示,
			"/" 时，以"join" 这种"目录"的形式展示，不会展开目录
prefix		列出以指定字符为开头的Key,可为""空字符串
marker		Key的初始位置，系统将列出比Key大的值，通常用作‘分页’的场景,可为""空字符串
max-keys	返回值的最大Key的数量
```

###<font color="#4682B4">func (b *Bucket) GetBucketInfo</font>
```
func (b *Bucket) GetBucketInfo(info string) (data []byte, err error)
```
获取bucket的meta或acl信息，"info"值为"meta" or "acl"

###<font color="#4682B4">func (b *Bucket) PutBucket</font>
```
func (b *Bucket) PutBucket(acl ACL) error
```
创建bucket

###<font color="#4682B4">func (b *Bucket) DelBucket</font>
```
func (b *Bucket) DelBucket() error
```
删除bucket

###<font color="#4682B4">func (b *Bucket) GetInfo</font>
```
func (b *Bucket) GetInfo(object string, info string) (data []byte, err error)
```
获取object的meta或acl信息，"info"值为"meta" or "acl"


### <font color="#4682B4">func (b *Bucket) Get</font>
```
func (b *Bucket) Get(object string) (data []byte, err error)
```
下载object

示例：
```
	scs := sdk.NewSCS(ak, sk, "http://uri")
	bt := scs.Bucket("bucketname")

	fd, err := os.Create("/tmp/3.png")
    if err != nil {
    	return err
    }
	data, err := bt.Get("3.png")
    if err != nil {
    	return err
    }
	n, err := fd.Write(data)
    if err != nil {
    	return err
    }
    fmt.Println(n)
```

###<font color="#4682B4">func (b *Bucket) Put</font>
```
func (b *Bucket) Put(object, uploadFile string, acl ACL) error
```
上传object

示例：
```
	err := bt.Put("test.go", "/tmp/test.go", sdk.Private)
	if err != nil {
		return err
	}
```

###<font color="#4682B4">func (b *Bucket) PutExpire</font>
```
func (b *Bucket) PutExpire(object, uploadFile string, acl ACL, expire time.Time) error
```
文件object并添加文件过期时间

示例：
```
	err := bt.PutExpire("test.go", "/tmp/test.go", sdk.Private, time.Now().Add(60*time.Second))
	if err != nil {
	        return err
	}
```

###<font color="#4682B4">func (b *Bucket) PutSsk</font>
```
func (b *Bucket) PutSsk(object, uploadFile string, acl ACL) (string, error)
```
以ssk的方式上传object, 返回响应header头的x-sina-serverside-key

###<font color="#4682B4">func (b *Bucket) PutAcl</font>
```
func (b *Bucket) PutAcl(object string, acl map[string][]string) error
```   
设置指定object 的acl,当object值为"/"时，设置的是对应bucket的acl， acl格式如下：
```
acl := map[string][]string{
	"SINA000000000000IMGX": []string{"read"},
	"GRPS000000ANONYMOUSE": []string{"read", "read_acp", "write", "write_acp"},
	}
```

###<font color="#4682B4">func (b *Bucket) PutMeta</font>
```
func (b *Bucket) PutMeta(object string, meta map[striring]string) error
```    
更新一个已经存在的object的附加meta信息，这个接口无法更新文件的基本信息，如文件的大小和类型等，meta格式如下： 

	meta := map[string]string{"x-amz-meta-name": "sandbox", "x-amz-meta-age": "13"}
    
###<font color="#4682B4">func (b *Bucket) Copy</font>
```
func (b *Bucket) Copy(dstObject, srcBucket, srcObject string) error
```
过拷贝方式创建object（不上传具体的文件内容,而是通过COPY方式对系统内另一文件进行复制）

###<font color="#4682B4">func (b *Bucket) Relax</font>
```
func (b *Bucket) Relax(object, uploadFile string, acl ACL) error
```
通过“秒传”方式创建Object（不上传具体的文件内容，而是通过SHA-1值对系统内文件进行复制）

###<font color="#4682B4">func (b *Bucket) Del</font>
```
func (b *Bucket) Del(object string) error
```
删除object

###<font color="#4682B4">func (b *Bucket) SignURL</font>
```
func (b *Bucket) SignURL(object string, expires time.Time) string
```
返回带有过期时间的下载签名URL

示例：
```
	uri := bt.SignURL("test.go", time.Now().Add(15*time.Second))
    fmt.Println(uri)
 
	//output: http://url/bucket/test.go?Expires=1479722790&KID=sina%2Cruikuntest&ssig=T233ytgAOv
```

###<font color="#4682B4">func (b *Bucket) URL</font>
```
func (b *Bucket) URL(object string) string
```
返回URL


##<font color="#4682B4">MULTIPART UPLOAD</font>
```
type Multi struct {
    Bucket   *Bucket
    Object   string
    UploadId string
}
```

###<font color="#4682B4">func (b *Bucket) InitMulti</font>
```
func (b *Bucket) InitMulti(object string) (*Multi, error)
```
大文件分片上传初始化，返回Multi类 

注意：在初始化上传接口中要求必须进行用户认证，匿名用户无法使用该接口

在初始化上传时需要给定文件上传所需要的meta绑定信息，在后续的上传中该信息将被保留，并在最终完成时写入云存储系统

###<font color="#4682B4">func (m *Multi) PutPart</font>
```
func (m *Multi) PutPart(uploadFile string, acl ACL, partSize int) ([]part, error)
```
上传分片, 注意：分片数不能超过2048

###<font color="#4682B4">func (m *Multi) ListPart</font>
```
func (m *Multi) ListPart() ([]part, error)
```
列出已经上传的所有分片信息

###<font color="#4682B4">func (m *Multi) Complete</font>
```
func (m *Multi) Complete(partInfo []part) error
```
大文件分片上传拼接（合并）

示例：
```
	multi, err := bt.InitMulti("pict.tar.gz")
	if err != nil {
		return err
	}
	partInfo, err := multi.PutPart("/tmp/pict.tar.gz", sdk.Private, 1024*1024*3)
	if err != nil {
		return err
	}
	listPart, err := multi.ListPart()
	if err != nil {
		return err
	}
	for k, v := range listPart {
		if partInfo[k].ETag != v.ETag {
            return fmt.Errorf("分片不匹配")
		}
	}
	err = multi.Complete(listPart)
	if err != nil {
		return err
	}
```



###<font color="#4682B4">ERROR OPERATION</font>
```
type Error struct {
    StatusCode int
    RequestId  string
    ErrorCode  string
    Date       string
}
```

###<font color="#4682B4">func (e *Error) Error</font>
```
func (e *Error) Error() string
```
