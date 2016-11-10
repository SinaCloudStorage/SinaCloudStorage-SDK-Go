package sinastoragegosdk

import (
	"log"
)

func ExampleMultUpload() {
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

}

func ExampleSCS_ListObject() {
	scs := &SCS{"accessKey", "secretKey", "Uri"}
	scs.ListObject("bucket", "", "", "", 400)
	scs.ListObject("bucket", "/", "", "", 400)
	scs.ListObject("bucket", "", "pict", "test.go", 400)
}

func ExampleSCS_GetObject() {
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
}
