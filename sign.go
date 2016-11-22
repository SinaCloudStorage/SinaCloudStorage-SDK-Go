package sinastoragegosdk

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"sort"
	"strings"
)

var s3ParamsToSign = map[string]bool{
	"acl":        true,
	"location":   true,
	"logging":    true,
	"relax":      true,
	"meta":       true,
	"torrent":    true,
	"uploads":    true,
	"part":       true,
	"copy":       true,
	"multipart":  true,
	"partNumber": true,
	"uploadId":   true,
	"ip":         true,
}

func sign(scs SCS, method, canonicalizedResource string, parmams, headers map[string][]string) {
	var md5, ctype, date, xsina string
	var harray []string
	for k, v := range headers {
		k = strings.ToLower(k)
		switch k {
		case "content-md5":
			md5 = v[0]
		case "content-type":
			ctype = v[0]
		case "date":
			date = v[0]
		default:
			if strings.HasPrefix(k, "x-amz-") || strings.HasPrefix(k, "x-sina-") {
				vall := strings.Join(v, ",")
				harray = append(harray, k+":"+vall)
			}
		}
	}
	if len(harray) > 0 {
		sort.StringSlice(harray).Sort()
		xsina = strings.Join(harray, "\n") + "\n"
	}
	expires := false
	if v, ok := parmams["Expires"]; ok {
		expires = true
		date = v[0]
		parmams["KID"] = []string{"sina," + scs.AccessKey}
	}
	if _, ok := parmams["relax"]; ok {
		delete(headers, "Content-MD5")
	}

	harray = harray[0:0]
	for k, v := range parmams {
		if s3ParamsToSign[k] {
			for _, vi := range v {
				if vi == "" {
					harray = append(harray, k)
				} else {
					harray = append(harray, k+"="+vi)
				}
			}
		}
	}
	if len(harray) > 0 {
		sort.StringSlice(harray).Sort()
		canonicalizedResource = canonicalizedResource + "?" + strings.Join(harray, "&")
	}
	sig := method + "\n" + md5 + "\n" + ctype + "\n" + date + "\n" + xsina + canonicalizedResource
	mac := hmac.New(sha1.New, []byte(scs.SecretKey))
	mac.Write([]byte(sig))
	ssig := base64.StdEncoding.EncodeToString(mac.Sum(nil))[5:15]
	if expires {
		parmams["ssig"] = []string{ssig}
		headers["Date"] = parmams["Expires"]
	} else {
		headers["Authorization"] = []string{"SINA " + scs.AccessKey + ":" + ssig}
	}
}
