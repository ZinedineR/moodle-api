package errs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"runtime"
	"strings"
)

var (
	dunno      = []byte("???")
	slash      = []byte("/")
	dot        = []byte(".")
	centerDot  = []byte(".")
	pathPrefix = "/go/src/github.com/ZinedineR/moodle-api"
)

func StackAndFile(skip int) (string, string) {
	buf := new(bytes.Buffer)

	var (
		lines     [][]byte
		lastFile  string
		firstFile string
	)

	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}

		if firstFile == "" {
			firstFile = strings.ReplaceAll(fmt.Sprintf("%s:%d", file, line), pathPrefix, "...")
		}

		if strings.Contains(file, "gin-gonix/gin@v1.4.0/context.go") ||
			strings.Contains(file, "net/http/server.go") {

			break
		}

		fmt.Fprintf(buf, "%s:%d\n", file, line)
		if file != lastFile {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				continue
			}
			lines = bytes.Split(data, []byte{'\n'})
			lastFile = file
		}
		fmt.Fprintf(buf, "\t%s: %s\n", function(pc), source(lines, line))
	}

	return strings.ReplaceAll(buf.String(), pathPrefix, "..."), firstFile

}

func function(pc uintptr) []byte {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return dunno
	}
	name := []byte(fn.Name())

	if lastSlash := bytes.LastIndex(name, slash); lastSlash >= 0 {
		name = name[lastSlash+1:]
	}
	if period := bytes.Index(name, dot); period >= 0 {
		name = name[period+1:]
	}
	name = bytes.Replace(name, centerDot, dot, -1)
	return name
}

func source(lines [][]byte, n int) []byte {
	n--

	if n < 0 || n >= len(lines) {
		return dunno
	}

	return bytes.TrimSpace(lines[n])
}
