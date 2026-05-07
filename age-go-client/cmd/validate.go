package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var supportedExtensions = map[string]bool{
	".txt":  true,
	".pdf":  true,
	".png":  true,
	".jpg":  true,
	".jpeg": true,
	".zip":  true,
	".tar":  true,
	".gz":   true,
	".mp4":  true,
	".docx": true,
	".xlsx": true,
	".pptx": true,
	".csv":  true,
	".json": true,
	".xml":  true,
	".bin":  true,
	".key":  true,
	".pem":  true,
}

var ageHeader = []byte("age-encryption.org/v1")

func ValidateInputFile(path string, ageFileFlag bool) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", path)
		}

		return fmt.Errorf("no access to file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("%s is directory not file", path)
	}

	if info.Size() == 0 {
		return fmt.Errorf("file %s is empty", path)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ageFileFlag {
		if ext != ".age" {
			return fmt.Errorf("file does not have .age extension: %s", path)
		}

		if !isAgeFile(path) {
			return fmt.Errorf("file has .age extension but it is not valid age file (error in header)")
		}
	} else {
		if ext == ".age" {
			return fmt.Errorf("file is encypt (.age) - use 'decrypt' to decrypt it")
		}

		if isAgeFile(path) {
			return fmt.Errorf("file seems to be encrypted with age despite the lack of an .age extension")
		}

		if !supportedExtensions[ext] && ext != "" {
			fmt.Fprintf(os.Stderr, "Attencion: extension '%s' is not beeing rocognize – encryption will be performed anyway\n", ext)
		}
	}

	return nil
}

func isAgeFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, len(ageHeader))
	n, err := f.Read(buf)
	if err != nil || n < len(ageHeader) {
		return false
	}

	return string(buf) == string(ageHeader)
}
