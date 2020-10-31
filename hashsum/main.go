package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"
)

var errUnknownAlgorithm = fmt.Errorf("unknown algorithm")

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `hashsum usage:

hashsum [option]... [algorithm]... [file]...

Prints checksums. When '-' or no files are specified, standard input is read.

Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), `
Supported algorithms:
	md4, md5, sha1, sha224, sha256, sha384, sha512, sha512/224, sha512/256,
	sha3-224, sha3-256, sha3-384, sha3-512, blake2s-256, blake2b-256,
	blake2b-384, blake2b-512 and aliases`)
	}
	flag.Int("hello", 0, "help")
	flag.Parse()
}

func main() {
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	var filesStart int = 1
	for i, arg := range args {
		if _, err := parseAlgArg(arg); err == errUnknownAlgorithm {
			filesStart = i
			break
		} else if err != nil {
			panic(fmt.Errorf("error creating %v hasher: %w", arg, err))
		}
	}
	algorithms := args[:filesStart]
	filenames := args[filesStart:]

	if len(algorithms) == 0 {
		panic(fmt.Errorf("you must specify at least one hash function"))
	}
	if len(filenames) == 0 {
		// If no filename is specified, default to stdin
		filenames = []string{"-"}
	}

	files := make([]io.Reader, len(filenames))
	for i, filename := range filenames {
		if filename == "-" {
			// '-' represents stdin
			files[i] = os.Stdin
		} else if f, err := os.Open(filename); err != nil {
			panic(fmt.Errorf("error opening file %v: %w", filename, err))
		} else {
			defer f.Close()
			files[i] = f
		}
	}

	for i, file := range files {
		hashers := make([]io.Writer, len(algorithms))
		for i, algString := range algorithms {
			hash, err := parseAlgArg(algString)
			if err != nil {
				panic(fmt.Errorf("error creating %v hasher: %w", algString, err))
			}
			hashers[i] = hash
		}

		w := io.MultiWriter(hashers...)
		io.Copy(w, file)

		for _, hasher := range hashers {
			h, _ := hasher.(hash.Hash)
			fmt.Printf("%x  %v\n", h.Sum(nil), filenames[i])
		}
	}
}

func parseAlgArg(alg string) (hash.Hash, error) {
	switch strings.ToLower(alg) {
	case "md4":
		return md4.New(), nil
	case "md5":
		return md5.New(), nil
	case "sha1", "sha-1":
		return sha1.New(), nil
	case "sha224", "sha2-224":
		return sha256.New224(), nil
	case "sha256", "sha2-256":
		return sha256.New(), nil
	case "sha384", "sha2-384":
		return sha512.New384(), nil
	case "sha512", "sha2-512":
		return sha512.New(), nil
	case "sha512/224", "sha2-512/224":
		return sha512.New512_224(), nil
	case "sha512/256", "sha2-512/256":
		return sha512.New512_256(), nil
	case "sha3-224":
		return sha3.New224(), nil
	case "sha3-256":
		return sha3.New256(), nil
	case "sha3-384":
		return sha3.New384(), nil
	case "sha3-512":
		return sha3.New512(), nil
	case "blake2s-256":
		return blake2s.New256(nil)
	case "blake2b-256":
		return blake2b.New256(nil)
	case "blake2b-384":
		return blake2b.New384(nil)
	case "blake2b-512":
		return blake2b.New512(nil)
	}
	return nil, errUnknownAlgorithm
}
