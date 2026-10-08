package coreinstall

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"path"
	"strconv"
	"strings"
)

func memberOK(a Artifact, name string, size int64, seen map[string]bool) bool {
	allowed, ok := a.members[name]
	if !ok || size != allowed || seen[name] || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || strings.TrimSuffix(name, "/") != path.Clean(name) {
		return false
	}
	seen[name] = true
	return true
}

func copyExact(dst io.Writer, src io.Reader, size int64) error {
	n, e := io.Copy(dst, io.LimitReader(src, size+1))
	if e != nil || n != size {
		return ErrIntegrity
	}
	return nil
}

// extract verifies every member and consumes each body; it only emits the binary.
func extract(a Artifact, src interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}, dst io.Writer) error {
	h := sha256.New()
	out := io.MultiWriter(dst, h)
	seen := map[string]bool{}
	switch a.format {
	case "raw":
		if e := copyExact(out, src, a.BinarySize); e != nil {
			return e
		}
	case "zip":
		z, e := zip.NewReader(src, a.ArchiveSize)
		if e != nil || len(z.File) != len(a.members) {
			return ErrIntegrity
		}
		for _, f := range z.File {
			if f.UncompressedSize64 > uint64(a.BinarySize+40000000) || f.CompressedSize64 > uint64(a.ArchiveSize) || !f.Mode().IsRegular() || (f.Method != zip.Store && f.Method != zip.Deflate) || !memberOK(a, f.Name, int64(f.UncompressedSize64), seen) {
				return ErrIntegrity
			}
			r, e := f.Open()
			if e != nil {
				return ErrIntegrity
			}
			w := io.Writer(io.Discard)
			if f.Name == a.BinaryMember {
				w = out
			}
			e = copyExact(w, r, int64(f.UncompressedSize64))
			ce := r.Close()
			if e != nil || ce != nil {
				return ErrIntegrity
			}
		}
	case "tar.gz":
		compressed := bufio.NewReader(src)
		g, e := gzip.NewReader(compressed)
		if e != nil {
			return ErrIntegrity
		}
		defer g.Close()
		g.Multistream(false)
		// Includes padding/headers and no unbounded decompressed trailer.
		limit := a.BinarySize + 16384
		lr := &io.LimitedReader{R: g, N: limit}
		var header [512]byte
		for {
			if _, e := io.ReadFull(lr, header[:]); e != nil {
				return ErrIntegrity
			}
			if bytes.Equal(header[:], make([]byte, 512)) {
				if _, e := io.ReadFull(lr, header[:]); e != nil || !bytes.Equal(header[:], make([]byte, 512)) {
					return ErrIntegrity
				}
				break
			}
			name, size, dir, e := tarHeader(header[:])
			if e != nil || !memberOK(a, name, size, seen) {
				return ErrIntegrity
			}
			if dir != strings.HasSuffix(name, "/") || (dir && size != 0) {
				return ErrIntegrity
			}
			w := io.Writer(io.Discard)
			if name == a.BinaryMember {
				w = out
			}
			if e := copyExact(w, io.LimitReader(lr, size), size); e != nil {
				return e
			}
			padding := (512 - size%512) % 512
			if padding != 0 {
				if _, e := io.ReadFull(lr, header[:padding]); e != nil {
					return ErrIntegrity
				}
				for _, v := range header[:padding] {
					if v != 0 {
						return ErrIntegrity
					}
				}
			}
		}
		// Finish CRC and bound trailing zero padding. Nonzero trailers are invalid.
		buf := make([]byte, 1024)
		for {
			n, e := lr.Read(buf)
			for _, v := range buf[:n] {
				if v != 0 {
					return ErrIntegrity
				}
			}
			if e == io.EOF {
				break
			}
			if e != nil {
				return ErrIntegrity
			}
			if lr.N == 0 {
				return ErrIntegrity
			}
		}
		if lr.N == 0 {
			return ErrIntegrity
		}
		if _, e := compressed.ReadByte(); e != io.EOF {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	if a.format != "raw" && len(seen) != len(a.members) {
		return ErrIntegrity
	}
	if hex.EncodeToString(h.Sum(nil)) != a.BinarySHA256 {
		return ErrIntegrity
	}
	return nil
}

// Parse only fixed-name regular USTAR/GNU records. Extended headers, sparse
// records, GNU long names, links and PAX are rejected instead of being hidden by
// a general purpose archive reader.
func tarHeader(b []byte) (string, int64, bool, error) {
	field := func(v []byte) (string, bool) {
		if i := bytes.IndexByte(v, 0); i >= 0 {
			for _, c := range v[i:] {
				if c != 0 {
					return "", false
				}
			}
			return string(v[:i]), true
		}
		return string(v), true
	}
	octal := func(v []byte) (int64, error) {
		s := strings.Trim(string(v), "\x00 ")
		if s == "" {
			return 0, ErrIntegrity
		}
		for _, c := range s {
			if c < '0' || c > '7' {
				return 0, ErrIntegrity
			}
		}
		return strconv.ParseInt(s, 8, 64)
	}
	name, ok := field(b[:100])
	if !ok {
		return "", 0, false, ErrIntegrity
	}
	size, e := octal(b[124:136])
	if e != nil || size < 0 {
		return "", 0, false, ErrIntegrity
	}
	expected, e := octal(b[148:156])
	if e != nil {
		return "", 0, false, ErrIntegrity
	}
	sum := int64(0)
	for i, v := range b {
		if i >= 148 && i < 156 {
			sum += 32
		} else {
			sum += int64(v)
		}
	}
	if sum != expected {
		return "", 0, false, ErrIntegrity
	}
	if strings.Trim(string(b[157:257]), "\x00") != "" {
		return "", 0, false, ErrIntegrity
	}
	magic := string(b[257:265])
	switch magic {
	case "ustar\x0000":
		prefix, valid := field(b[345:500])
		if !valid {
			return "", 0, false, ErrIntegrity
		}
		if prefix != "" {
			name = prefix + "/" + name
		}
	case "ustar  \x00":
	default:
		return "", 0, false, ErrIntegrity
	}
	if b[156] != '0' && b[156] != 0 && b[156] != '5' {
		return "", 0, false, ErrIntegrity
	}
	return name, size, b[156] == '5', nil
}

func verifyELF(a Artifact, src io.ReaderAt) error {
	f, e := elf.NewFile(src)
	if e != nil {
		return ErrIntegrity
	}
	defer f.Close()
	m := elf.EM_X86_64
	if a.Arch == "arm64" {
		m = elf.EM_AARCH64
	} else if a.Arch != "amd64" {
		return ErrIntegrity
	}
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != m || f.Type != elf.ET_EXEC {
		return ErrIntegrity
	}
	if len(f.Progs) == 0 || len(f.Progs) > 64 {
		return ErrIntegrity
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC || p.Off > uint64(a.BinarySize) || p.Filesz > uint64(a.BinarySize)-p.Off {
			return ErrIntegrity
		}
	}
	return nil
}
