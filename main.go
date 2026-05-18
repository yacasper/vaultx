package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

var version = "dev"

const (
	saltLen         = 32
	nonceLen        = 12
	argonTime       = 3
	argonMem        = 64 * 1024
	argonPara       = 4
	chunkSize       = 64 * 1024
	minPasswordLen  = 6
	progressMinSize = 1 * 1024 * 1024 // show progress bar for files ≥ 1 MB
)

// V1 — legacy in-memory format (read only, kept for backward compat)
// V2 — streaming chunked format (all new encryption)
var magicV1 = []byte("VAULTX\x01")
var magicV2 = []byte("VAULTX\x02")

const (
	algoAES    = byte(0x01)
	algoChacha = byte(0x02)
)

const (
	typeFile = byte(0x00)
	typeDir  = byte(0x01)
)

const (
	chunkMore = byte(0x00)
	chunkLast = byte(0xFF)
)

// ── progress ──────────────────────────────────────────────────────────────────

func formatBytes(n int64) string {
	const (
		KB = int64(1024)
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func printProgress(done, total int64) {
	const w = 20
	pct := float64(done) / float64(total)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * w)
	fmt.Fprintf(os.Stderr, "\r    Progress  : [%s%s] %3.0f%%  %s / %s",
		strings.Repeat("█", filled), strings.Repeat("░", w-filled),
		pct*100, formatBytes(done), formatBytes(total))
}

type progressReader struct {
	r       io.Reader
	read    int64
	total   int64
	enabled bool
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.read += int64(n)
	if p.enabled {
		printProgress(p.read, p.total)
	}
	return n, err
}

func newProgressReader(r io.Reader, src string, enabled bool) (*progressReader, bool) {
	if !term.IsTerminal(int(os.Stderr.Fd())) || src == "-" {
		return nil, false
	}
	info, err := os.Stat(src)
	if err != nil || info.Size() < progressMinSize {
		return nil, false
	}
	return &progressReader{r: r, total: info.Size(), enabled: enabled}, true
}

// ── key derivation ────────────────────────────────────────────────────────────

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMem, argonPara, 32)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ── cipher ────────────────────────────────────────────────────────────────────

func newAEAD(algo byte, key []byte) (cipher.AEAD, error) {
	switch algo {
	case algoAES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case algoChacha:
		return chacha20poly1305.New(key)
	}
	return nil, fmt.Errorf("unknown algorithm: %x", algo)
}

// ── chunk helpers ─────────────────────────────────────────────────────────────

func chunkNonce(base []byte, idx uint64) []byte {
	n := make([]byte, nonceLen)
	copy(n, base)
	for i := 0; i < 8; i++ {
		n[nonceLen-8+i] ^= byte(idx >> (56 - 8*i))
	}
	return n
}

func chunkAAD(idx uint64, flag byte) []byte {
	aad := make([]byte, 9)
	binary.BigEndian.PutUint64(aad, idx)
	aad[8] = flag
	return aad
}

// ── V2 streaming encrypt ──────────────────────────────────────────────────────

func encryptStream(r io.Reader, w io.Writer, password string, algo, contentType byte, onKeyReady func()) error {
	salt := randomBytes(saltLen)
	baseNonce := randomBytes(nonceLen)
	key := deriveKey(password, salt)

	if onKeyReady != nil {
		onKeyReady()
	}

	aead, err := newAEAD(algo, key)
	if err != nil {
		return err
	}

	header := make([]byte, 0, len(magicV2)+1+1+saltLen+nonceLen)
	header = append(header, magicV2...)
	header = append(header, algo, contentType)
	header = append(header, salt...)
	header = append(header, baseNonce...)
	if _, err = w.Write(header); err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	idx := uint64(0)
	prefix := make([]byte, 5)

	for {
		n, readErr := io.ReadFull(r, buf)
		isLast := readErr == io.ErrUnexpectedEOF || readErr == io.EOF
		if readErr != nil && !isLast {
			return readErr
		}

		flag := chunkMore
		if isLast {
			flag = chunkLast
		}

		ct := aead.Seal(nil, chunkNonce(baseNonce, idx), buf[:n], chunkAAD(idx, flag))
		prefix[0] = flag
		binary.BigEndian.PutUint32(prefix[1:], uint32(len(ct)))

		if _, err = w.Write(prefix); err != nil {
			return err
		}
		if _, err = w.Write(ct); err != nil {
			return err
		}
		idx++

		if isLast {
			break
		}
	}
	return nil
}

// ── V2 streaming decrypt ──────────────────────────────────────────────────────

type streamMeta struct {
	algo        byte
	contentType byte
	aead        cipher.AEAD
	baseNonce   []byte
}

func parseV2Header(r io.Reader, password string, onKeyReady func()) (*streamMeta, error) {
	headerLen := len(magicV2) + 1 + 1 + saltLen + nonceLen
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("not a vaultx file or corrupted header")
	}
	if string(header[:len(magicV2)]) != string(magicV2) {
		return nil, fmt.Errorf("not a vaultx file or corrupted header")
	}

	off := len(magicV2)
	algo := header[off]
	off++
	contentType := header[off]
	off++
	salt := header[off : off+saltLen]
	off += saltLen
	baseNonce := make([]byte, nonceLen)
	copy(baseNonce, header[off:])

	key := deriveKey(password, salt)

	if onKeyReady != nil {
		onKeyReady()
	}

	aead, err := newAEAD(algo, key)
	if err != nil {
		return nil, err
	}

	return &streamMeta{algo: algo, contentType: contentType, aead: aead, baseNonce: baseNonce}, nil
}

// decryptChunks reads V2 chunks from r and writes plaintext to w.
// Pass io.Discard to verify without writing.
func decryptChunks(r io.Reader, w io.Writer, m *streamMeta) error {
	prefix := make([]byte, 5)
	idx := uint64(0)

	for {
		if _, err := io.ReadFull(r, prefix); err != nil {
			return fmt.Errorf("not a vaultx file or corrupted header")
		}
		flag := prefix[0]
		chunkLen := binary.BigEndian.Uint32(prefix[1:])

		ct := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("not a vaultx file or corrupted header")
		}

		plain, err := m.aead.Open(nil, chunkNonce(m.baseNonce, idx), ct, chunkAAD(idx, flag))
		if err != nil {
			return fmt.Errorf("wrong password or corrupted file")
		}

		if len(plain) > 0 {
			if _, err = w.Write(plain); err != nil {
				return err
			}
		}

		idx++
		if flag == chunkLast {
			break
		}
	}
	return nil
}

// ── V1 legacy (backward compat decrypt) ──────────────────────────────────────

func encryptBytesV1(plaintext []byte, password string, algo byte) ([]byte, error) {
	salt := randomBytes(saltLen)
	nonce := randomBytes(nonceLen)
	key := deriveKey(password, salt)

	aead, err := newAEAD(algo, key)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(magicV1)+1+saltLen+nonceLen+len(ciphertext))
	out = append(out, magicV1...)
	out = append(out, algo)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptBytesV1(raw []byte, password string) ([]byte, error) {
	minLen := len(magicV1) + 1 + saltLen + nonceLen
	if len(raw) < minLen || string(raw[:len(magicV1)]) != string(magicV1) {
		return nil, fmt.Errorf("not a vaultx file or corrupted header")
	}

	offset := len(magicV1)
	algo := raw[offset]
	offset++
	salt := raw[offset : offset+saltLen]
	offset += saltLen
	nonce := raw[offset : offset+nonceLen]
	offset += nonceLen
	ciphertext := raw[offset:]

	key := deriveKey(password, salt)
	aead, err := newAEAD(algo, key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong password or corrupted file")
	}
	return plaintext, nil
}

// ── I/O helpers ───────────────────────────────────────────────────────────────

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func openInput(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

func openOutput(path string) (io.WriteCloser, error) {
	if path == "-" {
		return nopWriteCloser{os.Stdout}, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
}

// ── encrypt file / directory ──────────────────────────────────────────────────

func encryptFile(src, dst, password string, algo byte, shred, armor bool, onKeyReady func()) error {
	return encryptFileAs(src, dst, password, algo, shred, armor, typeFile, onKeyReady)
}

func encryptFileAs(src, dst, password string, algo byte, shred, armor bool, contentType byte, onKeyReady func()) error {
	r, err := openInput(src)
	if err != nil {
		return err
	}
	defer r.Close()

	var reader io.Reader = r
	pr, hasProgress := newProgressReader(r, src, true)
	if hasProgress {
		reader = pr
	}

	w, err := openOutput(dst)
	if err != nil {
		return err
	}

	if armor {
		enc := base64.NewEncoder(base64.StdEncoding, w)
		err = encryptStream(reader, enc, password, algo, contentType, onKeyReady)
		enc.Close()
	} else {
		err = encryptStream(reader, w, password, algo, contentType, onKeyReady)
	}
	w.Close()

	if hasProgress {
		fmt.Fprintln(os.Stderr)
	}

	if err != nil {
		if dst != "-" {
			os.Remove(dst)
		}
		return err
	}

	if shred && src != "-" {
		return shredFile(src)
	}
	return nil
}

func encryptDirectory(src, dst, password string, algo byte, shred, armor bool, onKeyReady func()) error {
	tmp, err := os.CreateTemp("", "vaultx-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	zw := zip.NewWriter(tmp)
	srcAbs, _ := filepath.Abs(src)
	parentDir := filepath.Dir(srcAbs)

	err = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(parentDir, path)
		w, e := zw.Create(rel)
		if e != nil {
			return e
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = io.Copy(w, f)
		return e
	})
	zw.Close()
	tmp.Close()
	if err != nil {
		return err
	}

	if err = encryptFileAs(tmpPath, dst, password, algo, false, armor, typeDir, onKeyReady); err != nil {
		return err
	}

	if shred {
		shredErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			return shredFile(path)
		})
		if shredErr != nil {
			return shredErr
		}
		return os.RemoveAll(src)
	}
	return nil
}

// ── decrypt file ──────────────────────────────────────────────────────────────

func decryptFile(src, dst, password string, armor bool, onKeyReady func()) error {
	r, err := openInput(src)
	if err != nil {
		return err
	}
	defer r.Close()

	var raw io.Reader = r
	if armor {
		raw = base64.NewDecoder(base64.StdEncoding, r)
	}

	peek := make([]byte, len(magicV1))
	if _, err = io.ReadFull(raw, peek); err != nil {
		return fmt.Errorf("not a vaultx file or corrupted header")
	}
	combined := io.MultiReader(bytes.NewReader(peek), raw)

	pr, hasProgress := newProgressReader(r, src, false)
	if hasProgress {
		combined = io.MultiReader(bytes.NewReader(peek), pr)
		origOnKeyReady := onKeyReady
		onKeyReady = func() {
			if origOnKeyReady != nil {
				origOnKeyReady()
			}
			pr.enabled = true
		}
	}

	var decErr error
	switch string(peek) {
	case string(magicV2):
		decErr = decryptFileV2(combined, dst, password, onKeyReady)
	case string(magicV1):
		if onKeyReady != nil {
			onKeyReady()
		}
		decErr = decryptFileV1(combined, dst, password)
	default:
		return fmt.Errorf("not a vaultx file or corrupted header")
	}

	if hasProgress {
		fmt.Fprintln(os.Stderr)
	}
	return decErr
}

func decryptFileV2(r io.Reader, dst, password string, onKeyReady func()) error {
	m, err := parseV2Header(r, password, onKeyReady)
	if err != nil {
		return err
	}

	if dst == "-" {
		return decryptChunks(r, os.Stdout, m)
	}

	if m.contentType == typeDir {
		var buf bytes.Buffer
		if err = decryptChunks(r, &buf, m); err != nil {
			return err
		}
		return decryptToDirectory(buf.Bytes(), dst)
	}

	// Stream to temp file; rename on success to avoid partial output.
	tmp := dst + ".vxtmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err = decryptChunks(r, f, m); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, dst)
}

func decryptFileV1(r io.Reader, dst, password string) error {
	all, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	plain, err := decryptBytesV1(all, password)
	if err != nil {
		return err
	}
	if isZip(plain) {
		return decryptToDirectory(plain, dst)
	}
	if dst == "-" {
		_, err = os.Stdout.Write(plain)
		return err
	}
	return os.WriteFile(dst, plain, 0600)
}

// ── directory extraction ──────────────────────────────────────────────────────

func decryptToDirectory(plaintext []byte, dst string) error {
	tmp, err := os.CreateTemp("", "vaultx-dec-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err = tmp.Write(plaintext); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	zr, err := zip.OpenReader(tmpPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	if err = os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	for _, f := range zr.File {
		outPath := filepath.Join(dst, filepath.Clean("/"+f.Name))
		if err = os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(outPath)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ── secure delete ─────────────────────────────────────────────────────────────

func shredFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	size := info.Size()
	buf := make([]byte, size)
	for i := 0; i < 3; i++ {
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			break
		}
		if _, err = rand.Read(buf); err != nil {
			break
		}
		f.Write(buf)
		f.Sync()
	}
	f.Close()
	return os.Remove(path)
}

// ── password prompt ───────────────────────────────────────────────────────────

func promptPassword(confirm bool) (string, error) {
	fmt.Fprint(os.Stderr, "🔑  Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(pw) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	if len(pw) < minPasswordLen {
		return "", fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if confirm {
		fmt.Fprint(os.Stderr, "🔑  Confirm password: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(pw) != string(pw2) {
			return "", fmt.Errorf("passwords do not match")
		}
	}
	return string(pw), nil
}

func validatePassword(pw string) error {
	if len(pw) == 0 {
		return fmt.Errorf("password cannot be empty")
	}
	if len(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func algoName(b byte) string {
	switch b {
	case algoAES:
		return "AES-256-GCM"
	case algoChacha:
		return "ChaCha20-Poly1305"
	}
	return "Unknown"
}

func isZip(data []byte) bool {
	return len(data) > 4 &&
		data[0] == 0x50 && data[1] == 0x4B &&
		data[2] == 0x03 && data[3] == 0x04
}

// ── commands ──────────────────────────────────────────────────────────────────

func cmdEncrypt(args []string) {
	fs := pflag.NewFlagSet("encrypt", pflag.ExitOnError)
	output := fs.StringP("output", "o", "", "Output path (default: <input>.vx, or stdout if input is -)")
	algoStr := fs.String("algo", "aes256gcm", "Algorithm: aes256gcm or chacha20")
	shred := fs.Bool("shred", false, "Securely delete original after encryption")
	armor := fs.Bool("armor", false, "Base64-encode output (text-safe transport)")
	password := fs.StringP("password", "p", "", "Password (insecure — prefer interactive prompt)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "❌  Usage: vaultx encrypt <file|dir|-> [options]")
		os.Exit(1)
	}

	src := fs.Arg(0)

	var isDir bool
	if src != "-" {
		info, err := os.Stat(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌  Not found: %s\n", src)
			os.Exit(1)
		}
		isDir = info.IsDir()
	}

	var algo byte
	switch *algoStr {
	case "aes256gcm":
		algo = algoAES
	case "chacha20":
		algo = algoChacha
	default:
		fmt.Fprintln(os.Stderr, "❌  Unknown algorithm. Use: aes256gcm or chacha20")
		os.Exit(1)
	}

	dst := *output
	if dst == "" {
		if src == "-" {
			dst = "-"
		} else if isDir {
			dst = strings.TrimSuffix(src, string(os.PathSeparator)) + ".vx"
		} else {
			dst = src + ".vx"
		}
	}

	var err error
	pw := *password
	if pw == "" {
		pw, err = promptPassword(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌  %v\n", err)
			os.Exit(1)
		}
	} else if err = validatePassword(pw); err != nil {
		fmt.Fprintf(os.Stderr, "❌  %v\n", err)
		os.Exit(1)
	}

	kind := "file"
	if isDir {
		kind = "directory"
	} else if src == "-" {
		kind = "stdin"
	}
	fmt.Fprintf(os.Stderr, "🔐  Encrypting %s: %s\n", kind, src)
	fmt.Fprintf(os.Stderr, "    Algorithm : %s\n", algoName(algo))
	fmt.Fprintf(os.Stderr, "    KDF       : Argon2id (time=%d, mem=%dMB, p=%d)\n", argonTime, argonMem/1024, argonPara)
	fmt.Fprintf(os.Stderr, "    Output    : %s\n", dst)
	if *shred {
		fmt.Fprintln(os.Stderr, "    Shred     : yes (original will be securely deleted)")
	}
	fmt.Fprint(os.Stderr, "    Deriving key… ")

	onKeyReady := func() { fmt.Fprintln(os.Stderr, "done.") }

	if isDir {
		err = encryptDirectory(src, dst, pw, algo, *shred, *armor, onKeyReady)
	} else {
		err = encryptFile(src, dst, pw, algo, *shred, *armor, onKeyReady)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌  Error: %v\n", err)
		os.Exit(1)
	}

	if dst != "-" {
		fmt.Printf("✅  Saved to: %s\n", dst)
	}
}

func cmdDecrypt(args []string) {
	fs := pflag.NewFlagSet("decrypt", pflag.ExitOnError)
	output := fs.StringP("output", "o", "", "Output path (default: strip .vx, or stdout if input is -)")
	armor := fs.Bool("armor", false, "Input is base64-armored")
	password := fs.StringP("password", "p", "", "Password (insecure — prefer interactive prompt)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "❌  Usage: vaultx decrypt <file.vx|-> [options]")
		os.Exit(1)
	}

	src := fs.Arg(0)
	if src != "-" {
		if _, err := os.Stat(src); err != nil {
			fmt.Fprintf(os.Stderr, "❌  Not found: %s\n", src)
			os.Exit(1)
		}
	}

	dst := *output
	if dst == "" {
		if src == "-" {
			dst = "-"
		} else if strings.HasSuffix(src, ".vx") {
			dst = src[:len(src)-3]
		} else {
			dst = src + ".dec"
		}
	}

	var err error
	pw := *password
	if pw == "" {
		pw, err = promptPassword(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌  %v\n", err)
			os.Exit(1)
		}
	} else if err = validatePassword(pw); err != nil {
		fmt.Fprintf(os.Stderr, "❌  %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "🔓  Decrypting: %s\n", src)
	fmt.Fprintf(os.Stderr, "    Output    : %s\n", dst)
	fmt.Fprint(os.Stderr, "    Deriving key… ")

	onKeyReady := func() { fmt.Fprintln(os.Stderr, "done.") }

	if err = decryptFile(src, dst, pw, *armor, onKeyReady); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌  %v\n", err)
		os.Exit(1)
	}

	if dst != "-" {
		fmt.Printf("✅  Saved to: %s\n", dst)
	}
}

func cmdVerify(args []string) {
	fs := pflag.NewFlagSet("verify", pflag.ExitOnError)
	armor := fs.Bool("armor", false, "File is base64-armored")
	password := fs.StringP("password", "p", "", "Password (insecure — prefer interactive prompt)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "❌  Usage: vaultx verify <file.vx>")
		os.Exit(1)
	}

	src := fs.Arg(0)
	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(os.Stderr, "❌  Not found: %s\n", src)
		os.Exit(1)
	}

	var err error
	pw := *password
	if pw == "" {
		pw, err = promptPassword(false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌  %v\n", err)
			os.Exit(1)
		}
	} else if err = validatePassword(pw); err != nil {
		fmt.Fprintf(os.Stderr, "❌  %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "🔍  Verifying: %s\n", src)

	f, err := os.Open(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌  %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var raw io.Reader = f
	if *armor {
		raw = base64.NewDecoder(base64.StdEncoding, f)
	}

	peek := make([]byte, len(magicV1))
	if _, err = io.ReadFull(raw, peek); err != nil {
		fmt.Fprintln(os.Stderr, "❌  Not a vaultx file.")
		os.Exit(1)
	}
	combined := io.MultiReader(bytes.NewReader(peek), raw)

	pr, hasProgress := newProgressReader(f, src, false)
	if hasProgress {
		combined = io.MultiReader(bytes.NewReader(peek), pr)
	}

	switch string(peek) {
	case string(magicV2):
		fmt.Fprint(os.Stderr, "    Deriving key… ")
		verifyOnKeyReady := func() {
			fmt.Fprintln(os.Stderr, "done.")
			if hasProgress {
				pr.enabled = true
			}
		}
		m, err := parseV2Header(combined, pw, verifyOnKeyReady)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n❌  %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "    Algorithm : %s\n", algoName(m.algo))
		fmt.Fprint(os.Stderr, "    Integrity… ")
		if err = decryptChunks(combined, io.Discard, m); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌  %v\n", err)
			os.Exit(1)
		}
		if hasProgress {
			fmt.Fprintln(os.Stderr)
		} else {
			fmt.Fprintln(os.Stderr, "ok.")
		}

	case string(magicV1):
		fmt.Fprint(os.Stderr, "    Deriving key and verifying… ")
		all, err := io.ReadAll(combined)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n❌  %v\n", err)
			os.Exit(1)
		}
		if _, err = decryptBytesV1(all, pw); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌  %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "done.")
		fmt.Fprintf(os.Stderr, "    Algorithm : %s (legacy v1)\n", algoName(all[len(magicV1)]))

	default:
		fmt.Fprintln(os.Stderr, "❌  Not a vaultx file.")
		os.Exit(1)
	}

	fmt.Println("✅  Password correct. File integrity verified.")
}

func cmdInfo(args []string) {
	fs := pflag.NewFlagSet("info", pflag.ExitOnError)
	armor := fs.Bool("armor", false, "File is base64-armored")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "❌  Usage: vaultx info <file.vx>")
		os.Exit(1)
	}

	src := fs.Arg(0)
	raw, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌  Not found: %s\n", src)
		os.Exit(1)
	}

	if *armor {
		raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			fmt.Fprintln(os.Stderr, "❌  Invalid base64 armor.")
			os.Exit(1)
		}
	}

	info, _ := os.Stat(src)
	fmt.Printf("📄  File      : %s\n", src)
	fmt.Printf("    Size      : %d bytes\n", info.Size())
	fmt.Printf("    Armored   : %v\n", *armor)

	switch {
	case len(raw) > len(magicV2) && string(raw[:len(magicV2)]) == string(magicV2):
		algo := raw[len(magicV2)]
		ct := raw[len(magicV2)+1]
		fmt.Printf("    Format    : vaultx v2 (streaming)\n")
		fmt.Printf("    Algorithm : %s\n", algoName(algo))
		if ct == typeDir {
			fmt.Printf("    Content   : directory\n")
		} else {
			fmt.Printf("    Content   : file\n")
		}
	case len(raw) > len(magicV1) && string(raw[:len(magicV1)]) == string(magicV1):
		algo := raw[len(magicV1)]
		fmt.Printf("    Format    : vaultx v1 (legacy)\n")
		fmt.Printf("    Algorithm : %s\n", algoName(algo))
	default:
		fmt.Fprintln(os.Stderr, "❌  Not a valid vaultx file.")
		os.Exit(1)
	}
}

// ── entry point ───────────────────────────────────────────────────────────────

func usage() {
	fmt.Print(`🔐  vaultx — cross-platform file encryption utility

Usage:
  vaultx encrypt <file|dir|->  [--algo aes256gcm|chacha20] [--shred] [--armor] [-p password] [-o output]
  vaultx decrypt <file.vx|->   [-o output] [--armor] [-p password]
  vaultx verify  <file.vx>     [--armor] [-p password]
  vaultx info    <file.vx>     [--armor]
  vaultx version

Aliases: e = encrypt, d = decrypt, ver = verify, i = info, v = version

Examples:
  vaultx encrypt secret.pdf
  vaultx encrypt notes/ -o vault.vx
  vaultx encrypt photo.jpg --algo chacha20
  vaultx encrypt report.pdf --shred
  vaultx encrypt msg.txt --armor
  cat secret.txt | vaultx encrypt - | vaultx decrypt -
  vaultx decrypt secret.pdf.vx
  vaultx decrypt vault.vx -o restored/
  vaultx verify  secret.pdf.vx
  vaultx info    secret.pdf.vx
  vaultx version
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "encrypt", "e":
		cmdEncrypt(os.Args[2:])
	case "decrypt", "d":
		cmdDecrypt(os.Args[2:])
	case "verify", "ver":
		cmdVerify(os.Args[2:])
	case "info", "i":
		cmdInfo(os.Args[2:])
	case "version", "v", "--version", "-v":
		fmt.Printf("vaultx %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "❌  Unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
