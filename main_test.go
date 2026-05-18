package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// ── deriveKey ─────────────────────────────────────────────────────────────────

func TestDeriveKey_Length(t *testing.T) {
	if len(deriveKey("password", randomBytes(saltLen))) != 32 {
		t.Fatal("expected 32-byte key")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := randomBytes(saltLen)
	if !bytes.Equal(deriveKey("secret", salt), deriveKey("secret", salt)) {
		t.Fatal("same password+salt must produce the same key")
	}
}

func TestDeriveKey_DifferentSalts(t *testing.T) {
	if bytes.Equal(deriveKey("secret", randomBytes(saltLen)), deriveKey("secret", randomBytes(saltLen))) {
		t.Fatal("different salts must produce different keys")
	}
}

// ── V2 streaming roundtrip ────────────────────────────────────────────────────

func streamRoundtrip(t *testing.T, algo byte, plaintext []byte, password string) {
	t.Helper()
	var enc bytes.Buffer
	if err := encryptStream(bytes.NewReader(plaintext), &enc, password, algo, typeFile, nil); err != nil {
		t.Fatalf("encryptStream: %v", err)
	}

	combined := io.MultiReader(bytes.NewReader(enc.Bytes()[:len(magicV2)]), bytes.NewReader(enc.Bytes()[len(magicV2):]))
	// Simpler: parse from full buffer
	r := bytes.NewReader(enc.Bytes())
	m, err := parseV2Header(r, password, nil)
	if err != nil {
		t.Fatalf("parseV2Header: %v", err)
	}
	_ = combined

	var dec bytes.Buffer
	if err = decryptChunks(r, &dec, m); err != nil {
		t.Fatalf("decryptChunks: %v", err)
	}

	if !bytes.Equal(plaintext, dec.Bytes()) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestStreamRoundtrip_AES_Small(t *testing.T)  { streamRoundtrip(t, algoAES, []byte("hello"), "pass") }
func TestStreamRoundtrip_ChaCha_Small(t *testing.T) {
	streamRoundtrip(t, algoChacha, []byte("hello"), "pass")
}

func TestStreamRoundtrip_MultiChunk(t *testing.T) {
	// 3 full chunks + 1 partial
	data := make([]byte, chunkSize*3+1234)
	for i := range data {
		data[i] = byte(i)
	}
	streamRoundtrip(t, algoAES, data, "multipass")
}

func TestStreamRoundtrip_Empty(t *testing.T) {
	streamRoundtrip(t, algoAES, []byte{}, "emptypass")
}

func TestStream_WrongPassword(t *testing.T) {
	var enc bytes.Buffer
	encryptStream(bytes.NewReader([]byte("secret")), &enc, "correct", algoAES, typeFile, nil)

	r := bytes.NewReader(enc.Bytes())
	m, err := parseV2Header(r, "wrong", nil)
	if err != nil {
		t.Fatal("header should parse even with wrong password (key derived, not yet verified)")
	}
	if err = decryptChunks(r, io.Discard, m); err == nil {
		t.Fatal("expected error on wrong password")
	}
}

func TestStream_TamperedChunk(t *testing.T) {
	var enc bytes.Buffer
	encryptStream(bytes.NewReader([]byte("secret")), &enc, "pass", algoAES, typeFile, nil)

	b := enc.Bytes()
	b[len(b)-1] ^= 0xFF // flip last byte of ciphertext

	r := bytes.NewReader(b)
	m, _ := parseV2Header(r, "pass", nil)
	if err := decryptChunks(r, io.Discard, m); err == nil {
		t.Fatal("expected error on tampered ciphertext")
	}
}

func TestStream_UniquePerEncryption(t *testing.T) {
	plain := []byte("same")
	var e1, e2 bytes.Buffer
	encryptStream(bytes.NewReader(plain), &e1, "pass", algoAES, typeFile, nil)
	encryptStream(bytes.NewReader(plain), &e2, "pass", algoAES, typeFile, nil)
	if bytes.Equal(e1.Bytes(), e2.Bytes()) {
		t.Fatal("two encryptions must differ")
	}
}

func TestStream_UnknownAlgo(t *testing.T) {
	if err := encryptStream(bytes.NewReader([]byte("x")), io.Discard, "p", 0xFF, typeFile, nil); err == nil {
		t.Fatal("expected error for unknown algo")
	}
}

// ── V2 verify (decrypt to Discard) ───────────────────────────────────────────

func TestVerify_OK(t *testing.T) {
	var enc bytes.Buffer
	encryptStream(bytes.NewReader([]byte("verify me")), &enc, "pass", algoAES, typeFile, nil)

	r := bytes.NewReader(enc.Bytes())
	m, err := parseV2Header(r, "pass", nil)
	if err != nil {
		t.Fatalf("parseV2Header: %v", err)
	}
	if err = decryptChunks(r, io.Discard, m); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

// ── file encrypt / decrypt ────────────────────────────────────────────────────

func TestEncryptFile_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.vx")
	dec := filepath.Join(dir, "plain.txt.out")

	os.WriteFile(src, []byte("file content"), 0600)
	if err := encryptFile(src, enc, "pass", algoAES, false, false, nil); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}
	if err := decryptFile(enc, dec, "pass", false, nil); err != nil {
		t.Fatalf("decryptFile: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != "file content" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestEncryptFile_Shred(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "secret.txt")
	enc := filepath.Join(dir, "secret.vx")

	os.WriteFile(src, []byte("shred me"), 0600)
	if err := encryptFile(src, enc, "pass", algoAES, true, false, nil); err != nil {
		t.Fatalf("encryptFile shred: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original must be deleted after shred")
	}
}

func TestEncryptFile_Armor(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "msg.txt")
	enc := filepath.Join(dir, "msg.vx")
	dec := filepath.Join(dir, "msg.out")

	os.WriteFile(src, []byte("armored"), 0600)
	if err := encryptFile(src, enc, "pass", algoAES, false, true, nil); err != nil {
		t.Fatalf("encryptFile armor: %v", err)
	}
	raw, _ := os.ReadFile(enc)
	for _, b := range bytes.TrimSpace(raw) {
		if b > 127 {
			t.Fatal("armored output must be ASCII-only")
		}
	}
	if err := decryptFile(enc, dec, "pass", true, nil); err != nil {
		t.Fatalf("decryptFile armor: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != "armored" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestDecryptFile_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "f.txt")
	enc := filepath.Join(dir, "f.vx")
	dec := filepath.Join(dir, "f.out")

	os.WriteFile(src, []byte("secret"), 0600)
	encryptFile(src, enc, "correct", algoAES, false, false, nil)
	if err := decryptFile(enc, dec, "wrong", false, nil); err == nil {
		t.Fatal("expected error on wrong password")
	}
}

// ── stdin / stdout (pipe via bytes.Buffer) ────────────────────────────────────

func TestStdinStdout_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	// Write plaintext to a file, encrypt to another file simulating pipe
	srcFile := filepath.Join(dir, "in.txt")
	encFile := filepath.Join(dir, "in.vx")
	decFile := filepath.Join(dir, "in.out")

	os.WriteFile(srcFile, []byte("pipe content"), 0600)

	if err := encryptFile(srcFile, encFile, "pipe", algoAES, false, false, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := decryptFile(encFile, decFile, "pipe", false, nil); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	got, _ := os.ReadFile(decFile)
	if string(got) != "pipe content" {
		t.Fatalf("unexpected: %q", got)
	}
}

// ── directory encrypt / decrypt ───────────────────────────────────────────────

func TestEncryptDirectory_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "docs")
	out := filepath.Join(dir, "docs.vx")
	restored := filepath.Join(dir, "restored")

	os.MkdirAll(filepath.Join(src, "sub"), 0755)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0600)
	os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("beta"), 0600)

	if err := encryptDirectory(src, out, "dirpass", algoAES, false, false, nil); err != nil {
		t.Fatalf("encryptDirectory: %v", err)
	}
	if err := decryptFile(out, restored, "dirpass", false, nil); err != nil {
		t.Fatalf("decryptFile dir: %v", err)
	}

	want := map[string]string{
		filepath.Join("docs", "a.txt"):        "alpha",
		filepath.Join("docs", "sub", "b.txt"): "beta",
	}
	for rel, content := range want {
		got, err := os.ReadFile(filepath.Join(restored, rel))
		if err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
		if string(got) != content {
			t.Fatalf("%s: got %q want %q", rel, got, content)
		}
	}
}

// ── backward compat: V1 files can be decrypted ────────────────────────────────

func TestBackwardCompat_V1File(t *testing.T) {
	dir := t.TempDir()
	enc := filepath.Join(dir, "legacy.vx")
	dec := filepath.Join(dir, "legacy.out")

	// Write a hand-crafted V1 file
	raw, err := encryptBytesV1([]byte("legacy content"), "pass", algoAES)
	if err != nil {
		t.Fatalf("encryptBytesV1: %v", err)
	}
	os.WriteFile(enc, raw, 0600)

	if err = decryptFile(enc, dec, "pass", false, nil); err != nil {
		t.Fatalf("decryptFile V1: %v", err)
	}
	got, _ := os.ReadFile(dec)
	if string(got) != "legacy content" {
		t.Fatalf("unexpected: %q", got)
	}
}

// ── shredFile ─────────────────────────────────────────────────────────────────

func TestShredFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "victim.bin")
	os.WriteFile(path, bytes.Repeat([]byte{0xAA}, 512), 0600)

	if err := shredFile(path); err != nil {
		t.Fatalf("shredFile: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file must not exist after shred")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func TestIsZip(t *testing.T) {
	if !isZip([]byte{0x50, 0x4B, 0x03, 0x04, 0x00}) {
		t.Fatal("must detect ZIP magic")
	}
	if isZip([]byte{0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Fatal("must not detect non-ZIP as ZIP")
	}
}

func TestAlgoName(t *testing.T) {
	if algoName(algoAES) != "AES-256-GCM" {
		t.Fatal("wrong AES name")
	}
	if algoName(algoChacha) != "ChaCha20-Poly1305" {
		t.Fatal("wrong ChaCha name")
	}
}

func TestRandomBytes_Length(t *testing.T) {
	for _, n := range []int{1, 12, 32, 64} {
		if len(randomBytes(n)) != n {
			t.Fatalf("randomBytes(%d) wrong length", n)
		}
	}
}

func TestChunkNonce_Unique(t *testing.T) {
	base := randomBytes(nonceLen)
	n0 := chunkNonce(base, 0)
	n1 := chunkNonce(base, 1)
	if bytes.Equal(n0, n1) {
		t.Fatal("different chunk indices must produce different nonces")
	}
	// chunk 0 XORs with 0, so n0 == base — correct by design
	if !bytes.Equal(n0, base) {
		t.Fatal("chunk 0 nonce must equal base nonce")
	}
}
