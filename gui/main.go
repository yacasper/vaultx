package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func findVaultx() string {
	exe, err := os.Executable()
	if err == nil {
		name := "vaultx"
		if runtime.GOOS == "windows" {
			name = "vaultx.exe"
		}
		candidate := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("vaultx"); err == nil {
		return path
	}
	return "vaultx"
}

func runVaultx(args ...string) (string, error) {
	out, err := exec.Command(findVaultx(), args...).CombinedOutput()
	return string(out), err
}

func filePicker(label string, w fyne.Window, onSelected func(string)) *fyne.Container {
	entry := widget.NewEntry()
	entry.SetPlaceHolder(label)

	browseBtn := widget.NewButtonWithIcon("", theme.FileIcon(), func() {
		d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			r.Close()
			entry.SetText(r.URI().Path())
			onSelected(r.URI().Path())
		}, w)
		d.Resize(fyne.NewSize(700, 500))
		d.Show()
	})

	return container.NewBorder(nil, nil, nil, browseBtn, entry)
}

func fileOrFolderPicker(w fyne.Window, onSelected func(string)) *fyne.Container {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Select file or folder…")

	fileBtn := widget.NewButtonWithIcon("File", theme.FileIcon(), func() {
		d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			r.Close()
			entry.SetText(r.URI().Path())
			onSelected(r.URI().Path())
		}, w)
		d.Resize(fyne.NewSize(700, 500))
		d.Show()
	})

	folderBtn := widget.NewButtonWithIcon("Folder", theme.FolderIcon(), func() {
		d := dialog.NewFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil || u == nil {
				return
			}
			entry.SetText(u.Path())
			onSelected(u.Path())
		}, w)
		d.Resize(fyne.NewSize(700, 500))
		d.Show()
	})

	return container.NewBorder(nil, nil, nil, container.NewHBox(fileBtn, folderBtn), entry)
}

func encryptTab(w fyne.Window, setStatus func(string, bool)) *fyne.Container {
	var selectedPath string
	picker := fileOrFolderPicker(w, func(p string) { selectedPath = p })

	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Password")
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Confirm password")

	encryptBtn := widget.NewButton("Encrypt", func() {
		if selectedPath == "" {
			setStatus("Select a file or folder first", true)
			return
		}
		if pass.Text == "" {
			setStatus("Enter a password", true)
			return
		}
		if pass.Text != confirm.Text {
			setStatus("Passwords do not match", true)
			return
		}
		setStatus("Encrypting…", false)
		go func() {
			_, err := runVaultx("encrypt", selectedPath, "-p", pass.Text)
			if err != nil {
				setStatus("Encryption failed", true)
				return
			}
			setStatus(fmt.Sprintf("Encrypted: %s", filepath.Base(selectedPath)), false)
			pass.SetText("")
			confirm.SetText("")
		}()
	})
	encryptBtn.Importance = widget.HighImportance

	form := widget.NewForm(
		widget.NewFormItem("File / Folder", picker),
		widget.NewFormItem("Password", pass),
		widget.NewFormItem("Confirm", confirm),
	)

	return container.NewVBox(
		container.NewPadded(form),
		container.NewPadded(encryptBtn),
	)
}

func decryptTab(w fyne.Window, setStatus func(string, bool)) *fyne.Container {
	var selectedPath string
	picker := filePicker("Select .vx file…", w, func(p string) { selectedPath = p })

	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Password")

	decryptBtn := widget.NewButton("Decrypt", func() {
		if selectedPath == "" {
			setStatus("Select a .vx file first", true)
			return
		}
		if pass.Text == "" {
			setStatus("Enter a password", true)
			return
		}
		setStatus("Decrypting…", false)
		go func() {
			out, err := runVaultx("decrypt", selectedPath, "-p", pass.Text)
			if err != nil {
				if strings.Contains(out, "wrong password") {
					setStatus("Wrong password", true)
				} else {
					setStatus("Decryption failed", true)
				}
				return
			}
			name := strings.TrimSuffix(filepath.Base(selectedPath), ".vx")
			setStatus(fmt.Sprintf("Decrypted: %s", name), false)
			pass.SetText("")
		}()
	})
	decryptBtn.Importance = widget.HighImportance

	form := widget.NewForm(
		widget.NewFormItem("Encrypted file (.vx)", picker),
		widget.NewFormItem("Password", pass),
	)

	return container.NewVBox(
		container.NewPadded(form),
		container.NewPadded(decryptBtn),
	)
}

func verifyTab(w fyne.Window, setStatus func(string, bool)) *fyne.Container {
	var selectedPath string
	picker := filePicker("Select .vx file…", w, func(p string) { selectedPath = p })

	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Password")

	verifyBtn := widget.NewButton("Verify integrity", func() {
		if selectedPath == "" {
			setStatus("Select a .vx file first", true)
			return
		}
		if pass.Text == "" {
			setStatus("Enter a password", true)
			return
		}
		setStatus("Verifying…", false)
		go func() {
			out, err := runVaultx("verify", selectedPath, "-p", pass.Text)
			if err != nil {
				if strings.Contains(out, "wrong password") {
					setStatus("Wrong password", true)
				} else {
					setStatus("Verification failed", true)
				}
				return
			}
			setStatus(fmt.Sprintf("✓ %s is intact", filepath.Base(selectedPath)), false)
			pass.SetText("")
		}()
	})
	verifyBtn.Importance = widget.HighImportance

	form := widget.NewForm(
		widget.NewFormItem("Encrypted file (.vx)", picker),
		widget.NewFormItem("Password", pass),
	)

	return container.NewVBox(
		container.NewPadded(form),
		container.NewPadded(verifyBtn),
	)
}

func main() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("vaultx")
	w.Resize(fyne.NewSize(620, 380))
	w.CenterOnScreen()

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	setStatus := func(msg string, isError bool) {
		if isError {
			statusLabel.SetText("✗  " + msg)
		} else {
			statusLabel.SetText("✓  " + msg)
		}
	}

	tabs := container.NewAppTabs(
		container.NewTabItem("  Encrypt  ", encryptTab(w, setStatus)),
		container.NewTabItem("  Decrypt  ", decryptTab(w, setStatus)),
		container.NewTabItem("  Verify  ", verifyTab(w, setStatus)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	statusBar := container.NewPadded(statusLabel)

	w.SetContent(container.NewBorder(nil, statusBar, nil, nil, tabs))
	w.ShowAndRun()
}
