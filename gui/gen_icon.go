//go:build ignore

package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

const size = 512

type C = color.RGBA

func smoothstep(a, b, x float64) float64 {
	t := math.Max(0, math.Min(1, (x-a)/(b-a)))
	return t * t * (3 - 2*t)
}

func blend(img *image.RGBA, x, y int, c C, a float64) {
	if x < 0 || y < 0 || x >= size || y >= size || a <= 0 {
		return
	}
	s := img.RGBAAt(x, y)
	img.SetRGBA(x, y, C{
		R: uint8(float64(c.R)*a + float64(s.R)*(1-a)),
		G: uint8(float64(c.G)*a + float64(s.G)*(1-a)),
		B: uint8(float64(c.B)*a + float64(s.B)*(1-a)),
		A: 255,
	})
}

func fillCircle(img *image.RGBA, cx, cy, r float64, c C) {
	for y := int(cy-r) - 1; y <= int(cy+r)+1; y++ {
		for x := int(cx-r) - 1; x <= int(cx+r)+1; x++ {
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			blend(img, x, y, c, smoothstep(r+0.8, r-0.8, d))
		}
	}
}

func fillRoundedRect(img *image.RGBA, x0, y0, w, h, r float64, c C) {
	x1, y1 := x0+w, y0+h
	for y := int(y0) - 1; y <= int(y1)+1; y++ {
		for x := int(x0) - 1; x <= int(x1)+1; x++ {
			fx, fy := float64(x), float64(y)
			nx := math.Max(x0+r, math.Min(x1-r, fx))
			ny := math.Max(y0+r, math.Min(y1-r, fy))
			d := math.Hypot(fx-nx, fy-ny) - r
			blend(img, x, y, c, smoothstep(0.8, -0.8, d))
		}
	}
}

// draws only the top half of a ring (the shackle arch)
func fillTopArch(img *image.RGBA, cx, cy, innerR, outerR float64, c C) {
	mid := (innerR + outerR) / 2
	half := (outerR - innerR) / 2
	for y := int(cy-outerR) - 1; y <= int(cy)+1; y++ {
		for x := int(cx-outerR) - 1; x <= int(cx+outerR)+1; x++ {
			if float64(y) > cy {
				continue
			}
			d := math.Abs(math.Hypot(float64(x)-cx, float64(y)-cy) - mid)
			blend(img, x, y, c, smoothstep(half+0.8, half-0.8, d))
		}
	}
}

func main() {
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// White background
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.SetRGBA(x, y, C{255, 255, 255, 255})
		}
	}

	cx, cy := float64(size/2), float64(size/2)

	// Coin shadow
	fillCircle(img, cx, cy+8, 222, C{160, 120, 10, 255})
	// Coin border ring
	fillCircle(img, cx, cy, 222, C{200, 155, 20, 255})
	// Coin main fill
	fillCircle(img, cx, cy, 210, C{255, 200, 30, 255})
	// Coin highlight (top-left)
	fillCircle(img, cx-30, cy-40, 160, C{255, 225, 100, 60})

	lc := C{48, 42, 36, 255}

	// Shackle arch
	archCX := cx
	archCY := cy - 54.0
	archInner := 34.0
	archOuter := 58.0
	strokeW := archOuter - archInner

	fillTopArch(img, archCX, archCY, archInner, archOuter, lc)

	// Left leg
	fillRoundedRect(img, archCX-archOuter, archCY, strokeW, cy-18-archCY, 3, lc)
	// Right leg
	fillRoundedRect(img, archCX+archInner, archCY, strokeW, cy-18-archCY, 3, lc)

	// 3 body bars
	barW := 144.0
	barH := 22.0
	gap := 16.0
	barX := cx - barW/2
	startY := cy - 12.0

	for i := 0; i < 3; i++ {
		y0 := startY + float64(i)*(barH+gap)
		fillRoundedRect(img, barX, y0, barW, barH, 6, lc)
	}

	f, _ := os.Create("Icon.png")
	defer f.Close()
	png.Encode(f, img)
}
