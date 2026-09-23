// Command icongen renders the QNAPFileManager app icon ("root prompt": an
// amber folder carrying a '#_' root shell prompt on a slate rounded tile) and
// writes every derived file from one geometry:
//
//	docs/brand/icon.svg                     canonical vector source
//	internal/web/static/favicon.svg         the UI favicon (same bytes)
//	qpkg/icons/QNAPFileManager.gif          64x64, App Center
//	qpkg/icons/QNAPFileManager_80.gif       80x80, App Center
//	qpkg/icons/QNAPFileManager_gray.gif     64x64, "disabled" state
//
// Run it from the repository root:
//
//	go run ./scripts/icongen
//	go run ./scripts/icongen -preview icon-preview.png   # 4x contact sheet
//
// The design and renderer are gpt-6-astra's (chosen by the owner 2026-09-23);
// this adaptation changes only where files are written and makes the preview
// optional. It lives in its own package directory (not behind a build tag) so
// `go vet ./...` keeps compiling it in CI; nothing imports it, so it never
// reaches the shipped binary. Stdlib only.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

// 12 samples per axis produce 145 exact coverage colors plus transparency.
const samples = 12
const levels = samples * samples

type point struct{ x, y float64 }

func rect(x, y, left, top, width, height float64) bool {
	return x >= left && x < left+width && y >= top && y < top+height
}
func rounded(x, y, left, top, width, height, radius float64) bool {
	dx := math.Max(math.Abs(x-left-width/2)-(width/2-radius), 0)
	dy := math.Max(math.Abs(y-top-height/2)-(height/2-radius), 0)
	return dx*dx+dy*dy <= radius*radius
}
func polygon(x, y float64, p []point) bool {
	inside := false
	j := len(p) - 1
	for i := range p {
		a, b := p[i], p[j]
		if (a.y > y) != (b.y > y) && x < (b.x-a.x)*(y-a.y)/(b.y-a.y)+a.x {
			inside = !inside
		}
		j = i
	}
	return inside
}

var tab = []point{{18, 22}, {32, 22}, {40, 29}, {40, 44}, {18, 44}}
var hashLeft = []point{{28, 35}, {31.5, 35}, {28, 54}, {24.5, 54}}
var hashRight = []point{{37, 35}, {40.5, 35}, {37, 54}, {33.5, 54}}

func folder(x, y float64) bool {
	return rounded(x, y, 14, 29, 52, 32, 4) || rounded(x, y, 14, 22, 8, 22, 4) || polygon(x, y, tab)
}
func prompt(x, y float64) bool {
	return polygon(x, y, hashLeft) || polygon(x, y, hashRight) || rect(x, y, 23.75, 40, 18.75, 3.75) || rect(x, y, 22.5, 47.5, 18.75, 3.75) || rect(x, y, 45, 50, 12.5, 3.75)
}
func render(size int, slate, amber color.NRGBA) *image.Paletted {
	palette := color.Palette{color.NRGBA{0, 0, 0, 0}}
	for i := 0; i <= levels; i++ {
		mix := func(a, b uint8) uint8 { return uint8((int(a)*(levels-i) + int(b)*i + levels/2) / levels) }
		palette = append(palette, color.NRGBA{mix(slate.R, amber.R), mix(slate.G, amber.G), mix(slate.B, amber.B), 255})
	}
	im := image.NewPaletted(image.Rect(0, 0, size, size), palette)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			tile, ink := 0, 0
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/samples) * 80 / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/samples) * 80 / float64(size)
					if rounded(x, y, 3, 3, 74, 74, 16) {
						tile++
						if folder(x, y) && !prompt(x, y) {
							ink++
						}
					}
				}
			}
			// GIF has binary alpha: threshold the outer edge without matte halos.
			// All internal edges retain their exact supersampled coverage colors.
			if tile*2 >= levels {
				im.SetColorIndex(px, py, uint8(ink+1))
			}
		}
	}
	return im
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func saveGIF(name string, im *image.Paletted) *image.Paletted {
	f, err := os.Create(name)
	must(err)
	must(gif.Encode(f, im, nil))
	must(f.Close())
	// Decode the delivered GIF for the preview and verify dimensions and pixels.
	f, err = os.Open(name)
	must(err)
	decoded, err := gif.Decode(f)
	must(err)
	must(f.Close())
	p, ok := decoded.(*image.Paletted)
	if !ok || p.Bounds() != im.Bounds() {
		panic("GIF round-trip mismatch")
	}
	_, _, _, alpha := p.At(0, 0).RGBA()
	if alpha != 0 {
		panic("GIF background must be transparent")
	}
	for y := 0; y < im.Bounds().Dy(); y++ {
		for x := 0; x < im.Bounds().Dx(); x++ {
			if p.ColorIndexAt(x, y) != im.ColorIndexAt(x, y) {
				panic("GIF pixel mismatch")
			}
		}
	}
	fmt.Printf("Verified %s: %dx%d, %d designed palette entries, transparent index 0\n", name, im.Bounds().Dx(), im.Bounds().Dy(), len(im.Palette))
	return p
}

// Bitmap labels avoid reliance on any installed fonts.
var letters = map[rune][7]string{
	'6': {"01110", "10000", "10000", "11110", "10001", "10001", "01110"},
	'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	'0': {"01110", "10001", "10011", "10101", "11001", "10001", "01110"},
	'x': {"00000", "00000", "10001", "01010", "00100", "01010", "10001"},
	'O': {"01110", "10001", "10001", "10001", "10001", "10001", "01110"},
	'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
}

func label(im *image.NRGBA, text string, center, y int, c color.Color) {
	x := center - (len(text)*12-2)/2
	for _, ch := range text {
		for row, bits := range letters[ch] {
			for col, bit := range bits {
				if bit == '1' {
					draw.Draw(im, image.Rect(x+col*2, y+row*2, x+col*2+2, y+row*2+2), image.NewUniform(c), image.Point{}, draw.Src)
				}
			}
		}
		x += 12
	}
}
func preview(path string, icons []*image.Paletted) {
	im := image.NewNRGBA(image.Rect(0, 0, 960, 800))
	backgrounds := []color.NRGBA{{255, 255, 255, 255}, {20, 26, 34, 255}}
	centers := []int{160, 480, 800}
	labels := []string{"64x64", "80x80", "64x64 OFF"}
	for row, bg := range backgrounds {
		draw.Draw(im, image.Rect(0, row*400, 960, (row+1)*400), image.NewUniform(bg), image.Point{}, draw.Src)
		fg := color.NRGBA{91, 103, 116, 255}
		if row == 1 {
			fg = color.NRGBA{177, 190, 203, 255}
		}
		for i, icon := range icons {
			label(im, labels[i], centers[i], row*400+20, fg)
			size := icon.Bounds().Dx()
			left, top := centers[i]-size*2, row*400+54+(320-size*4)/2
			for y := 0; y < size*4; y++ {
				for x := 0; x < size*4; x++ {
					c := icon.At(x/4, y/4)
					_, _, _, a := c.RGBA()
					if a != 0 {
						im.Set(left+x, top+y, c)
					}
				}
			}
		}
	}
	f, err := os.Create(path)
	must(err)
	must(png.Encode(f, im))
	must(f.Close())
}

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 80 80">
  <title>QNAPFileManager — root access</title>
  <rect x="3" y="3" width="74" height="74" rx="16" fill="#253445"/>
  <path fill="#edaa42" d="M18 22H32L40 29H62A4 4 0 0 1 66 33V57A4 4 0 0 1 62 61H18A4 4 0 0 1 14 57V26A4 4 0 0 1 18 22Z"/>
  <g fill="#253445">
    <path d="M28 35H31.5L28 54H24.5ZM37 35H40.5L37 54H33.5Z"/>
    <path d="M23.75 40H42.5V43.75H23.75ZM22.5 47.5H41.25V51.25H22.5ZM45 50H57.5V53.75H45Z"/>
  </g>
</svg>
`

func main() {
	root := flag.String("root", ".", "repository root")
	previewPath := flag.String("preview", "", "also write a 4x nearest-neighbour PNG preview (on white and on dark) to this path")
	flag.Parse()
	join := func(p ...string) string { return filepath.Join(append([]string{*root}, p...)...) }

	must(os.MkdirAll(join("docs", "brand"), 0o755))
	must(os.WriteFile(join("docs", "brand", "icon.svg"), []byte(svg), 0644))
	must(os.WriteFile(join("internal", "web", "static", "favicon.svg"), []byte(svg), 0644))
	slate, amber := color.NRGBA{37, 52, 69, 255}, color.NRGBA{237, 170, 66, 255}
	a := saveGIF(join("qpkg", "icons", "QNAPFileManager.gif"), render(64, slate, amber))
	b := saveGIF(join("qpkg", "icons", "QNAPFileManager_80.gif"), render(80, slate, amber))
	c := saveGIF(join("qpkg", "icons", "QNAPFileManager_gray.gif"), render(64, color.NRGBA{169, 169, 169, 255}, color.NRGBA{220, 220, 220, 255}))
	if *previewPath != "" {
		preview(*previewPath, []*image.Paletted{a, b, c})
	}
}
