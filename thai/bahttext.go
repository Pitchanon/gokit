// Package thai formats values the way Thai business documents print them:
// amounts spelled out in words (BahtText) and Buddhist-era dates.
package thai

import (
	"math"
	"strconv"
	"strings"
)

var digitWords = [...]string{"", "หนึ่ง", "สอง", "สาม", "สี่", "ห้า", "หก", "เจ็ด", "แปด", "เก้า"}

// placeWords are the place-value words within a group of six digits, indexed
// from the units place.
var placeWords = [...]string{"", "สิบ", "ร้อย", "พัน", "หมื่น", "แสน"}

// BahtText spells out amount in Thai words, as printed on receipts and tax
// invoices, e.g. 143.50 → "หนึ่งร้อยสี่สิบสามบาทห้าสิบสตางค์".
//
// The amount is first rounded to two decimals the way fmt's %.2f does.
// Rules:
//
//   - The tens digit 1 is read "สิบ" and 2 is read "ยี่สิบ".
//   - A units digit 1 is read "เอ็ด" when the tens digit of the same group is
//     not zero (11 → สิบเอ็ด), and "หนึ่ง" otherwise (101 → หนึ่งร้อยหนึ่ง).
//   - Every six digits are joined by "ล้าน", so large amounts repeat it
//     (1,000,000,000,000 → หนึ่งล้านล้าน).
//   - Whole amounts end in "ถ้วน"; amounts below one baht have no "บาท"
//     (0.50 → ห้าสิบสตางค์); zero is "ศูนย์บาทถ้วน".
//   - Negative amounts are prefixed with "ลบ".
//
// NaN and ±Inf return "".
func BahtText(amount float64) string {
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return ""
	}
	s := strconv.FormatFloat(amount, 'f', 2, 64)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign, s = "ลบ", s[1:]
	}
	intPart, satang, _ := strings.Cut(s, ".")

	baht := readNumber(intPart)
	sat := readGroup(satang)
	if baht == "" && sat == "" {
		return "ศูนย์บาทถ้วน"
	}

	var b strings.Builder
	b.WriteString(sign)
	if baht != "" {
		b.WriteString(baht)
		b.WriteString("บาท")
	}
	if sat == "" {
		b.WriteString("ถ้วน")
	} else {
		b.WriteString(sat)
		b.WriteString("สตางค์")
	}
	return b.String()
}

// readNumber reads a string of decimal digits of any length; all zeros read
// as "".
func readNumber(digits string) string {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return ""
	}
	first := len(digits) % 6
	if first == 0 {
		first = 6
	}
	var b strings.Builder
	b.WriteString(readGroup(digits[:first]))
	for i := first; i < len(digits); i += 6 {
		b.WriteString("ล้าน")
		b.WriteString(readGroup(digits[i : i+6]))
	}
	return b.String()
}

// readGroup reads up to six digits; all zeros read as "".
func readGroup(digits string) string {
	n := len(digits)
	tensNonZero := n >= 2 && digits[n-2] != '0'
	var b strings.Builder
	for i := 0; i < n; i++ {
		d := int(digits[i] - '0')
		if d == 0 {
			continue
		}
		place := n - 1 - i
		switch {
		case place == 1 && d == 1:
			b.WriteString("สิบ")
		case place == 1 && d == 2:
			b.WriteString("ยี่สิบ")
		case place == 0 && d == 1 && tensNonZero:
			b.WriteString("เอ็ด")
		default:
			b.WriteString(digitWords[d])
			b.WriteString(placeWords[place])
		}
	}
	return b.String()
}
