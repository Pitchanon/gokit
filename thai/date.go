package thai

import (
	"fmt"
	"time"
)

// BuddhistEraOffset is added to a Common Era year to get the Buddhist Era
// year used on Thai documents.
const BuddhistEraOffset = 543

var monthAbbr = [...]string{
	"ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
	"ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค.",
}

var monthFull = [...]string{
	"มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน",
	"กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม",
}

// DateThai formats t as day, abbreviated month and Buddhist-era year, e.g.
// "22 ก.ค. 2569". The zero time gives "" so a printed form shows an empty box
// instead of a bogus date.
func DateThai(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d %s %d", t.Day(), monthAbbr[t.Month()-1], t.Year()+BuddhistEraOffset)
}

// DateThaiLong is DateThai with the full month name, e.g. "22 กรกฎาคม 2569".
func DateThaiLong(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d %s %d", t.Day(), monthFull[t.Month()-1], t.Year()+BuddhistEraOffset)
}
