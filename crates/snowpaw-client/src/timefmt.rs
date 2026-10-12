//! Human-readable timestamps in local time.
//!
//! There's no timezone library in the dependency set, so the local UTC offset is read
//! once at startup from `/bin/date +%z` (present on Linux and macOS) and UTC is used
//! if that fails. Daylight-saving changes while the app is running aren't picked up.

const MINUTE: i64 = 60_000;
const DAY: i64 = 86_400_000;
const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const WEEKDAYS_LONG: [&str; 7] =
    ["Thursday", "Friday", "Saturday", "Sunday", "Monday", "Tuesday", "Wednesday"];
const MONTHS_LONG: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

#[derive(Debug, Clone, Copy)]
pub struct TimeFmt {
    offset_ms: i64,
}

impl TimeFmt {
    /// Local time minus UTC, in milliseconds (for turning local dates into UTC and back).
    pub fn offset_ms(&self) -> i64 {
        self.offset_ms
    }

    /// UTC (no offset): for tests and reproducible screenshots.
    pub fn utc() -> Self {
        Self { offset_ms: 0 }
    }

    pub fn local() -> Self {
        let offset = std::process::Command::new("/bin/date")
            .arg("+%z")
            .env_clear()
            .env("TZ", std::env::var_os("TZ").unwrap_or_default())
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| parse_offset(s.trim()));
        Self { offset_ms: offset.unwrap_or(0) }
    }

    fn local_ms(&self, utc_ms: i64) -> i64 {
        utc_ms.saturating_add(self.offset_ms)
    }

    /// Chat list: "14:03" today, "Mon" this week, "Oct 11" otherwise.
    pub fn list_time(&self, at_ms: i64, now_ms: i64) -> String {
        let (at, now) = (self.local_ms(at_ms), self.local_ms(now_ms));
        let (at_day, now_day) = (at.div_euclid(DAY), now.div_euclid(DAY));
        if at_day == now_day {
            clock(at)
        } else if (0..7).contains(&(now_day - at_day)) {
            WEEKDAYS[at_day.rem_euclid(7) as usize].to_owned()
        } else {
            let (_, m, d) = civil(at_day);
            format!("{} {d}", MONTHS[m as usize - 1])
        }
    }

    /// Local calendar day number (days since 1970-01-01 in local time).
    pub fn local_day(&self, at_ms: i64) -> i64 {
        self.local_ms(at_ms).div_euclid(DAY)
    }

    /// Centered timeline separator: "Today 08:15", "Yesterday 21:14", "Wednesday 11:20"
    /// within a week, then "October 2" (plus the year if it isn't this year).
    pub fn separator(&self, at_ms: i64, now_ms: i64) -> String {
        let (at, now) = (self.local_ms(at_ms), self.local_ms(now_ms));
        let (at_day, now_day) = (at.div_euclid(DAY), now.div_euclid(DAY));
        match now_day - at_day {
            0 => format!("Today {}", clock(at)),
            1 => format!("Yesterday {}", clock(at)),
            2..=6 => format!("{} {}", WEEKDAYS_LONG[at_day.rem_euclid(7) as usize], clock(at)),
            _ => {
                let (y, m, d) = civil(at_day);
                let (now_y, _, _) = civil(now_day);
                let month = MONTHS_LONG[m as usize - 1];
                if y == now_y { format!("{month} {d}") } else { format!("{month} {d}, {y}") }
            }
        }
    }

    /// Message bubble: "14:03" today, "Oct 11, 14:03" otherwise.
    pub fn bubble_time(&self, at_ms: i64, now_ms: i64) -> String {
        let (at, now) = (self.local_ms(at_ms), self.local_ms(now_ms));
        if at.div_euclid(DAY) == now.div_euclid(DAY) {
            clock(at)
        } else {
            let (_, m, d) = civil(at.div_euclid(DAY));
            format!("{} {d}, {}", MONTHS[m as usize - 1], clock(at))
        }
    }
}

fn clock(local_ms: i64) -> String {
    let mins = local_ms.rem_euclid(DAY) / MINUTE;
    format!("{:02}:{:02}", mins / 60, mins % 60)
}

/// "+0100" / "-0530" -> milliseconds.
fn parse_offset(s: &str) -> Option<i64> {
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    if rest.len() != 4 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i64 = rest[..2].parse().ok()?;
    let m: i64 = rest[2..].parse().ok()?;
    if h > 14 || m > 59 {
        return None;
    }
    Some(sign * (h * 60 + m) * MINUTE)
}

/// Days since 1970-01-01 -> (year, month 1-12, day 1-31). Howard Hinnant's algorithm.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-10-11 13:05 UTC (a Sunday).
    const NOW: i64 = 1_791_723_900_000;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(NOW / DAY), (2026, 10, 11));
        assert_eq!(civil(-1), (1969, 12, 31));
    }

    #[test]
    fn formats() {
        let f = TimeFmt::utc();
        assert_eq!(f.list_time(NOW, NOW), "13:05");
        assert_eq!(f.list_time(NOW - DAY, NOW), "Sat");
        assert_eq!(f.list_time(NOW - 10 * DAY, NOW), "Oct 1");
        assert_eq!(f.bubble_time(NOW, NOW), "13:05");
        assert_eq!(f.bubble_time(NOW - 10 * DAY, NOW), "Oct 1, 13:05");
        let plus2 = TimeFmt { offset_ms: 2 * 60 * MINUTE };
        assert_eq!(plus2.bubble_time(NOW, NOW), "15:05");
    }

    #[test]
    fn separators() {
        let f = TimeFmt::utc();
        assert_eq!(f.separator(NOW, NOW), "Today 13:05");
        assert_eq!(f.separator(NOW - DAY, NOW), "Yesterday 13:05");
        assert_eq!(f.separator(NOW - 4 * DAY, NOW), "Wednesday 13:05");
        assert_eq!(f.separator(NOW - 9 * DAY, NOW), "October 2");
        assert_eq!(f.separator(NOW - 400 * DAY, NOW), "September 6, 2025");
    }

    #[test]
    fn offsets() {
        assert_eq!(parse_offset("+0000"), Some(0));
        assert_eq!(parse_offset("-0530"), Some(-(5 * 60 + 30) * MINUTE));
        for bad in ["", "0000", "+00", "+9999", "+01:00", "UTC"] {
            assert_eq!(parse_offset(bad), None, "{bad}");
        }
    }
}
