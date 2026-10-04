//! Calendar timestamps in kernel transport prefixes.
use jiff::{
    Timestamp,
    civil::{DateTime, Time},
};

/// Calendar time printed by the transport, without inferred year or timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WallTime {
    /// An ISO timestamp with an explicit UTC offset.
    Instant(Timestamp),
    /// A full local date and time without a timezone.
    Local(DateTime),
    /// Traditional syslog timestamps omit the year and timezone.
    Syslog {
        /// Calendar month, 1 through 12.
        month: i8,
        /// Day of month.
        day: i8,
        /// Local clock time.
        time: Time,
    },
}

pub(crate) fn parse_wall_time(prefix: &str) -> Option<WallTime> {
    let prefix = prefix.trim_start();
    let prefix = if let Some(rest) = prefix.strip_prefix('<') {
        rest.split_once('>')
            .map_or(prefix, |(_, tail)| tail.trim_start())
    } else {
        prefix
    };
    if let Some(body) = prefix.strip_prefix('[') {
        if let Some((stamp, _)) = body.split_once(']') {
            if let Ok(date) = DateTime::strptime("%a %b %d %H:%M:%S %Y", stamp.trim()) {
                return Some(WallTime::Local(date));
            }
            return parse_wall_time(stamp);
        }
    }
    if let Ok(date) = DateTime::strptime("%a %b %d %H:%M:%S %Y", prefix.trim()) {
        return Some(WallTime::Local(date));
    }
    let token = prefix.split_whitespace().next()?;
    if let Ok(stamp) = token.parse::<Timestamp>() {
        return Some(WallTime::Instant(stamp));
    }
    if token.contains(':') {
        if let Ok(stamp) = token.parse::<DateTime>() {
            return Some(WallTime::Local(stamp));
        }
    }
    let mut words = prefix.split_whitespace();
    let first = words.next()?;
    let second = words.next()?;
    if let Ok(stamp) = format!("{first}T{second}").parse::<DateTime>() {
        return Some(WallTime::Local(stamp));
    }
    let third = words.next()?;
    // Use a leap year only to validate month/day, then discard the synthetic year.
    let date = DateTime::strptime(
        "%Y %b %d %H:%M:%S",
        format!("2000 {first} {second} {third}"),
    )
    .ok()?;
    Some(WallTime::Syslog {
        month: date.month(),
        day: date.day(),
        time: date.time(),
    })
}

/// Return the message/hostname following a leading ISO or syslog timestamp.
pub(crate) fn calendar_prefix_tail(input: &str) -> Option<&str> {
    let (first, tail) = input.split_once(char::is_whitespace)?;
    let tail = tail.trim_start();
    if parse_wall_time(first).is_some() {
        return Some(tail);
    }
    let (second, after_second) = tail.split_once(char::is_whitespace)?;
    let after_second = after_second.trim_start();
    let stamp = &input[..input.len() - after_second.len()];
    if parse_wall_time(stamp).is_some() {
        return Some(after_second);
    }
    let (third, after_third) = after_second.split_once(char::is_whitespace)?;
    let after_third = after_third.trim_start();
    // Calendar decoding can remain absent for a localized month, while the
    // transport's month/day/time shape still identifies its leading fields.
    if first.chars().all(char::is_alphabetic)
        && second
            .parse::<u8>()
            .is_ok_and(|day| (1..=31).contains(&day))
        && third.parse::<Time>().is_ok()
    {
        return Some(after_third);
    }
    None
}

// Recognize dmesg -T's date shape independently of localized weekday/month names.
// Calendar decoding remains optional; never invent a timezone or translate names.
pub(crate) fn is_dmesg_date(stamp: &str) -> bool {
    let words: Vec<_> = stamp.split_whitespace().collect();
    words.len() == 5
        && words[..2]
            .iter()
            .all(|s| !s.is_empty() && s.chars().all(char::is_alphabetic))
        && words[2]
            .parse::<u8>()
            .is_ok_and(|day| (1..=31).contains(&day))
        && words[3].parse::<Time>().is_ok()
        && words[4].len() == 4
        && words[4].bytes().all(|b| b.is_ascii_digit())
}
