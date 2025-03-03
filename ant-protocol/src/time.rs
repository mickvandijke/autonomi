use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn time_in_secs_since_unix_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_secs()
}
