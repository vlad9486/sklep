use std::time::{Duration, SystemTime};

pub const TTL: Duration = Duration::from_secs(1); // 1 second

pub fn now() -> (u64, u32) {
    fuser(fuser::TimeOrNow::Now)
}

pub fn fuser(v: fuser::TimeOrNow) -> (u64, u32) {
    system(match v {
        fuser::TimeOrNow::Now => SystemTime::now(),
        fuser::TimeOrNow::SpecificTime(t) => t,
    })
}

pub fn system(v: SystemTime) -> (u64, u32) {
    let duration = v.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    (duration.as_secs(), duration.subsec_nanos())
}

pub fn to_system(secs: u64, nanos: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
}
