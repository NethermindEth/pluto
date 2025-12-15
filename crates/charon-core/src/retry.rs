use crate::types::{Duty, DutyDefinitionSet, DutyType};
use charon::retry;

async fn fetcher_fetch(
    _duty: Duty,
    _set: DutyDefinitionSet<DutyType>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

async fn consensus_participate(_duty: Duty) -> std::result::Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

/// TODO
pub fn with_async_retry(options: retry::AsyncOptions<Duty>) {
    let fetcher_fetch = |duty: Duty, set: DutyDefinitionSet<DutyType>| {
        tokio::spawn(retry::do_async(
            options.clone(),
            duty.clone(),
            "fetcher",
            "fetch",
            move || fetcher_fetch(duty.clone(), set.clone()),
        ));
    };
    let consensus_participate = |duty: Duty| {
        tokio::spawn(retry::do_async(
            options.clone(),
            duty.clone(),
            "consensus",
            "participate",
            move || consensus_participate(duty.clone()),
        ));
    };
    // ... other funcs
}

#[cfg(test)]
mod tests {
    use crate::types::Duty;
    use charon::retry;
    use core::time;

    #[test]
    fn it_compiles() {
        let opts = retry::AsyncOptions::new(|_: Duty| Some(time::Duration::from_secs(30)));
        super::with_async_retry(opts);
    }
}
