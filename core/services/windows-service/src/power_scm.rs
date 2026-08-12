//! Windows implementation of the power-event port.
//!
//! A service does not get a window, so `WM_POWERBROADCAST` never reaches it —
//! the OS delivers power transitions to the SCM control handler instead. That
//! handler is registered before any runtime dependency exists, so the callback
//! is parked in a process-wide slot the handler dispatches into; the service
//! runs one SCM connection per process, so there is exactly one producer.

use std::sync::{Arc, Mutex, OnceLock};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::power::{
    PowerEvent, PowerEventCallback, PowerEventObserver, PowerEventSubscription,
};
use windows_service::service::PowerEventParam;

fn slot() -> &'static Mutex<Option<PowerEventCallback>> {
    static SLOT: OnceLock<Mutex<Option<PowerEventCallback>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Called from the SCM control handler for every `SERVICE_CONTROL_POWEREVENT`.
/// Everything except the suspend/resume edges is ignored: battery and
/// power-scheme changes say nothing about whether the network survived.
pub fn dispatch(param: PowerEventParam) {
    let event = match param {
        PowerEventParam::ResumeAutomatic
        | PowerEventParam::ResumeSuspend
        | PowerEventParam::ResumeCritical => PowerEvent::Resume,
        PowerEventParam::Suspend => PowerEvent::Suspend,
        _ => return,
    };
    let callback = slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(Arc::clone);
    if let Some(callback) = callback {
        callback(event);
    }
}

/// Clears the parked callback when the subscription is dropped, so a control
/// event arriving during teardown finds nothing to call.
struct SlotGuard;

impl Drop for SlotGuard {
    fn drop(&mut self) {
        *slot().lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// The SCM-backed observer. Under console mode nothing ever dispatches into it;
/// the neutral resume watchdog covers that case.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScmPowerEventObserver;

impl PowerEventObserver for ScmPowerEventObserver {
    fn subscribe(
        &self,
        on_event: PowerEventCallback,
    ) -> Result<PowerEventSubscription, PlatformError> {
        *slot().lock().unwrap_or_else(|p| p.into_inner()) = Some(on_event);
        Ok(PowerEventSubscription::new(Box::new(SlotGuard)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn resume_params_dispatch_and_unsubscribing_stops_them() {
        let resumes = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&resumes);
        let sub = ScmPowerEventObserver
            .subscribe(Arc::new(move |event| {
                if event == PowerEvent::Resume {
                    r.fetch_add(1, Ordering::SeqCst);
                }
            }))
            .expect("subscribe never fails");

        dispatch(PowerEventParam::ResumeAutomatic);
        dispatch(PowerEventParam::Suspend);
        dispatch(PowerEventParam::BatteryLow);
        assert_eq!(resumes.load(Ordering::SeqCst), 1);

        drop(sub);
        dispatch(PowerEventParam::ResumeAutomatic);
        assert_eq!(resumes.load(Ordering::SeqCst), 1);
    }
}
