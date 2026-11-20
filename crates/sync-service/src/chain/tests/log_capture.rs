use super::*;

/// Records `sync_service` tracing events as field-name to value maps.
#[derive(Clone, Default)]
pub(super) struct CapturedEvents(pub(super) Arc<std::sync::Mutex<Vec<BTreeMap<String, String>>>>);

impl CapturedEvents {
    pub(super) fn capture(&self) -> CaptureGuard {
        // With one registered dispatcher, tracing-core resolves a callsite first
        // hit on another test thread against that thread's empty default and
        // caches it as disabled. A second live dispatcher keeps interest computed
        // across every registered dispatcher, including this thread's capture.
        let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
        CaptureGuard {
            _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
            _registered: registered,
        }
    }

    pub(super) fn events(&self) -> Vec<BTreeMap<String, String>> {
        self.0.lock().expect("captured events lock").clone()
    }

    pub(super) fn with_message(&self, message: &str) -> Vec<BTreeMap<String, String>> {
        self.events()
            .into_iter()
            .filter(|event| event.get("message").is_some_and(|value| value == message))
            .collect()
    }

    pub(super) fn find(&self, message: &str) -> BTreeMap<String, String> {
        self.events()
            .into_iter()
            .find(|event| event.get("message").is_some_and(|value| value == message))
            .unwrap_or_else(|| panic!("missing {message:?} event"))
    }
}

pub(super) struct CaptureGuard {
    pub(super) _default: tracing::subscriber::DefaultGuard,
    pub(super) _registered: tracing::Dispatch,
}

pub(super) struct CaptureSubscriber(pub(super) CapturedEvents);

pub(super) struct CapturedFields<'a>(pub(super) &'a mut BTreeMap<String, String>);

impl tracing::field::Visit for CapturedFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("sync_service")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut CapturedFields(&mut fields));
        self.0.0.lock().expect("captured events lock").push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}
