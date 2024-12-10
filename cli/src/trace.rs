use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::io;
use std::io::stderr;
use std::io::Stderr;
use std::io::StderrLock;
use std::io::Write;
use std::num::NonZeroU64;
use std::ops::DerefMut as _;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use tracing::field::Field;
use tracing::field::ValueSet;
use tracing::field::Visit;
use tracing::level_filters::LevelFilter;
use tracing::span;
use tracing::Event;
use tracing::Level;
use tracing::Metadata;
use tracing::Subscriber;
use tracing_core::span::Current;
use tracing_subscriber::fmt::format;
use tracing_subscriber::fmt::time::FormatTime as _;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::registry::LookupSpan;


const RESET: &str = "\x1b[0m";
const BLUE_S: &str = "\x1b[32m";
const BLUE_E: &str = RESET;
const RED_S: &str = "\x1b[31m";
const RED_E: &str = RESET;
const BOLD_S: &str = "\x1b[1m";
const BOLD_E: &str = RESET;


struct Writer<W>(W);

impl<W> fmt::Write for Writer<W>
where
    W: io::Write,
{
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let () = self.0.write_all(s.as_bytes()).map_err(|_err| fmt::Error)?;
        Ok(())
    }
}

#[derive(Debug)]
enum Value {
    F64(f64),
    I64(i64),
    U64(u64),
    I128(i128),
    U128(u128),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
}


type FieldValues = HashMap<&'static str, Value>;


#[derive(Debug, Default)]
struct Visitor {
    values: FieldValues,
}

impl Visitor {
    fn record_value(&mut self, field: &Field, value: Value) {
        let _entry = self.values.entry(field.name()).or_insert(value);
    }

    fn into_values(self) -> FieldValues {
        self.values
    }
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.record_value(field, Value::Str(format!("{value:?}")))
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, Value::F64(value))
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, Value::I64(value))
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, Value::U64(value))
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_value(field, Value::I128(value))
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_value(field, Value::U128(value))
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, Value::Bool(value))
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, Value::Str(value.to_string()))
    }

    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        self.record_value(field, Value::Str(value.to_string()))
    }
}


#[derive(Debug)]
struct SpanMeta {
    metadata: &'static Metadata<'static>,
    values: FieldValues,
    parent: Option<(span::Id, Arc<SpanMeta>)>,
}


#[derive(Clone, Debug)]
pub(crate) struct Builder<W = Stderr> {
    max_level: Option<Level>,
    writer: W,
}

impl<W> Builder<W> {
    pub fn with_max_level(mut self, level: Option<Level>) -> Self {
        self.max_level = level;
        self
    }

    pub fn build(self) -> Hierarchical<W> {
        let Self { max_level, writer } = self;
        Hierarchical {
            id_alloc: AtomicU64::new(1),
            max_level: LevelFilter::from(max_level.unwrap_or(Level::WARN)),
            time: SystemTime,
            current_span: AtomicU64::new(0),
            spans: RwLock::default(),
            writer,
        }
    }
}


pub(crate) struct Hierarchical<W> {
    /// Our "allocator" for span IDs.
    id_alloc: AtomicU64,
    /// The maximum level we are going to emit traces for.
    max_level: LevelFilter,
    /// The time we use when emitting traces.
    time: SystemTime,
    /// The currently active span.
    current_span: AtomicU64,
    /// A mapping of span IDs to associated meta data.
    spans: RwLock<HashMap<span::Id, Arc<SpanMeta>>>,
    /// The writer to which we emit traces.
    writer: W,
}

impl Hierarchical<Stderr> {
    pub(crate) fn builder() -> Builder<Stderr> {
        Builder {
            max_level: None,
            writer: stderr(),
        }
    }

    fn write_args(&self, span: &span::Id, args: fmt::Arguments<'_>) {
        fn write(
            mut writer: StderrLock<'_>,
            time: &SystemTime,
            meta: &SpanMeta,
            args: fmt::Arguments<'_>,
        ) -> fmt::Result {
            fn write_names(writer: &mut StderrLock<'_>, meta: &SpanMeta) -> fmt::Result {
                let prefix = if let Some((_id, parent)) = &meta.parent {
                    let () = write_names(writer, parent)?;
                    ":"
                } else {
                    ""
                };

                let name = meta.metadata.name();
                let () = write!(writer, "{prefix}{name}").map_err(|_err| fmt::Error)?;
                Ok(())
            }


            let () = time.format_time(&mut format::Writer::new(&mut Writer(&mut writer)))?;
            let () = match *meta.metadata.level() {
                Level::TRACE => todo!(),
                Level::DEBUG => todo!(),
                Level::INFO => {
                    write!(writer, "  {BLUE_S}INFO {BLUE_E}").map_err(|_err| fmt::Error)?
                }
                Level::WARN => todo!(),
                Level::ERROR => {
                    write!(writer, "  {RED_S}INFO {RED_E}").map_err(|_err| fmt::Error)?
                }
            };


            let () = write!(writer, " {BOLD_S}").map_err(|_err| fmt::Error)?;
            let () = write_names(&mut writer, meta)?;
            let () = write!(writer, "{BOLD_E}:").map_err(|_err| fmt::Error)?;
            let () = writeln!(writer, " {args}").map_err(|_err| fmt::Error)?;
            Ok(())
        }

        let guard = self.spans.read().unwrap();
        let meta = guard.get(span).unwrap();
        let writer = self.writer.lock();
        let _result = write(writer, &self.time, meta, args);
    }
}

impl Subscriber for Hierarchical<Stderr> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // We enable both spans and events, as long as they are visible
        // as per our level filter.
        *metadata.level() <= self.max_level
    }

    fn new_span(&self, attrs: &span::Attributes<'_>) -> span::Id {
        println!("ATTRS: {attrs:?}");
        let id = self.id_alloc.fetch_add(1, Ordering::Relaxed);
        let id = span::Id::from_u64(id);

        let mut visitor = Visitor::default();
        let () = attrs.values().record(&mut visitor);

        let parent_id = attrs.parent().cloned().or_else(|| {
            let current = self.current_span.load(Ordering::Relaxed);
            NonZeroU64::new(current).map(span::Id::from_non_zero_u64)
        });
        let parent = parent_id.and_then(|parent_id| {
            // TODO: Must not unwrap.
            let guard = self.spans.read().unwrap();
            guard
                .get(&parent_id)
                .map(|meta| (parent_id, Arc::clone(meta)))
        });

        println!("PARENT: {parent:?}");

        let span_meta = SpanMeta {
            metadata: attrs.metadata(),
            values: visitor.into_values(),
            parent,
        };
        let mut guard = self.spans.write().unwrap();
        let _prev = guard.insert(id.clone(), Arc::new(span_meta));
        id
    }

    fn record(&self, span: &span::Id, values: &span::Record<'_>) {
        self.write_args(span, format_args!("RECORD"));
    }

    fn record_follows_from(&self, span: &span::Id, follows: &span::Id) {
        self.write_args(span, format_args!("RECORD_FOLLOWS_FROM"));
    }

    fn event(&self, event: &Event<'_>) {
        // TODO: Use current span.
        //self.write_args(format_args!("EVENT"));
    }

    fn enter(&self, span: &span::Id) {
        let () = self.current_span.store(span.into_u64(), Ordering::Relaxed);
        self.write_args(span, format_args!("ENTER"));
    }

    fn exit(&self, span: &span::Id) {
        let guard = self.spans.read().unwrap();
        if let Some(meta) = guard.get(span) {
            if let Some((parent_span, ..)) = &meta.parent {
                let () = self
                    .current_span
                    .store(parent_span.into_u64(), Ordering::Relaxed);
            }
        }

        self.write_args(span, format_args!("EXIT"));
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.max_level)
    }

    fn try_close(&self, id: span::Id) -> bool {
        // TODO: Unclear what is there to "try".
        let mut guard = self.spans.write().unwrap();
        let _prev = guard.remove(&id);
        true
    }

    //fn current_span(&self) -> Current {
    //    let current = self.current_span.load(Ordering::Relaxed);
    //    if current == 0 {
    //        return Current::none()
    //    }

    //    let id = span::Id::from_u64(current);
    //    let guard = self.spans.read().unwrap();
    //    if let Some(meta) = guard.get(&id) {
    //        Current::new(id, meta.meta)
    //    } else {
    //        // TODO: Should probably be `Current::unkown` except is
    //        //       private?!
    //        Current::none()
    //    }
    //}
}
