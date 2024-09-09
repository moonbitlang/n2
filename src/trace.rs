//! Chrome trace output.

use std::fs::File;
use std::future::Future;
use std::io::{BufWriter, Write};
use std::time::Instant;

static mut TRACE: Option<Trace> = None;

pub struct Trace {
    start: Instant,
    w: BufWriter<File>,
    count: usize,
}

impl Trace {
    fn new(path: &str) -> std::io::Result<Self> {
        let mut w = BufWriter::new(File::create(path)?);
        writeln!(w, "[")?;
        Ok(Trace {
            start: Instant::now(),
            w,
            count: 0,
        })
    }

    fn write_event_prefix(&mut self, name: &str, ts: Instant) {
        if self.count > 0 {
            write!(self.w, ",").unwrap();
        }
        self.count += 1;
        write!(
            self.w,
            "{{\"pid\":0, \"name\":{:?}, \"ts\":{}, ",
            name,
            ts.duration_since(self.start).as_micros(),
        )
        .unwrap();
    }

    pub fn write_complete(&mut self, name: &str, tid: usize, start: Instant, end: Instant) {
        self.write_event_prefix(name, start);
        writeln!(
            self.w,
            "\"tid\": {}, \"ph\":\"X\", \"dur\":{}}}",
            tid,
            end.duration_since(start).as_micros()
        )
        .unwrap();
    }

    fn scope<T>(&mut self, name: &str, f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = f();
        let end = Instant::now();
        self.write_complete(name, 0, start, end);
        result
    }

    async fn async_scope<T>(&mut self, name: &str, f: impl Future<Output = T>) -> T {
        let start = Instant::now();
        let result = f.await;
        let end = Instant::now();
        self.write_complete(name, 0, start, end);
        result
    }

    /*
    These functions were useful when developing, but are currently unused.

    pub fn write_instant(&mut self, name: &str) {
        self.write_event_prefix(name, Instant::now());
        writeln!(self.w, "\"ph\":\"i\"}}").unwrap();
    }

    pub fn write_counts<'a>(
        &mut self,
        name: &str,
        counts: impl Iterator<Item = &'a (&'a str, usize)>,
    ) {
        self.write_event_prefix(name, Instant::now());
        write!(self.w, "\"ph\":\"C\", \"args\":{{").unwrap();
        for (i, (name, count)) in counts.enumerate() {
            if i > 0 {
                write!(self.w, ",").unwrap();
            }
            write!(self.w, "\"{}\":{}", name, count).unwrap();
        }
        writeln!(self.w, "}}}}").unwrap();
    }
    */

    fn close(&mut self) {
        self.write_complete("main", 0, self.start, Instant::now());
        writeln!(self.w, "]").unwrap();
        self.w.flush().unwrap();
    }
}

pub fn open(path: &str) -> std::io::Result<()> {
    let trace = Trace::new(path)?;
    // Safety: accessing global mut, not threadsafe.
    unsafe {
        TRACE = Some(trace);
    }
    Ok(())
}

#[inline]
#[allow(static_mut_refs)]
pub fn if_enabled(f: impl FnOnce(&mut Trace)) {
    // Safety: accessing global mut, not threadsafe.
    unsafe {
        match &mut TRACE {
            None => {}
            Some(t) => f(t),
        }
    }
}

#[inline]
#[allow(static_mut_refs)]
pub fn scope<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    // Safety: accessing global mut, not threadsafe.
    unsafe {
        match &mut TRACE {
            None => f(),
            Some(t) => t.scope(name, f),
        }
    }
}

#[inline]
#[allow(static_mut_refs)]
pub async fn async_scope<T>(name: &'static str, f: impl Future<Output = T>) -> T {
    // Safety: accessing global mut, not threadsafe.
    unsafe {
        match &mut TRACE {
            None =>  f.await,
            Some(t) => t.async_scope(name, f).await,
        }
    }
}

pub fn close() {
    if_enabled(|t| t.close());
}
