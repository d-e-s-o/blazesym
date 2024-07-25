use std::hint::unreachable_unchecked;
use std::thread;
use std::thread::JoinHandle;

type GlobalScheduler = SerialRunner;
const GLOBAL_SCHEDULER: GlobalScheduler = SerialRunner;


trait Handle<T> {
    fn get(self) -> T;
}

trait Scheduler {
    type Handle<T>: Handle<T>;

    fn schedule<F, T>(&self, f: F) -> Self::Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

struct ImmediateHandle<T>(T);

impl<T> Handle<T> for ImmediateHandle<T> {
    #[inline]
    fn get(self) -> T {
        self.0
    }
}

struct SerialRunner;

impl Scheduler for SerialRunner {
    type Handle<T> = ImmediateHandle<T>;

    fn schedule<F, T>(&self, f: F) -> Self::Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Just execute the function here and there and return the result.
        ImmediateHandle(f())
    }
}

impl<T> Handle<T> for JoinHandle<T> {
    #[inline]
    fn get(self) -> T {
        self.join().expect("thread panicked")
    }
}

struct DumbThreadedScheduler;

impl Scheduler for DumbThreadedScheduler {
    type Handle<T> = JoinHandle<T>;

    fn schedule<F, T>(&self, f: F) -> Self::Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        thread::spawn(f)
    }
}

enum HandleOrResolved<H, R> {
    Handle(Option<H>),
    Resolved(R),
}

struct Promise<T> {
    value: HandleOrResolved<<GlobalScheduler as Scheduler>::Handle<T>, T>,
}

impl<T> Promise<T> {
    pub fn new<F>(f: F) -> Self
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let handle = GLOBAL_SCHEDULER.schedule(f);
        Self {
            value: HandleOrResolved::Handle(Some(handle)),
        }
    }

    #[inline]
    pub fn get(&mut self) -> &T {
        if let HandleOrResolved::Resolved(ref value) = self.value {
            return value;
        }

        match &mut self.value {
            HandleOrResolved::Handle(handle) => {
                // SANITY: There will always be a handle present, actually.
                let handle = handle.take().unwrap();
                self.value = HandleOrResolved::Resolved(handle.get());
                self.get()
            }
            HandleOrResolved::Resolved(..) => unsafe { unreachable_unchecked() },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread::{current, sleep},
        time::Duration,
    };

    use super::*;

    type Future<T> = Promise<T>;

    #[test]
    fn it_works() {
        let mut future1 = Future::new(|| {
            let name = current()
                .name()
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("{:?}", current().id()));
            println!("HELLO FROM THREAD: {}", name);
            name
        });

        let mut future2 = Future::new(|| {
            let name = current()
                .name()
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("{:?}", current().id()));
            println!("HELLO FROM THREAD: {}", name);
            name
        });

        println!("SLEEPING...");
        sleep(Duration::from_secs(2));

        println!("future1: {:?}", future1.get());
        println!("future2: {:?}", future2.get());
    }
}
