use std::hint::unreachable_unchecked;
use std::marker::PhantomData;
use std::thread;

#[cfg(not(feature = "multi-threaded"))]
type GlobalScheduler = SerialRunner;
#[cfg(not(feature = "multi-threaded"))]
const GLOBAL_SCHEDULER: GlobalScheduler = SerialRunner;

// TODO: Should be part of `Scheduler` trait, except it can't for <reasons>
//       pertaining various restrictions on the Rust side.
#[cfg(not(feature = "multi-threaded"))]
fn with_scope<'env, F>(f: F)
where
    F: for<'scope> FnOnce(&'scope ())
{
   f(&())
}

#[cfg(feature = "multi-threaded")]
type GlobalScheduler = DumbThreadedScheduler;
#[cfg(feature = "multi-threaded")]
const GLOBAL_SCHEDULER: GlobalScheduler = DumbThreadedScheduler;

#[cfg(feature = "multi-threaded")]
fn with_scope<'env, F>(f: F)
where
    F: for<'scope> FnOnce(&'scope thread::Scope<'scope, 'env>),
{
    thread::scope(f)
}


trait Handle<T> {
    fn get(self) -> T;
}

trait Scheduler {
    type Scope<'scope, 'env: 'scope>;
    type Handle<'scope, T>: Handle<T>
    where
        T: 'scope;

    fn schedule<'scope, 'env: 'scope, F, T>(
        &self,
        scope: &'scope Self::Scope<'scope, 'env>,
        f: F,
    ) -> Self::Handle<'scope, T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope;
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
    type Scope<'scope, 'env: 'scope> = ();
    type Handle<'scope, T> = ImmediateHandle<T>
    where
        T: 'scope;

    fn schedule<'scope, 'env: 'scope, F, T>(
        &self,
        _scope: &'scope Self::Scope<'scope, 'env>,
        f: F,
    ) -> Self::Handle<'scope, T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        // Just execute the function here and now and return the result.
        ImmediateHandle(f())
    }
}

impl<T> Handle<T> for thread::ScopedJoinHandle<'_, T> {
    #[inline]
    fn get(self) -> T {
        self.join().expect("thread panicked")
    }
}


struct DumbThreadedScheduler;

impl Scheduler for DumbThreadedScheduler {
    type Scope<'scope, 'env: 'scope> = thread::Scope<'scope, 'env>;
    type Handle<'scope, T> = thread::ScopedJoinHandle<'scope, T>
    where
        T: 'scope;

    fn schedule<'scope, 'env: 'scope, F, T>(
        &self,
        scope: &'scope Self::Scope<'scope, 'env>,
        f: F,
    ) -> Self::Handle<'scope, T>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        scope.spawn(f)
    }
}

enum HandleOrResolved<H, R> {
    Handle(Option<H>),
    Resolved(R),
}

struct Promise<'scope, 'env, T>
where
    T: 'scope,
{
    value: HandleOrResolved<<GlobalScheduler as Scheduler>::Handle<'scope, T>, T>,
    _phantom: PhantomData<(&'scope (), &'env ())>,
}

impl<'scope, 'env: 'scope, T> Promise<'scope, 'env, T> {
    pub fn new<F>(scope: &'scope <GlobalScheduler as Scheduler>::Scope<'scope, 'env>, f: F) -> Self
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send,
    {
        let handle = GLOBAL_SCHEDULER.schedule(scope, f);
        Self {
            value: HandleOrResolved::Handle(Some(handle)),
            _phantom: PhantomData,
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
    use super::*;

    use std::str;
    use std::sync::Arc;
    use std::thread::sleep;
    use std::time::Duration;

    type Future<'scope, 'env, T> = Promise<'scope, 'env, T>;

    fn parse(data: &[u8]) -> &str {
        str::from_utf8(data).unwrap()
    }

    fn thread_name() -> String {
        thread::current()
            .name()
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("{:?}", thread::current().id()))
    }

    #[test]
    fn it_works() {
        let data = b"hallihallo".to_vec();
        let data = Arc::new(data);
        let slice = data.as_slice();

        with_scope(move |scope| {
        //thread::scope(move |scope| {
            let mut future1 = Future::new(scope, || {
                println!("PARSING ON THREAD: {}", thread_name());
                parse(slice).split_at(5).0
            });
            let mut future2 = Future::new(scope, || {
                println!("PARSING ON THREAD: {}", thread_name());
                parse(slice).split_at(5).1
            });

            println!("SLEEPING...");
            sleep(Duration::from_secs(2));

            println!("future1: {:?}", future1.get());
            println!("future2: {:?}", future2.get());
        })
    }
}
