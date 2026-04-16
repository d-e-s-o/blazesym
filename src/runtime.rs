use std::hint::unreachable_unchecked;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::thread;

#[cfg(not(feature = "multi-threaded"))]
type GlobalScheduler = SerialRunner;
#[cfg(not(feature = "multi-threaded"))]
const GLOBAL_SCHEDULER: GlobalScheduler = SerialRunner;

/// The scope type used for scheduling work.
#[cfg(not(feature = "multi-threaded"))]
pub(crate) type Scope<'scope, 'env> = ();

// TODO: Should be part of `Scheduler` trait, except it can't for <reasons>
//       pertaining various restrictions on the Rust side.
#[cfg(not(feature = "multi-threaded"))]
pub(crate) fn with_scope<'env, F, R>(f: F) -> R
where
    F: for<'scope> FnOnce(&'scope ()) -> R
{
   f(&())
}

#[cfg(feature = "multi-threaded")]
type GlobalScheduler = ThreadPoolScheduler;
#[cfg(feature = "multi-threaded")]
const GLOBAL_SCHEDULER: GlobalScheduler = ThreadPoolScheduler;

/// The scope type used for scheduling work.
#[cfg(feature = "multi-threaded")]
pub(crate) type Scope<'scope, 'env> = ScopedPool<'scope, 'env>;

#[cfg(feature = "multi-threaded")]
pub(crate) fn with_scope<'env, F, R>(f: F) -> R
where
    F: for<'scope> FnOnce(&'scope ScopedPool<'scope, 'env>) -> R,
{
    thread::scope(|scope| {
        let pool = ScopedPool::new(scope);
        f(&pool)
        // pool is dropped here: workers are shut down
        // scope exit: all scoped threads are joined
    })
}


pub(crate) trait Handle<T> {
    fn get(self) -> T;
}

pub(crate) trait Scheduler {
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

pub(crate) struct ImmediateHandle<T>(T);

impl<T> Handle<T> for ImmediateHandle<T> {
    #[inline]
    fn get(self) -> T {
        self.0
    }
}

pub(crate) struct SerialRunner;

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


// -- Thread Pool Scheduler (feature = "multi-threaded") --

/// A type-erased job for the thread pool.
#[cfg(feature = "multi-threaded")]
struct Job {
    func: Box<dyn FnOnce() + Send>,
}

/// The shared state between the pool and its workers.
#[cfg(feature = "multi-threaded")]
struct SharedQueue {
    /// The job queue. `None` signals shutdown.
    queue: Mutex<Option<Vec<Job>>>,
    /// Notifies workers when new jobs are available or shutdown occurs.
    condvar: Condvar,
}

/// A scoped thread pool that pre-spawns worker threads.
///
/// Workers persist for the lifetime of the pool and pull jobs from a
/// shared queue. This avoids the overhead of creating a new OS thread
/// per task.
///
/// # Safety
///
/// This pool uses `unsafe` to erase the `'scope` lifetime from task
/// closures before sending them to worker threads. The safety
/// invariant is that all jobs complete before the pool is dropped,
/// which is guaranteed by:
/// 1. `Drop` sets the queue to `None` (shutdown signal)
/// 2. `Drop` waits (via condvar) until all workers have exited
/// 3. The pool lives inside a `thread::scope`, which joins all
///    spawned threads before returning
///
/// Therefore, all borrowed data referenced by `'scope` remains valid
/// for the entire duration of job execution.
#[cfg(feature = "multi-threaded")]
pub(crate) struct ScopedPool<'scope, 'env: 'scope> {
    shared: Arc<SharedQueue>,
    /// The number of workers still alive. Workers decrement this
    /// atomically on exit. Drop waits until this reaches 0.
    alive: Arc<std::sync::atomic::AtomicUsize>,
    _phantom: PhantomData<(&'scope (), &'env ())>,
}

#[cfg(feature = "multi-threaded")]
impl<'scope, 'env: 'scope> ScopedPool<'scope, 'env> {
    fn new(scope: &'scope thread::Scope<'scope, 'env>) -> Self {
        let num_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let shared = Arc::new(SharedQueue {
            queue: Mutex::new(Some(Vec::new())),
            condvar: Condvar::new(),
        });
        let alive = Arc::new(std::sync::atomic::AtomicUsize::new(num_threads));

        for _ in 0..num_threads {
            let shared = Arc::clone(&shared);
            let alive = Arc::clone(&alive);
            scope.spawn(move || {
                Self::worker_loop(&shared);
                alive.fetch_sub(1, std::sync::atomic::Ordering::Release);
                shared.condvar.notify_all();
            });
        }

        Self {
            shared,
            alive,
            _phantom: PhantomData,
        }
    }

    fn worker_loop(shared: &SharedQueue) {
        loop {
            let job = {
                let mut guard = shared.queue.lock().unwrap();
                loop {
                    match guard.as_mut() {
                        None => return, // Shutdown signal.
                        Some(queue) => {
                            if let Some(job) = queue.pop() {
                                break job;
                            }
                        }
                    }
                    guard = shared.condvar.wait(guard).unwrap();
                }
            };
            (job.func)();
        }
    }

    fn push_job(&self, job: Job) {
        let mut guard = self.shared.queue.lock().unwrap();
        if let Some(queue) = guard.as_mut() {
            queue.push(job);
        }
        // Wake one worker to pick up the job.
        self.shared.condvar.notify_one();
    }
}

#[cfg(feature = "multi-threaded")]
impl Drop for ScopedPool<'_, '_> {
    fn drop(&mut self) {
        // Signal shutdown.
        {
            let mut guard = self.shared.queue.lock().unwrap();
            *guard = None;
        }
        self.shared.condvar.notify_all();

        // Wait until all workers have exited. This is necessary so
        // that we don't return from `with_scope` while workers are
        // still running (and potentially accessing borrowed data).
        // Note: the actual thread joining is handled by
        // `thread::scope`, but we need to ensure workers have
        // finished their current job before we proceed.
        let mut guard = self.shared.queue.lock().unwrap();
        while self.alive.load(std::sync::atomic::Ordering::Acquire) > 0 {
            guard = self.shared.condvar.wait(guard).unwrap();
        }
    }
}


/// A result slot for communicating a value from a worker back to the
/// caller.
#[cfg(feature = "multi-threaded")]
struct ResultSlot<T> {
    value: Mutex<Option<T>>,
    ready: Condvar,
}

#[cfg(feature = "multi-threaded")]
impl<T> ResultSlot<T> {
    fn new() -> Self {
        Self {
            value: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn set(&self, value: T) {
        let mut guard = self.value.lock().unwrap();
        *guard = Some(value);
        self.ready.notify_one();
    }

    fn wait(&self) -> T {
        let mut guard = self.value.lock().unwrap();
        loop {
            if let Some(value) = guard.take() {
                return value;
            }
            guard = self.ready.wait(guard).unwrap();
        }
    }
}


/// Handle for a result that will be produced by a pool worker.
#[cfg(feature = "multi-threaded")]
pub(crate) struct PoolHandle<T> {
    slot: Arc<ResultSlot<T>>,
}

#[cfg(feature = "multi-threaded")]
impl<T> Handle<T> for PoolHandle<T> {
    #[inline]
    fn get(self) -> T {
        self.slot.wait()
    }
}


pub(crate) struct ThreadPoolScheduler;

#[cfg(feature = "multi-threaded")]
impl Scheduler for ThreadPoolScheduler {
    type Scope<'scope, 'env: 'scope> = ScopedPool<'scope, 'env>;
    type Handle<'scope, T> = PoolHandle<T>
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
        let slot = Arc::new(ResultSlot::new());
        let slot_clone = Arc::clone(&slot);

        // Wrap the closure: run f(), store result in slot.
        let wrapper: Box<dyn FnOnce() + Send + 'scope> = Box::new(move || {
            let result = f();
            slot_clone.set(result);
        });

        // SAFETY: The ScopedPool guarantees all jobs complete before
        // the pool is dropped (Drop waits for all workers). The pool
        // lives inside a `thread::scope` which joins all threads
        // before returning. Therefore, all borrowed data in 'scope
        // remains valid for the entire duration of job execution.
        let wrapper: Box<dyn FnOnce() + Send + 'static> =
            unsafe { std::mem::transmute(wrapper) };

        scope.push_job(Job { func: wrapper });
        PoolHandle { slot }
    }
}


enum HandleOrResolved<H, R> {
    Handle(Option<H>),
    Resolved(R),
}

pub(crate) struct Promise<'scope, 'env, T>
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
