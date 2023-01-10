//! This module contains the `Progress` struct which is used to communicate
//! the status of an ongoing operation between threads.

use std::{
    io,
    sync::{Arc, Mutex},
};

struct ProgressState {
    progress: usize,
    out_of: usize,
    //last_call: time::Instant,
    //delta: time::Duration,
    state: String,
}

#[derive(Clone)]
pub struct Progress {
    inner: Arc<Mutex<ProgressState>>,
}

#[allow(dead_code)]
impl Progress {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProgressState {
                progress: 0,
                out_of: 1,
                //last_call: time::Instant::now(),
                //delta: time::Duration::from_millis(0),
                state: String::new(),
            })),
        }
    }
    pub fn inc(&self) {
        let mut inner = self.inner.lock().unwrap();
        //inner.delta = self.last_call.elapsed();
        //inner.last_call = time::Instant::now();
        inner.progress += 1;
    }
    pub fn set_state(&self, state: String) {
        let mut inner = self.inner.lock().unwrap();
        inner.state = state;
    }
    pub fn percentage(&self) -> f32 {
        let inner = self.inner.lock().unwrap();
        (inner.progress as f32) / (inner.out_of as f32)
    }
    pub fn set_max(&self, max: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.out_of = max;
    }
    pub fn set_max_data(&self, bytes: usize) {
        self.set_max(bytes / 64)
    }
    pub fn inc_max(&self, inc: usize) {
        let mut inner = self.inner.lock().unwrap();
        inner.out_of += inc;
    }
    pub fn get_state(&self) -> String {
        self.inner.lock().unwrap().state.clone()
    }
    pub fn get_count(&self) -> usize {
        self.inner.lock().unwrap().progress
    }
    pub fn get_max(&self) -> usize {
        self.inner.lock().unwrap().out_of
    }
}

impl Default for Progress {
    fn default() -> Self {
        Progress::new()
    }
}

#[cfg(feature = "console")]
pub fn print_progress_bar(
    out: &mut console::Term,
    _h: u16,
    w: u16,
    prog: Progress,
) -> io::Result<()> {
    use io::Write;

    let state = prog.get_state();
    let percentage = prog.percentage() * 100.0;
    let count = prog.get_count();
    let max = prog.get_max();

    out.clear_line()?;

    if w > 50 {
        out.write_all(b" ")?;

        let max = 30;
        for i in 0..max {
            if i < (percentage * 0.01 * max as f32) as i32 {
                out.write_all("█".as_bytes())?;
            } else {
                out.write_all("-".as_bytes())?;
            }
        }
    }
    out.write_all(b" ")?;
    out.write_all(format!("{percentage:>3.0}% ").as_bytes())?;
    out.write_all(format!("[{count}/{max}]").as_bytes())?;
    out.write_all(b" - ")?;
    out.write_all(state.as_bytes())?;

    out.flush()?;

    Ok(())
}
