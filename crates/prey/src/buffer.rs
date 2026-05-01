//! # Buffer Module
//! The Buffer module of PREY framework contains all the buffer allocation and management logic,
//! made considering efficiency and convenience.

use std::alloc::{alloc, Layout};
use std::sync::Arc;
use crossbeam_queue::ArrayQueue;

//Commom max cache line value used by CPUs
const CACHE_LINE: usize = 64;

//Size of buffers used in prey
const BUFFER_SIZE: usize = 2048;

/// # Buffer
/// Struct that contains the main buffer structure of the PREY framework.
/// ## Fields
/// - ptr: `*mut u8` - Pointer to the root of the buffer.
/// - capacity: `usize` - Total capacity of the buffer (2048 bytes).
/// - head: `usize` - Offset to actual start of useful data in buffer (128 bytes).
/// - size: `usize` - Size of useful data in buffer.
/// - pool: `Arc<BufferPool>` - Reference to parent buffer pool.
pub struct Buffer {
    pub ptr: *mut u8,
    pub capacity: usize,
    pub head: usize,
    pub size: usize,
    pub pool: Arc<BufferPool>
}

impl Drop for Buffer {
    //Implements drop trait for Buffer struct, to override default behavior
    // stopping the complete release of buffer memory area, and simply returning
    // its control back to the buffer pool.
    fn drop(&mut self) {
        let _ = self.pool.available.push(self.ptr);
    }
}

impl Buffer {
    /// # fn as_mut_slice
    /// Get the next writable slice of the buffer.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    ///
    /// # Returns
    /// The address to a `slice of u8` that represents the writable slice of the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            let start_ptr = self.ptr.add(self.head + self.size);
            let available_space = self.capacity - (self.head + self.size);
            std::slice::from_raw_parts_mut(start_ptr, available_space)
        }
    }

    /// # fn advance
    /// Advances the variable that keeps track of the end of buffer data. Used after data was written in buffer.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    /// - n: `usize` - size of data that was inserted in buffer.
    pub fn advance(&mut self, n: usize) {
        self.size += n;
    }

    /// # fn data
    /// Get buffer's data.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    ///
    /// # Returns
    /// A `u8 slice` reference containing all buffer's data.
    pub fn data(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.ptr.add(self.head), self.size)
        }
    }

    /// # fn data
    /// Get buffer's data, but allows overwriting (for editing purposes).
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    ///
    /// # Returns
    /// A `u8 slice` reference containing all buffer's data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.add(self.head), self.size)
        }
    }

    /// # fn prepend
    /// Allows writing a header into the 128 bytes of buffer's headroom, **only if it fits there**.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    /// - header: `&[u8]` - Header that will be written as bytes.
    pub fn prepend(&mut self, header: &[u8]) {
        let len = header.len();
        if len <= self.head {
            self.head -= len;
            self.size += len;
            unsafe {
                let start = self.ptr.add(self.head);
                std::ptr::copy_nonoverlapping(header.as_ptr(), start, len);
            }
        }
    }

    /// # fn clear
    /// Allows clearing the buffer content by reseting its size and head position.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated buffer.
    pub fn clear(&mut self) {
        self.size = 0;
        self.head = 128;
    }
}

/// # BufferPool
/// structure that holds all the space buffers will need.
///
/// ## Fields
/// - storage: `*mut u8` - Reference to the start of allocated memory area.
/// - capacity: `usize` - Total size of Buffer Pull memory area.
/// - available: `ArrayQueue<*mut u8>` - Array that holds all buffer sections start points.
pub struct BufferPool {
    pub storage: *mut u8,
    pub capacity: usize,
    pub available: ArrayQueue<*mut u8>
}

impl BufferPool {
    /// # fn new
    /// Function that creates a new BufferPool.
    ///
    /// # Params
    /// - num_buffers: `usize` - Number of buffers that will exist in the pool.
    ///
    /// # Returns
    /// A `Arc` reference to a new BufferPool, with 100MB of memory already allocated.
    pub fn new(num_buffers: usize) -> Arc<Self> {
        let total_size = num_buffers * BUFFER_SIZE;
        let layout = Layout::from_size_align(total_size, CACHE_LINE).expect("Falha ao definir layout da pool na memória.");

        let storage = unsafe { alloc(layout) };
        let available = ArrayQueue::new(num_buffers);

        for i in 0..num_buffers {
            unsafe {
                let buffer_ptr = storage.add(i * BUFFER_SIZE);
                let _ = available.push(buffer_ptr);
            }
        }


        Arc::new(Self {
            storage,
            capacity: num_buffers,
            available
        })
    }

    /// # fn acquire
    /// Function that reserve a 2048 bytes space of a pool to a Buffer.
    ///
    /// # Params
    /// - self: `&Arc<Self>` - Reference to the BufferPool.
    ///
    /// # Returns
    /// - If there is space available for a new Buffer acquisition, returns a new
    /// buffer object, else returns an Err.
    pub fn acquire(self: &Arc<Self>) -> Option<Buffer> {
        self.available.pop().map(|ptr| Buffer {
            ptr,
            capacity: BUFFER_SIZE,
            head: 128,
            size: 0,
            pool: Arc::clone(self)
        })
    }
}
