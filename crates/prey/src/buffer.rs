//! # Buffer Module
//! The Buffer module of PREY framework contains all the buffer allocation and management logic,
//! made considering efficiency and convenience.
//! 
//! # How to use this module properly
//! 
//! The first thing you want to do is to create a new `BufferPool`. It's the main structure
//! for the whole feature of this module. Let's assume you've created a pool with 10 buffers.
//! It means that you have only 10 buffers that can be use simultaneously by your code. Keep it in mind.
//! 
//! Then, once with your pool created, you want to alocate a space of that pool to use it as an actual **buffer**.
//! Once you've done that, you'll have a fully functional 2048 bytes buffer to use as you wish.
//! 
//! There are somethings to keep in mind:
//! 1. If you want to **write** something in the buffer, you'll need to get the mutable
//! writing slice of the buffer, calling `as_mut_slice()`. This function will return the next
//! empty buffer's space you can write.
//! 2. If you want to **overwrite** something in the buffer, you'll need to get the whole buffer
//! data as an *mutable* object, calling `data_mut()`. This function will return the whole data of the
//! buffer, so keep in mind that the first spots of the function's return will be actually filled with data.
//! 3. After writing or erasing some content of buffer, you **need** to update its size - by
//! calling `buffer.advance(n)` (`n` can be a negative value in case of erasing buffer data). If
//! you miss this step, your data will be physically in the buffer, but not logically and it will be overwritten
//! by the next `as_mut_slice()` return value update.
//! 4. Asking yourself what is `Buffer::ptr` and `Buffer::head`? They are the control variables that makes
//! PREY Buffer Module works. `Buffer::ptr` always points to the **root** of buffer's space segment. `Buffer::head`
//! always points to the start of **buffer's data segment**. Because PREY Buffers use the *headroom* thecnique to allow
//! easy header insertion, we keep an empty space of 128 bytes between the root of the buffer and its actual data segment.
//! That way, if you need to add an extra header to a full filled buffer, you can write it at the headroon and will not have
//! to **overwrite the entire buffer data**.
//! 5. If you want to see what's inside buffer, without overwiting anything, just call `data()` and the whole data segment of buffer
//! will be in your hands as an imutable object.
//! 
//! **IMPORTANT**: When calling `prepend(n)` you'll subtract n from 128 (default head size). This will increase buffer's data segment
//! size by decreasing the headroom size and when calling `advance(n)` you'll add n to `buffer::size`.
//! The size variable holds the amount of data written in the buffer. `prepend(n)` already updates `size`.
//! We hope the following diagram helps you understand it:
//! 
//! ```
//!    HEADROOM                          DATA SEGMENT
//! [               |                                                ]
//! 0              128                                              2048
//! ptr         ptr + head 
//!                size
//! ```
//! 
//! - When you call `data()` you'll get a slice starting at `ptr + head` and ending at `ptr + head + size`.
//! - When you call `data_mut()` you'll get the same slice returned by `data()` but as a mutable object.
//! - When you call `advance(n)` you're adding `n` to `size` variable.
//! - When you call `prepend(n)` you're subtractin `n` to `head` variable.
//! - When you call `as_mut_slice()` you'll get a slice starting at `ptr + head + size` and ending at buffer's space segment end.
//! 
//! # Code Example
//! ```rust
//!     let pool = BufferPool::new(10);
//!     let buffer1 = pool.acquire();
//!     // buffer1 = [| HEADROOM | DATA |]
//!     let buffer2 = pool.acquire();
//!     // buffer2 = [| HEADROOM | DATA |]
//! 
//!     let mut writing_space = buffer1.as_mut_slice();
//!     //  writing_space = buffer1: [| DATA |]
//!     let content = [0x01, 0x02, 0x03, 0x04, 0x05];
//!     writing_space[..content.len()].copy_from_slice(&content);
//!     //writing_space = buffer1: [|0x01, 0x02, 0x03, 0x04, 0x05, DATA |]
//!     buffer1.advance(content1.len());
//!     // buffer1 = [| HEADROOM | 0x01, 0x02, 0x03, 0x04, 0x05, DATA|] 
//! 
//!     let header = [0xff, 0xff, 0xff, 0xff, 0xff];
//!     buffer2.prepend(&header);
//!     // buffer2 = [|0xff, 0xff, 0xff, 0xff, 0xff, HEADROOM | DATA |]
//!     
//! ```

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
    /// 
    /// # Usage
    /// ```rust
    ///     let content = [0x01, 0x02, 0x03];
    ///     let wb = buffer.as_mut_slice(); // return the next writable slice of the buffer, based on buffer's ptr pointer.
    ///     wb[..content.len()].copy_from_slice(&content); // write content into buffer's data
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let content = [0x01, 0x02, 0x03];
    ///     let wb = buffer.as_mut_slice(); // return the next writable slice of the buffer, based on buffer's ptr pointer.
    ///     wb[..content.len()].copy_from_slice(&content); // write content into buffer's data
    ///     buffer.advance(content.len()); // advancing buffer pointer (ptr) for the next empty data slice
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let buffer_data = buffer.data(); // return all buffer data as an imutable object
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let mut buffer_data = buffer.data_mut(); // return all buffer data as a mutable object
    ///     buffer_data[12] = 0x00 // Overwriting byte 12 of buffer's data
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let header = [0x01, 0x02, 0x03];
    ///     buffer.prepend(&header); // Will write header content into buffer's headroom
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let content = [0x01, 0x02, 0x03];
    ///     let wb = buffer.as_mut_slice(); // return the next writable slice of the buffer, based on buffer's ptr pointer.
    ///     wb[..content.len()].copy_from_slice(&content); // write content into buffer's data
    ///     buffer.advance(content.len()); // advancing buffer pointer (ptr) for the next empty data slice
    ///     buffer.clear() // will reset buffer size and buffer head index. It means that content's data is **still** inside buffer's data array, but the next slice for writing will overwrite the actual content.
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    /// 
    ///     let pool = BufferPool::new(10); // will create 10 buffers with 2048 bytes each
    /// 
    /// ```
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
    /// 
    /// # Usage
    /// ```rust
    ///     let pool = BufferPool(10); // creates pool with 10 buffers
    ///     let buffer = pool.acquire() // returns one of the ten buffers of the pool
    ///     // Will panic if more then 10 buffers were meant to be acquired
    /// ```
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
