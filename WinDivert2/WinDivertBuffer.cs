using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDivert2
{
    public class WinDivertBuffer : IDisposable
    {
        /// <summary>
        /// The internal buffer object.
        /// </summary>
        public byte[] _buffer;

        /// <summary>
        /// The pinned pointer to the buffer.
        /// </summary>
        public IntPtr BufferPointer;

        /// <summary>
        /// The GCHandle that provides our <see cref="BufferPointer"/> member.
        /// </summary>
        private GCHandle _bufferHandle;

        /// <summary>
        /// Constructs a new buffer with the default max-packet size.
        /// </summary>
        public WinDivertBuffer() : this(65536)
        {
        }

        /// <summary>
        /// Constructs a new buffer from the given raw buffer data.
        /// </summary>
        /// <param name="bufferData">
        /// The raw buffer data to wrap.
        /// </param>
        public WinDivertBuffer(byte[] bufferData)
        {
            _buffer = bufferData;
            _bufferHandle = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            BufferPointer = _bufferHandle.AddrOfPinnedObject();
        }

        /// <summary>
        /// Constructs a new buffer from the given buffer data
        /// </summary>
        /// <param name="bufferData">The buffer data</param>
        /// <param name="bufferSize">The size of the buffer</param>
        public WinDivertBuffer(byte[] bufferData, int bufferSize)
        {
            _buffer = new byte[bufferSize];
            Array.Copy(bufferData, _buffer, bufferSize);
            _bufferHandle = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            BufferPointer = _bufferHandle.AddrOfPinnedObject();
        }

        /// <summary>
        /// Constructs a new buffer with the given size.
        /// </summary>
        /// <param name="bufferSize"></param>
        public WinDivertBuffer(int bufferSize)
        {
            _buffer = new byte[bufferSize];
            _bufferHandle = GCHandle.Alloc(_buffer, GCHandleType.Pinned);
            BufferPointer = _bufferHandle.AddrOfPinnedObject();
        }

        /// <summary>
        /// Gets or sets the buffer value at the specified index.
        /// </summary>
        /// <param name="index">
        /// The index.
        /// </param>
        /// <exception cref="IndexOutOfRangeException">
        /// Will throw if the supplied index is out of range.
        /// </exception>
        public byte this[int index]
        {
            get
            {
                return _buffer[index];
            }

            set
            {
                _buffer[index] = value;
            }
        }

        /// <summary>
        /// Gets or sets the buffer value at the specified index.
        /// </summary>
        /// <param name="index">
        /// The index.
        /// </param>
        /// <exception cref="IndexOutOfRangeException">
        /// Will throw if the supplied index is out of range.
        /// </exception>
        public byte this[uint index]
        {
            get
            {
                return _buffer[index];
            }

            set
            {
                _buffer[index] = value;
            }
        }

        /// <summary>
        /// Gets the length of the buffer.
        /// </summary>
        public uint Length
        {
            get
            {
                return (uint)_buffer.Length;
            }
        }

        #region IDisposable Support

        private bool disposed = false; // To detect redundant calls

        /// <summary>
        /// Disposes of the buffer.
        /// </summary>
        /// <param name="disposing">
        /// Whether or not we're disposing.
        /// </param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (_buffer != null)
                    {
                        _bufferHandle.Free();
                        BufferPointer = IntPtr.Zero;
                        Array.Clear(_buffer, 0, _buffer.Length);
                        _buffer = null;
                    }
                }

                disposed = true;
            }
        }

        /// <summary>
        /// Disposes the buffer.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }

        #endregion IDisposable Support
    }
}
