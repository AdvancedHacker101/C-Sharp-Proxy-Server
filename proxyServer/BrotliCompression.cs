/* Copyright 2016 Simon Mourier. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/

//https://github.com/smourier/brotli

using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace Brotli
{
    public static class BrotliCompression
    {
        public static void Compress(string inputFilePath, string outputFilePath)
        {
            Compress(CreateDefaultParameters(), inputFilePath, outputFilePath);
        }

        public static void Compress(CompressionParameters parameters, string inputFilePath, string outputFilePath)
        {
            if (inputFilePath == null)
                throw new ArgumentNullException(nameof(inputFilePath));

            if (outputFilePath == null)
                throw new ArgumentNullException(nameof(outputFilePath));

            using (var input = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Write))
            {
                using (var output = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    Compress(parameters, input, output);
                }
            }
        }

        public static void Compress(Stream input, Stream output)
        {
            Compress(CreateDefaultParameters(), input, output);
        }

        public static void Compress(CompressionParameters parameters, Stream input, Stream output)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (output == null)
                throw new ArgumentNullException(nameof(output));

            ValidateParameters(parameters);
            var inputStream = new SequentialStream(input);
            var outputStream = new SequentialStream(output);
            int ok = CompressStream(ref parameters, inputStream, outputStream);
            if (ok == 0)
                throw new BrotliException();
        }

        private static void ValidateParameters(CompressionParameters parameters)
        {
            if (parameters.Quality < 0 || parameters.Quality > 11)
                throw new BrotliException("Invalid parameter. Quality range is 0 to 11.");

            if (parameters.LgWin < 10 || parameters.LgWin > 24)
                throw new BrotliException("Invalid parameter. LgWin range is 10 to 24.");

            if (parameters.LgBlock != 0 && (parameters.LgBlock < 16 || parameters.LgBlock > 24))
                throw new BrotliException("Invalid parameter. LgBlock range is 0 or 16 to 24.");
        }

        public static CompressionParameters CreateDefaultParameters()
        {
            var parameters = new CompressionParameters
            {
                Quality = 11,
                LgWin = 22,
                EnableDictionary = true,
                EnableContextModeling = true
            };
            return parameters;
        }

        private class SequentialStream : ISequentialStream
        {
            private Stream _stream;

            public SequentialStream(Stream stream)
            {
                _stream = stream;
            }

            public void Read(byte[] pv, int cb, IntPtr pcbRead)
            {
                int read = _stream.Read(pv, 0, cb);
                if (pcbRead != IntPtr.Zero)
                {
                    Marshal.WriteInt32(pcbRead, read);
                }
            }

            public void Write(byte[] pv, int cb, IntPtr pcbWritten)
            {
                _stream.Write(pv, 0, cb);
                if (pcbWritten != IntPtr.Zero)
                {
                    Marshal.WriteInt32(pcbWritten, cb);
                }
            }
        }

        public static void Decompress(string inputFilePath, string outputFilePath)
        {
            if (inputFilePath == null)
                throw new ArgumentNullException(nameof(inputFilePath));

            if (outputFilePath == null)
                throw new ArgumentNullException(nameof(outputFilePath));

            using (var input = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Write))
            {
                using (var output = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    Decompress(input, output);
                }
            }
        }

        public static void Decompress(Stream input, Stream output)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            if (output == null)
                throw new ArgumentNullException(nameof(output));

            // ported from tools/bro.cc
            IntPtr state = CreateState();
            byte[] inputBuffer = new byte[6553600];
            byte[] outputBuffer = new byte[6553600];
            IntPtr availableOut = new IntPtr(outputBuffer.Length);
            IntPtr availableIn = IntPtr.Zero;
            IntPtr totalOut = IntPtr.Zero;
            try
            {
                BrotliResult result = BrotliResult.BROTLI_RESULT_NEEDS_MORE_INPUT;
                IntPtr offsetIn = IntPtr.Zero;
                IntPtr offsetOut = IntPtr.Zero;
                while (true)
                {
                    if (result == BrotliResult.BROTLI_RESULT_ERROR)
                        throw new BrotliException();

                    if (result == BrotliResult.BROTLI_RESULT_NEEDS_MORE_INPUT)
                    {
                        availableIn = new IntPtr(input.Read(inputBuffer, 0, inputBuffer.Length));
                        if (availableIn.ToInt64() == 0)
                            break;
                    }
                    else if (result == BrotliResult.BROTLI_RESULT_NEEDS_MORE_OUTPUT)
                    {
                        output.Write(outputBuffer, 0, outputBuffer.Length);
                        availableOut = new IntPtr(outputBuffer.Length);
                    }
                    else
                        break;

                    result = DecompressStream(
                        ref availableIn, inputBuffer, ref offsetIn,
                        ref availableOut, outputBuffer, ref offsetOut,
                        ref totalOut, state);
                }

                if (offsetOut != IntPtr.Zero)
                {
                    output.Write(outputBuffer, 0, offsetOut.ToInt32());
                }
            }
            finally
            {
                DestroyState(state);
            }
        }

        private static void DestroyState(IntPtr state)
        {
            if (state == IntPtr.Zero)
                return;

            if (IntPtr.Size == 4)
            {
                DestroyState86(state);
                return;
            }
            DestroyState64(state);
        }

        private static IntPtr CreateState()
        {
            int hr = IntPtr.Size == 4 ? CreateState86(out IntPtr state) : CreateState64(out state);
            if (hr != 0)
                throw new Win32Exception(hr);

            return state;
        }

        private static BrotliResult DecompressStream(
            ref IntPtr availableIn, byte[] nextIn, ref IntPtr offsetIn,
            ref IntPtr availableOut, byte[] nextOut, ref IntPtr offsetOut,
            ref IntPtr totalOut, IntPtr state
            )
        {
            if (IntPtr.Size == 4)
                return DecompressStream86(
                    ref availableIn, nextIn, ref offsetIn,
                    ref availableOut, nextOut, ref offsetOut,
                    ref totalOut, state);

            return DecompressStream64(
                    ref availableIn, nextIn, ref offsetIn,
                    ref availableOut, nextOut, ref offsetOut,
                ref totalOut, state);
        }

        private static int CompressStream(ref CompressionParameters parameters, ISequentialStream input, ISequentialStream output)
        {
            if (IntPtr.Size == 4)
                return CompressStream86(ref parameters, input, output);

            return CompressStream64(ref parameters, input, output);
        }

        [DllImport("winbrotli.x86.dll", EntryPoint = "CompressStream")]
        private static extern int CompressStream86(ref CompressionParameters parameters, ISequentialStream input, ISequentialStream output);

        [DllImport("winbrotli.x64.dll", EntryPoint = "CompressStream")]
        private static extern int CompressStream64(ref CompressionParameters parameters, ISequentialStream input, ISequentialStream output);

        [DllImport("winbrotli.x86.dll", EntryPoint = "DecompressStream")]
        private static extern BrotliResult DecompressStream86(
            ref IntPtr availableIn, byte[] nextIn, ref IntPtr offsetIn,
            ref IntPtr availableOut, [In, Out] byte[] nextOut, ref IntPtr offsetOut,
            ref IntPtr totalOut, IntPtr state
            );

        [DllImport("winbrotli.x64.dll", EntryPoint = "DecompressStream")]
        private static extern BrotliResult DecompressStream64(
            ref IntPtr availableIn, byte[] nextIn, ref IntPtr offsetIn,
            ref IntPtr availableOut, [In, Out] byte[] nextOut, ref IntPtr offsetOut,
            ref IntPtr totalOut, IntPtr state
            );

        [DllImport("winbrotli.x86.dll", EntryPoint = "CreateState")]
        private static extern int CreateState86(out IntPtr state);

        [DllImport("winbrotli.x86.dll", EntryPoint = "DestroyState")]
        private static extern int DestroyState86(IntPtr state);

        [DllImport("winbrotli.x64.dll", EntryPoint = "CreateState")]
        private static extern int CreateState64(out IntPtr state);

        [DllImport("winbrotli.x64.dll", EntryPoint = "DestroyState")]
        private static extern int DestroyState64(IntPtr state);

        private enum BrotliResult
        {
            BROTLI_RESULT_ERROR = 0,
            BROTLI_RESULT_SUCCESS = 1,
            BROTLI_RESULT_NEEDS_MORE_INPUT = 2,
            BROTLI_RESULT_NEEDS_MORE_OUTPUT = 3
        }

        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface ISequentialStream
        {
            void Read([Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, int cb, IntPtr pcbRead);
            void Write([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] pv, int cb, IntPtr pcbWritten);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CompressionParameters
    {
        public CompressionMode Mode;

        // Controls the compression-speed vs compression-density tradeoffs. The higher the quality, the slower the compression. Range is 0 to 11.
        public int Quality;

        // Base 2 logarithm of the sliding window size. Range is 10 to 24.
        public int LgWin;

        // Base 2 logarithm of the maximum input block size. Range is 16 to 24. If set to 0, the value will be set based on the quality.
        public int LgBlock;

        [MarshalAs(UnmanagedType.I1)]
        public bool EnableDictionary;

        [MarshalAs(UnmanagedType.I1)]
        public bool EnableTransforms;

        [MarshalAs(UnmanagedType.I1)]
        public bool GreedyBlockSplit;

        [MarshalAs(UnmanagedType.I1)]
        public bool EnableContextModeling;
    }

    public enum CompressionMode
    {
        // Default compression mode. The compressor does not know anything in advance about the properties of the input.
        Generic = 0,

        // Compression mode for UTF-8 format text input.
        Text = 1,

        // Compression mode used in WOFF 2.0.
        Font = 2
    }

    [Serializable]
    public class BrotliException : IOException
    {
        public BrotliException()
            : base(string.Empty)
        {
        }

        public BrotliException(string message)
            : base(message)
        {
        }

        public BrotliException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public BrotliException(Exception innerException)
            : base(null, innerException)
        {
        }

        protected BrotliException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}