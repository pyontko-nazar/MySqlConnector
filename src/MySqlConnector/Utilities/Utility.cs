using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MySqlConnector.Utilities
{
	internal static class Utility
	{
		public static void Dispose<T>(ref T disposable)
			where T : class, IDisposable
		{
			if (disposable != null)
			{
				disposable.Dispose();
				disposable = null;
			}
		}

		public static string FormatInvariant(this string format, params object[] args) =>
			string.Format(CultureInfo.InvariantCulture, format, args);

		public static string GetString(this Encoding encoding, ArraySegment<byte> arraySegment) =>
			encoding.GetString(arraySegment.Array, arraySegment.Offset, arraySegment.Count);

		/// <summary>
		/// Loads a RSA public key from a PEM string. Taken from <a href="https://stackoverflow.com/a/32243171/23633">Stack Overflow</a>.
		/// </summary>
		/// <param name="publicKey">The public key, in PEM format.</param>
		/// <returns>An RSA public key, or <c>null</c> on failure.</returns>
		public static RSA DecodeX509PublicKey(string publicKey)
		{
			var x509Key = Convert.FromBase64String(publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", ""));

			// encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
			byte[] seqOid = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

			// ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
			using (var stream = new MemoryStream(x509Key))
			using (var reader = new BinaryReader(stream)) //wrap Memory Stream with BinaryReader for easy reading
			{
				var temp = reader.ReadUInt16();
				switch (temp)
				{
				case 0x8130:
					reader.ReadByte(); //advance 1 byte
					break;
				case 0x8230:
					reader.ReadInt16(); //advance 2 bytes
					break;
				default:
					throw new FormatException("Expected 0x8130 or 0x8230 but read {0:X4}".FormatInvariant(temp));
				}

				var seq = reader.ReadBytes(15);
				if (!seq.SequenceEqual(seqOid)) //make sure Sequence for OID is correct
					throw new FormatException("Expected RSA OID but read {0}".FormatInvariant(BitConverter.ToString(seq)));

				temp = reader.ReadUInt16();
				if (temp == 0x8103) //data read as little endian order (actual data order for Bit String is 03 81)
					reader.ReadByte(); //advance 1 byte
				else if (temp == 0x8203)
					reader.ReadInt16(); //advance 2 bytes
				else
					throw new FormatException("Expected 0x8130 or 0x8230 but read {0:X4}".FormatInvariant(temp));

				var bt = reader.ReadByte();
				if (bt != 0x00) //expect null byte next
					throw new FormatException("Expected 0x00 but read {0:X2}".FormatInvariant(bt));

				temp = reader.ReadUInt16();
				if (temp == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
					reader.ReadByte(); //advance 1 byte
				else if (temp == 0x8230)
					reader.ReadInt16(); //advance 2 bytes
				else
					throw new FormatException("Expected 0x8130 or 0x8230 but read {0:X4}".FormatInvariant(temp));

				temp = reader.ReadUInt16();
				byte lowbyte;
				byte highbyte = 0x00;

				if (temp == 0x8102)
				{
					//data read as little endian order (actual data order for Integer is 02 81)
					lowbyte = reader.ReadByte(); // read next bytes which is bytes in modulus
				}
				else if (temp == 0x8202)
				{
					highbyte = reader.ReadByte(); //advance 2 bytes
					lowbyte = reader.ReadByte();
				}
				else
				{
					throw new FormatException("Expected 0x8102 or 0x8202 but read {0:X4}".FormatInvariant(temp));
				}

				var modulusSize = highbyte * 256 + lowbyte;

				var firstbyte = reader.ReadByte();
				reader.BaseStream.Seek(-1, SeekOrigin.Current);

				if (firstbyte == 0x00)
				{
					//if first byte (highest order) of modulus is zero, don't include it
					reader.ReadByte(); //skip this null byte
					modulusSize -= 1; //reduce modulus buffer size by 1
				}

				var modulus = reader.ReadBytes(modulusSize); //read the modulus bytes

				if (reader.ReadByte() != 0x02) //expect an Integer for the exponent data
					throw new FormatException("Expected 0x02");
				int exponentSize = reader.ReadByte(); // should only need one byte for actual exponent data (for all useful values)
				var exponent = reader.ReadBytes(exponentSize);

				// ------- create RSACryptoServiceProvider instance and initialize with public key -----
				var rsa = RSA.Create();
				var rsaKeyInfo = new RSAParameters
				{
					Modulus = modulus,
					Exponent = exponent
				};
				rsa.ImportParameters(rsaKeyInfo);
				return rsa;
			}
		}

		/// <summary>
		/// Returns a new <see cref="ArraySegment{T}"/> that starts at index <paramref name="index"/> into <paramref name="arraySegment"/>.
		/// </summary>
		/// <param name="arraySegment">The <see cref="ArraySegment{T}"/> from which to create a slice.</param>
		/// <param name="index">The non-negative, zero-based starting index of the new slice (relative to <see cref="ArraySegment{T}.Offset"/> of <paramref name="arraySegment"/>.</param>
		/// <returns>A new <see cref="ArraySegment{T}"/> starting at the <paramref name="index"/>th element of <paramref name="arraySegment"/> and continuing to the end of <paramref name="arraySegment"/>.</returns>
		public static ArraySegment<T> Slice<T>(this ArraySegment<T> arraySegment, int index) =>
			new ArraySegment<T>(arraySegment.Array, arraySegment.Offset + index, arraySegment.Count - index);

		/// <summary>
		/// Returns a new <see cref="ArraySegment{T}"/> that starts at index <paramref name="index"/> into <paramref name="arraySegment"/> and has a length of <paramref name="length"/>.
		/// </summary>
		/// <param name="arraySegment">The <see cref="ArraySegment{T}"/> from which to create a slice.</param>
		/// <param name="index">The non-negative, zero-based starting index of the new slice (relative to <see cref="ArraySegment{T}.Offset"/> of <paramref name="arraySegment"/>.</param>
		/// <param name="length">The non-negative length of the new slice.</param>
		/// <returns>A new <see cref="ArraySegment{T}"/> of length <paramref name="length"/>, starting at the <paramref name="index"/>th element of <paramref name="arraySegment"/>.</returns>
		public static ArraySegment<T> Slice<T>(this ArraySegment<T> arraySegment, int index, int length) =>
			new ArraySegment<T>(arraySegment.Array, arraySegment.Offset + index, length);

#if NET45
		public static Task<T> TaskFromException<T>(Exception exception)
		{
			var tcs = new TaskCompletionSource<T>();
			tcs.SetException(exception);
			return tcs.Task;
		}
#else
		public static Task<T> TaskFromException<T>(Exception exception) => Task.FromException<T>(exception);
#endif

		public static byte[] TrimZeroByte(byte[] value)
		{
			if (value[value.Length - 1] == 0)
				Array.Resize(ref value, value.Length - 1);
			return value;
		}

#if NET45
		public static bool TryGetBuffer(this MemoryStream memoryStream, out ArraySegment<byte> buffer)
		{
			try
			{
				var rawBuffer = memoryStream.GetBuffer();
				buffer = new ArraySegment<byte>(rawBuffer, 0, checked((int) memoryStream.Length));
				return true;
			}
			catch (UnauthorizedAccessException)
			{
				buffer = default(ArraySegment<byte>);
				return false;
			}
		}
#endif

		public static void WriteUtf8(this BinaryWriter writer, string value) =>
			WriteUtf8(writer, value, 0, value.Length);

		public static void WriteUtf8(this BinaryWriter writer, string value, int startIndex, int length)
		{
			var endIndex = startIndex + length;
			while (startIndex < endIndex)
			{
				int codePoint = char.ConvertToUtf32(value, startIndex);
				startIndex++;
				if (codePoint < 0x80)
				{
					writer.Write((byte) codePoint);
				}
				else if (codePoint < 0x800)
				{
					writer.Write((byte) (0xC0 | ((codePoint >> 6) & 0x1F)));
					writer.Write((byte) (0x80 | (codePoint & 0x3F)));
				}
				else if (codePoint < 0x10000)
				{
					writer.Write((byte) (0xE0 | ((codePoint >> 12) & 0x0F)));
					writer.Write((byte) (0x80 | ((codePoint >> 6) & 0x3F)));
					writer.Write((byte) (0x80 | (codePoint & 0x3F)));
				}
				else
				{
					writer.Write((byte) (0xF0 | ((codePoint >> 18) & 0x07)));
					writer.Write((byte) (0x80 | ((codePoint >> 12) & 0x3F)));
					writer.Write((byte) (0x80 | ((codePoint >> 6) & 0x3F)));
					writer.Write((byte) (0x80 | (codePoint & 0x3F)));
					startIndex++;
				}
			}
		}

#if NET45 || NET46
		public static bool IsWindows() => Environment.OSVersion.Platform == PlatformID.Win32NT;

		public static void GetOSDetails(out string os, out string osDescription, out string architecture)
		{
			os = Environment.OSVersion.Platform == PlatformID.Win32NT ? "Windows" :
				Environment.OSVersion.Platform == PlatformID.Unix ? "Linux" :
				Environment.OSVersion.Platform == PlatformID.MacOSX ? "macOS" : null;
			osDescription = Environment.OSVersion.VersionString;
			architecture = IntPtr.Size == 8 ? "X64" : "X86";
		}
#else
		public static bool IsWindows()
		{
			try
			{
				// OSPlatform.Windows is not supported on AWS Lambda
				return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
			}
			catch (PlatformNotSupportedException)
			{
				return false;
			}
		}

		public static void GetOSDetails(out string os, out string osDescription, out string architecture)
		{
			os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" :
				RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" :
				RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "macOS" : null;
			osDescription = RuntimeInformation.OSDescription;
			architecture = RuntimeInformation.ProcessArchitecture.ToString();
		}
#endif

		internal static DateTime ParseDateTime(ArraySegment<byte> value, bool convertZeroDateTime)
		{
#if LEGACY_PARSER
			return ParseDateTimeLegacy(value, convertZeroDateTime);
#else
			int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, microseconds = 0;
			var currentIndex = 0;
			var currentPart = ParsedDateTimePart.Year;
			while (currentIndex < value.Count)
			{
				// ReSharper disable once PossibleNullReferenceException
				var b = (char) value.Array[value.Offset + currentIndex];
				if (b < '0' || b > '9')
					currentIndex++; // Skipe delimiter
				else
				{
					var tmpIndex = currentIndex;
					var n = ParseInt32(value, ref tmpIndex);
					switch (currentPart)
					{
					case ParsedDateTimePart.Year:
						year = n;
						break;
					case ParsedDateTimePart.Month:
						month = n;
						break;
					case ParsedDateTimePart.Day:
						day = n;
						break;
					case ParsedDateTimePart.Hour:
						hour = n;
						break;
					case ParsedDateTimePart.Minute:
						minute = n;
						break;
					case ParsedDateTimePart.Second:
						second = n;
						break;
					case ParsedDateTimePart.Microseconds:
					{
						var microDiff = tmpIndex - currentIndex;
						while (microDiff < 6)
						{
							microDiff++;
							n *= 10;
						}
						microseconds = n;
						break;
					}
					}

					if (currentIndex == tmpIndex)
						throw new InvalidCastException($"Unable to convert MySQL date/time to System.DateTime: {Encoding.UTF8.GetString(value)}.");

					currentIndex = tmpIndex;
					currentPart++;
				}
			}

			if (currentPart <= ParsedDateTimePart.Hour)
			{
				if (year == 0 && month == 0 && day == 0)
				{
					if (convertZeroDateTime)
						return DateTime.MinValue;
					throw new InvalidCastException($"Unable to convert MySQL date/time to System.DateTime: {Encoding.UTF8.GetString(value)}.");
				}

				var dt = new DateTime(year, month, day);
				return dt;
			}
			if (currentPart <= ParsedDateTimePart.Microseconds)
			{
				var dt = new DateTime(year, month, day, hour, minute, second);
				return dt;
			}

			var dtWithMicroseconds =
				new DateTime(year, month, day, hour, minute, second, microseconds / 1000).AddTicks(microseconds % 1000 * 10);
			return dtWithMicroseconds;
#endif
		}

		internal static TimeSpan ParseTimeSpan(ArraySegment<byte> value)
		{
#if LEGACY_PARSER
			return ParseTimeSpanLegacy(value);
#else
			int hours = 0, minutes = 0, seconds = 0, microseconds = 0;
			var currentIndex = 0;
			var currentPart = ParsedDateTimePart.Hour;
			while (currentIndex < value.Count)
			{
				// ReSharper disable once PossibleNullReferenceException
				var b = (char) value.Array[value.Offset + currentIndex];
				if ((b < '0' || b > '9') && b != '-' && b != '+')
					currentIndex++; // Skipe delimiter
				else
				{
					var tmpIndex = currentIndex;
					var n = ParseInt32(value, ref tmpIndex);
					switch (currentPart)
					{
					case ParsedDateTimePart.Hour:
						hours = n;
						break;
					case ParsedDateTimePart.Minute:
						minutes = n;
						break;
					case ParsedDateTimePart.Second:
						seconds = n;
						break;
					case ParsedDateTimePart.Microseconds:
					{
						var microDiff = tmpIndex - currentIndex;
						while (microDiff < 6)
						{
							microDiff++;
							n *= 10;
						}
						microseconds = n;
						break;
					}
					}

					if (currentIndex == tmpIndex)
						throw new InvalidCastException($"Unable to convert MySQL date/time to System.DateTime: {Encoding.UTF8.GetString(value)}.");

					currentIndex = tmpIndex;
					currentPart++;
				}
			}

			if (hours < 0)
				minutes = -minutes;
			if (hours < 0)
				seconds = -seconds;
			if (currentPart <= ParsedDateTimePart.Microseconds)
			{
				var ts = new TimeSpan(hours, minutes, seconds);
				return ts;
			}

			if (hours < 0)
				microseconds = -microseconds;
			var tsWithMicroseconds = new TimeSpan(0, hours, minutes, seconds, microseconds / 1000) +
			                         TimeSpan.FromTicks(microseconds % 1000 * 10);
			return tsWithMicroseconds;
#endif
		}

		private enum ParsedDateTimePart
		{
			Year,
			Month,
			Day,
			Hour,
			Minute,
			Second,
			Microseconds
		}

		internal static int ParseInt32(ArraySegment<byte> s)
		{
			var index = 0;
			return ParseInt32(s, ref index);
		}

		private static int ParseInt32(ArraySegment<byte> s, ref int index)
		{
			var bytes = s.Array;
			var len = s.Count;

			var sign = 1;
			var number = 0;

			for (; index < len; ++index)
			{
				var ch = (char) bytes[s.Offset + index];
				if (ch == '-')
					sign = -1;
				else
					break;
			}

			for (; index < len; ++index)
			{
				var digit = (char) bytes[s.Offset + index] - '0';
				if (digit < 0 || digit > 9)
					break;

				number *= 10;
				number += digit;
			}
			return sign * number;
		}

		internal static DateTime ParseDateTimeLegacy(ArraySegment<byte> value, bool convertZeroDateTime)
		{
			var parts = Encoding.UTF8.GetString(value).Split('-', ' ', ':', '.');

			var year = int.Parse(parts[0], CultureInfo.InvariantCulture);
			var month = int.Parse(parts[1], CultureInfo.InvariantCulture);
			var day = int.Parse(parts[2], CultureInfo.InvariantCulture);

			if (year == 0 && month == 0 && day == 0)
			{
				if (convertZeroDateTime)
					return DateTime.MinValue;
				throw new InvalidCastException("Unable to convert MySQL date/time to System.DateTime.");
			}

			if (parts.Length == 3)
				return new DateTime(year, month, day);

			var hour = int.Parse(parts[3], CultureInfo.InvariantCulture);
			var minute = int.Parse(parts[4], CultureInfo.InvariantCulture);
			var second = int.Parse(parts[5], CultureInfo.InvariantCulture);
			if (parts.Length == 6)
				return new DateTime(year, month, day, hour, minute, second);

			var microseconds = int.Parse(parts[6] + new string('0', 6 - parts[6].Length), CultureInfo.InvariantCulture);
			return new DateTime(year, month, day, hour, minute, second, microseconds / 1000).AddTicks(microseconds % 1000 * 10);
		}

		internal static TimeSpan ParseTimeSpanLegacy(ArraySegment<byte> value)
		{
			var parts = Encoding.UTF8.GetString(value).Split(':', '.');

			var hours = int.Parse(parts[0], CultureInfo.InvariantCulture);
			var minutes = int.Parse(parts[1], CultureInfo.InvariantCulture);
			if (hours < 0)
				minutes = -minutes;
			var seconds = int.Parse(parts[2], CultureInfo.InvariantCulture);
			if (hours < 0)
				seconds = -seconds;
			if (parts.Length == 3)
				return new TimeSpan(hours, minutes, seconds);

			var microseconds = int.Parse(parts[3] + new string('0', 6 - parts[3].Length), CultureInfo.InvariantCulture);
			if (hours < 0)
				microseconds = -microseconds;
			return new TimeSpan(0, hours, minutes, seconds, microseconds / 1000) + TimeSpan.FromTicks(microseconds % 1000 * 10);
		}
	}
}
