using System;
using System.Globalization;
using System.Text;
using MySqlConnector.Utilities;
using Xunit;

namespace SideBySide
{
	public class UtilityTests
	{
		[Fact]
		public void TestParseDateTime()
		{
			for (var ts = new DateTime(1970, 1, 1); ts.Year < 1971; ts = ts.AddMilliseconds(104729))
				foreach (var format in new[]
				{
					"yyyy-MM-dd",
					"yyyy-MM-dd hh:mm:ss",
					"yyyy-MM-dd hh:mm:ss.f",
					"yyyy-MM-dd hh:mm:ss.ff",
					"yyyy-MM-dd hh:mm:ss.fff",
					"yyyy-MM-dd hh:mm:ss.ffff",
					"yyyy-MM-dd hh:mm:ss.fffff",
					"yyyy-MM-dd hh:mm:ss.ffffff"
				})
				{
					var tsStr = ts.ToString(format, CultureInfo.InvariantCulture);
					var bytes = new ArraySegment<byte>(Encoding.UTF8.GetBytes(tsStr));
					Assert.Equal(Utility.ParseDateTimeLegacy(bytes, true), Utility.ParseDateTime(bytes, true));
				}
		}

		[Fact]
		public void TestParseTimeSpan()
		{
			for (var ts = new TimeSpan(-23, 59, 59); ts.TotalHours <= 24; ts = ts.Add(TimeSpan.FromMilliseconds(179)))
				foreach (var format in new[]
				{
					"hh\\:mm\\:ss",
					"hh\\:mm\\:ss\\.f",
					"hh\\:mm\\:ss\\.ff",
					"hh\\:mm\\:ss\\.fff",
					"hh\\:mm\\:ss\\.ffff",
					"hh\\:mm\\:ss\\.fffff",
					"hh\\:mm\\:ss\\.ffffff"
				})
				{
					var tsStr = ts.Hours < 0
						? "-" + ts.Negate().ToString(format, CultureInfo.InvariantCulture)
						: ts.ToString(format, CultureInfo.InvariantCulture);
					var bytes = new ArraySegment<byte>(Encoding.UTF8.GetBytes(tsStr));
					Assert.Equal(Utility.ParseTimeSpanLegacy(bytes), Utility.ParseTimeSpan(bytes));
				}
		}
	}
}
