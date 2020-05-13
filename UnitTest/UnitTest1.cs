using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinDivert2;

namespace UnitTest
{
	/// <summary>
	/// How to kill a hung service:
	/// 
	/// sc query WinDivert
	/// </summary>

	[TestClass]
	public class UnitTest
	{
		[TestInitialize]
		public void BeforeTest()
		{
			Assert.IsTrue((new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator), "Visual Studio must be run as Administrator to test WinDivert.");
		}

		[TestMethod]
		public void GetSetParameter()
		{
			ulong value = 0;

			// Start WinDivert and make sure it returned a valid handle
			IntPtr divert = WinDivert._WinDivertOpen("false", WinDivert.Layer.NETWORK, 0, WinDivert.Flag.NONE);
			Assert.AreNotEqual(WinDivert.INVALID_HANDLE_VALUE, divert, GetLastError());

			// Check to see if WinDivert is running
			TestWinDivertRunning(true);

			// Check to see if the queue length is default
			WinDivert._WinDivertGetParam(divert, WinDivert.Param.QUEUE_LENGTH, out value);
			Assert.AreEqual(WinDivert.PARAM_QUEUE_LENGTH_DEFAULT, value);

			// Check to see that we can modify the queue length, and make sure the setting sticks
			WinDivert._WinDivertSetParam(divert, WinDivert.Param.QUEUE_LENGTH, WinDivert.PARAM_QUEUE_LENGTH_MIN);
			WinDivert._WinDivertGetParam(divert, WinDivert.Param.QUEUE_LENGTH, out value);
			Assert.AreEqual(WinDivert.PARAM_QUEUE_LENGTH_MIN, value);

			// Close the handle and stop the WinDivert driver.
			Assert.IsTrue(WinDivert._WinDivertClose(divert), GetLastError());
			WinDivert.StopDriver();

			// Check to see if WinDivert is not running
			TestWinDivertRunning(false);
		}

		[TestMethod]
		public void WinDivertRecieveTest()
		{
			// Start WinDivert and make sure it returned a valid handle
			IntPtr divert = WinDivert._WinDivertOpen("tcp", WinDivert.Layer.SOCKET, 0, WinDivert.Flag.SNIFF | WinDivert.Flag.RECV_ONLY);
			Assert.AreNotEqual(WinDivert.INVALID_HANDLE_VALUE, divert, GetLastError());

			WinDivertBuffer buf = new WinDivertBuffer();
			Assert.AreEqual((uint)65536, buf.Length);
			uint len = 0;
			bool success;

			WinDivert.Address pAddress = new WinDivert.Address();

			success = WinDivert._WinDivertRecv(divert, buf.BufferPointer, buf.Length, ref len, ref pAddress);

			Assert.IsTrue(success);
			Assert.AreEqual((uint)65536, buf.Length);
			Assert.IsTrue(len < buf.Length);

			//Debug.WriteLine(System.Text.Encoding.UTF8.GetString(buf._buffer, 0, buf._buffer.Length));
			//Debug.WriteLine(pAddress.ToString());

			WinDivert._WinDivertClose(divert);
			WinDivert.StopDriver();
		}

		/// <summary>
		/// Check to see if WinDivert is running by querying the driver
		/// </summary>
		/// <param name="shouldBeRunning">If the service is supposed to be running or not</param>
		public void TestWinDivertRunning(bool shouldBeRunning)
		{
			Assert.AreEqual(shouldBeRunning, WinDivert.DriverRunning());
			Assert.AreEqual(shouldBeRunning, WinDivert.ServiceRunning());
		}

		/// <summary>
		/// Get the last error that occured, as a text string
		/// </summary>
		/// <returns>A string describing the error</returns>
		public String GetLastError()
		{
			try
			{
				WinDivert.GetLastError();
			}
			catch (Exception e)
			{
				return e.ToString();
			}

			return "";
		}
	}
}
