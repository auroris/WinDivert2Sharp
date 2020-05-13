using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class IncompatibleDriverException : Exception
	{
		public IncompatibleDriverException(string message) : base(message)
		{
		}
	}
}
