using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class NoDataException : Exception
	{
		public NoDataException(string message) : base(message)
		{
		}
	}
}
