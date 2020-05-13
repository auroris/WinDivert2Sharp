using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class HostUnreachableException : Exception
	{
		public HostUnreachableException(string message) : base(message)
		{
		}
	}
}
