using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class InsufficientBufferException : Exception
	{
		public InsufficientBufferException(string message) : base(message)
		{
		}
	}
}
