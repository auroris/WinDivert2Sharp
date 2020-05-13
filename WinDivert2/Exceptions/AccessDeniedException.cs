using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class AccessDeniedException : Exception
	{
		public AccessDeniedException(string message) : base(message)
		{
		}
	}
}
