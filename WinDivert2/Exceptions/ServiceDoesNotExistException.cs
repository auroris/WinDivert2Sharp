using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class ServiceDoesNotExistException : Exception
	{
		public ServiceDoesNotExistException(string message) : base(message)
		{
		}
	}
}
