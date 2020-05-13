using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2.Exceptions
{
	class ServiceCannotStartException : Exception
	{
		public ServiceCannotStartException(string message) : base(message)
		{
		}
	}
}
