using System;
using System.Collections.Generic;
using System.Text;

namespace WinDivert2
{
	public class ServiceNotRegisteredException : Exception
	{
		public ServiceNotRegisteredException(string message) : base(message)
		{
		}
	}
}
