using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace OPFService
{
	class EventLogWorker
	{
		public void AddLogEntry(string messageType, string message, int eventID)
		{
			EventLogEntryType logEntryType;
			if (messageType == "Error")
			{
				logEntryType = EventLogEntryType.Error;
			}
			else if (messageType == "Warning")
			{
				logEntryType = EventLogEntryType.Warning;
			}
			else if (messageType == "Success")
			{
				logEntryType = EventLogEntryType.SuccessAudit;
			}
			else if (messageType == "Failure")
			{
				logEntryType = EventLogEntryType.FailureAudit;
			}
			else
			{
				logEntryType = EventLogEntryType.Information;
			}

			try
			{
				using (EventLog eventLog = new EventLog("CSLab Password Filter"))
				{
					if (!EventLog.SourceExists("PassFilter Service"))
					{
						EventLog.CreateEventSource("PassFilter Service", "CSLab Password Filter");
					}
					eventLog.Source = "PassFilter Service";
					eventLog.WriteEntry(message, logEntryType, eventID);
				}
			}
			catch (Exception err)
			{
				using (EventLog eventLog = new EventLog("Application"))
				{
					eventLog.Source = "CSLab PassFilter Service";
					eventLog.WriteEntry(err.Message, EventLogEntryType.Error, 9111);
				}
			}
		}
	}
}
