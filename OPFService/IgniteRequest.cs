using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;
using Newtonsoft.Json;

namespace OPFService
{
	class IgniteRequest
	{
		public bool AcceptAllCertifications(object sender, System.Security.Cryptography.X509Certificates.X509Certificate certification, System.Security.Cryptography.X509Certificates.X509Chain chain, System.Net.Security.SslPolicyErrors sslPolicyErrors)
		{
			return true;
		}
		public bool CheckPass(string pass)
		{
			EventLogWorker eventLogWorker = new EventLogWorker();

			bool result = false;
			string url = "https://" + OPFService.dbUri + "/ignite?cmd=get&cacheName=my-cache";
			try
			{
				ServicePointManager.ServerCertificateValidationCallback = new System.Net.Security.RemoteCertificateValidationCallback(AcceptAllCertifications);
				ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

				HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
				request.Method = "POST";
				request.ContentType = "application/x-www-form-urlencoded";
				request.Timeout = 3000;
				byte[] requestBody = Encoding.UTF8.GetBytes("key=" + pass);

				Stream stream = request.GetRequestStream();
				stream.Write(requestBody, 0, requestBody.Length);
				stream.Close();

				var response = request.GetResponse();
				Stream respStream = response.GetResponseStream();
				StreamReader sr = new StreamReader(respStream);
				string respResult = sr.ReadToEnd();
				var deserResult = JsonConvert.DeserializeObject<JsonResp>(respResult);

				// В БД хранятся записи в формате словаря <Ключ, Значение> - в нашем случае 
				// это был Dictonary<string, string> (<password, password>).
				// Происходит поиск по ключу и возвращается значение, которое сравнивается с паролем.
				// Для экономии оперативной памяти, используемой БД, словарь в БД можно
				// организовать иначе, например Dictonary<string, bool> и проверять
				// только наличие возвращаемого значения
				if (deserResult.response == pass)
				{
					if (OPFService.auditMode == 0)
					{
						result = true;
						if (OPFService.logLevel == 1)
						{
							eventLogWorker.AddLogEntry("Failure", "Failure\r\nUser tried to change the password to a password from Database\r\n", 9001);
						}
						else if (OPFService.logLevel == 2)
						{
							eventLogWorker.AddLogEntry("Failure", "Failure\r\nUser tried to change the password to a password from Database\r\nPassword: " + pass, 9001);
						}
					}
					else
					{
						if (OPFService.logLevel == 1)
						{
							eventLogWorker.AddLogEntry("Success", "Sucess\r\nUser tried to change the password to a password from Database\r\n", 9001);
						}
						else if (OPFService.logLevel == 2)
						{
							eventLogWorker.AddLogEntry("Success", "Success\r\nUser tried to change the password to a password from Database\r\nPassword: " + pass, 9001);
						}
					}
				}
			}
			catch (Exception err)
			{
				eventLogWorker.AddLogEntry("Error", "Database error\r\n" + err.Message, 9103);
			}

			return result;
		}
	}

	public class JsonResp
	{
		public int successStatus { get; set; }
		public string affinityNodeId { get; set; }
		public string error { get; set; }

		public string sessionToken { get; set; }
		public string response { get; set; }
	}
}
