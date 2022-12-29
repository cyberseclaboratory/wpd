using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.SqlClient;

namespace OPFService
{
	class DBRequest
	{
		private string connDB = "Data Source=localhost;Initial Catalog=Pass;Trusted_Connection=Yes";

		public bool CheckPass(string pass)
		{
			bool result = false;

			string command = "SELECT * FROM passwords WHERE passwords = '" + pass + "';";
			SqlConnection conn = new SqlConnection(connDB);
			SqlCommand cmd = new SqlCommand(command, conn);
			try
			{
				conn.Open();
				using (SqlDataReader reader = cmd.ExecuteReader())
				{
					if (reader.Read())
					{
						result = true;
					}
				}
				conn.Close();
			}
			catch
			{
				//File.AppendAllText("log.txt", DateTime.Now + " " + sqlErr.Message);
			}
			return result;
		}
	}
}
