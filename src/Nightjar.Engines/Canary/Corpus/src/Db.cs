using System.Data.SqlClient;
using System.Diagnostics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

class Db {
    void Find(SqlConnection conn, string name) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        var cmd2 = new SqlCommand($"SELECT * FROM users WHERE name = '{name}'", conn);
        var ok = new SqlCommand("SELECT * FROM users WHERE name = @name", conn);
        var f = new BinaryFormatter();
        var h = MD5.Create();
        Process.Start("cmd", "/c " + name);
    }
}
