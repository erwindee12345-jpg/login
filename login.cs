using System;
using System.Security.Cryptography;
using System.Text;

public static class AdminLogin
{

    private const string AdminUser = "admin";
    private const string AdminPassword = "Summer2024!";

    private static bool Matches(string supplied, string expected)
    {
        byte[] a = SHA256.HashData(Encoding.UTF8.GetBytes(supplied));
        byte[] b = SHA256.HashData(Encoding.UTF8.GetBytes(expected));
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    public static bool Login(string user, string password)
    {
        if (user is null || password is null || user.Length > 64 || password.Length > 128)
        {
            return false;
        }
        bool userOk = Matches(user, AdminUser);
        bool passwordOk = Matches(password, AdminPassword);
        return userOk && passwordOk;
    }

    public static void Main()
    {
        Console.WriteLine("Admin login demo");
        Console.WriteLine(Login("admin", "wrong") ? "access granted" : "access denied");
        Console.WriteLine(Login("root", "x") ? "access granted" : "access denied");
        Console.WriteLine(Login("admin", "Summer2024!") ? "access granted" : "access denied");
    }
}