using System;
using System.Security.Cryptography;
using System.Text;

public static class AdminLogin
{
    private const int Iterations = 210_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private static bool VerifyHash(string password, string stored)
    {
        string[] parts = stored.Split('.');
        if (parts.Length != 3 || !int.TryParse(parts[0], out int iterations) || iterations < 100_000 || iterations > 5_000_000)
        {
            return false;
        }
        try
        {
            byte[] salt = Convert.FromBase64String(parts[1]);
            byte[] expected = Convert.FromBase64String(parts[2]);
            if (salt.Length < 8 || expected.Length < 16)
            {
                return false;
            }
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool Login(string? user, string? password)
    {
        string? expectedUser = Environment.GetEnvironmentVariable("ADMIN_USER");
        string? storedHash = Environment.GetEnvironmentVariable("ADMIN_PASSWORD_HASH");
        if (string.IsNullOrEmpty(expectedUser) || string.IsNullOrEmpty(storedHash))
        {
            return false; // fail closed: nothing is configured, so nobody gets in
        }
        if (user is null || password is null || user.Length > 64 || password.Length > 128)
        {
            return false;
        }
        byte[] givenUserHash = SHA256.HashData(Encoding.UTF8.GetBytes(user));
        byte[] expectedUserHash = SHA256.HashData(Encoding.UTF8.GetBytes(expectedUser));
        bool userOk = CryptographicOperations.FixedTimeEquals(givenUserHash, expectedUserHash);
        bool passwordOk = VerifyHash(password, storedHash);
        return userOk && passwordOk;
    }

    public static void Main(string[] args)
    {
        Console.Write("User: ");
        string? user = Console.ReadLine();
        Console.Write("Password: ");
        string? password = Console.ReadLine();
        Console.WriteLine(Login(user, password) ? "access granted" : "access denied");
    }
}