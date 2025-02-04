using System;
using System.Text;
using System.Runtime.InteropServices;

public static class ResourceStringResolver
{
    // Store the original source code as a string (without comments)
    public static string SourceCode = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class ResourceStringResolver
{
    [DllImport(""Shlwapi.dll"", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int SHLoadIndirectString(
        string pszSource, StringBuilder pszOutBuf, int cchOutBuf, IntPtr ppvReserved
    );

    public static string GetString(string rawString)
    {
        if (string.IsNullOrWhiteSpace(rawString)) { return rawString; }
        StringBuilder sb = new StringBuilder(1024);
        int hr = SHLoadIndirectString(rawString, sb, sb.Capacity, IntPtr.Zero);
        return hr != 0 ? rawString : sb.ToString();
    }
}
";

    // SHLoadIndirectString is a Windows API function from Shlwapi.dll. It takes
    // a special "indirect string" (e.g., "@C:\\SomeDll.dll,-101") and resolves
    // that to a user-friendly, localized, or otherwise stored string resource.
    [DllImport("Shlwapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int SHLoadIndirectString(
        // pszSource: This is the indirect string reference that the API will
        // resolve into a readable string. It's often something like
        // "@C:\\Windows\\System32\\shell32.dll,-21787", pointing to a resource.
        string pszSource,
        // pszOutBuf: A buffer that will receive the resolved string. In C#,
        // we use a StringBuilder to represent that buffer.
        StringBuilder pszOutBuf,
        // cchOutBuf: The size (in characters) of pszOutBuf. This helps prevent
        // writing past the end of the buffer.
        int cchOutBuf,
        // ppvReserved: This is normally IntPtr.Zero (null). It's reserved
        // for internal usage or future expansion of the API.
        IntPtr ppvReserved
    );

    // This method wraps SHLoadIndirectString in a C#-friendly way.
    // It returns the resolved string if successful; otherwise, it returns the
    // original string.
    public static string GetString(string rawString)
    {
        // If the string is null or whitespace, there's nothing to resolve.
        // Return it immediately.
        if (string.IsNullOrWhiteSpace(rawString))
        {
            return rawString;
        }
        // Prepare a StringBuilder with a certain capacity to hold the resolved text.
        StringBuilder sb = new StringBuilder(1024);
        // SHLoadIndirectString returns an HRESULT-like integer. 0 (S_OK) means success.
        // Non-zero means failure or some other status.
        int hr = SHLoadIndirectString(rawString, sb, sb.Capacity, IntPtr.Zero);
        // If the function did not succeed, just return the original string.
        if (hr != 0)
        {
            return rawString;
        }
        // If successful, return whatever the API wrote into our StringBuilder.
        return sb.ToString();
    }
}
