using System.Runtime.InteropServices;

namespace CertificateManagerTests
{
    public static class OSHelper
    {
        public static bool IsWindows() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public static bool IsMacOS() =>
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        public static bool IsLinux() => 
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    }
}