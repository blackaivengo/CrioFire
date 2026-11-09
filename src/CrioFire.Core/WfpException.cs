using System.ComponentModel;
using CrioFire.Core.Interop;

namespace CrioFire.Core;

/// <summary>A Windows Filtering Platform call failed.</summary>
public sealed class WfpException : Exception
{
    public WfpException(string operation, uint errorCode)
        : base(Describe(operation, errorCode))
    {
        Operation = operation;
        ErrorCode = errorCode;
    }

    public WfpException()
    {
        Operation = string.Empty;
    }

    public WfpException(string message)
        : base(message)
    {
        Operation = string.Empty;
    }

    public WfpException(string message, Exception innerException)
        : base(message, innerException)
    {
        Operation = string.Empty;
    }

    public string Operation { get; }

    public uint ErrorCode { get; }

    public bool IsAccessDenied => ErrorCode == FwpErrors.ERROR_ACCESS_DENIED;

    private static string Describe(string operation, uint code)
    {
        var detail = code switch
        {
            FwpErrors.ERROR_ACCESS_DENIED => "access denied. Run CrioFire as administrator.",
            FwpErrors.FWP_E_ALREADY_EXISTS => "the object already exists.",
            FwpErrors.FWP_E_FILTER_NOT_FOUND => "no filter with that ID.",
            FwpErrors.FWP_E_PROVIDER_NOT_FOUND or FwpErrors.FWP_E_SUBLAYER_NOT_FOUND =>
                "CrioFire is not installed in the filtering engine. Run 'criofire install' first.",
            FwpErrors.FWP_E_IN_USE => "the object is still in use.",
            _ => new Win32Exception(unchecked((int)code)).Message,
        };

        return $"{operation} failed (0x{code:X8}): {detail}";
    }
}
