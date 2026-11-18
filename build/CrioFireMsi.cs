// Windows Installer's own functions (msi.dll) for the build scripts, loaded with Add-Type:
// package-msi.ps1 makes, checks and stores the language transforms; test-msi-upgrade.ps1 makes
// other versions of an MSI to install over each other.
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

public static class CrioFireMsi
{
    const uint NoData = 232, MoreData = 234, NoMoreItems = 259;

    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiOpenDatabaseW(string path, IntPtr persist, out IntPtr database);
    [DllImport("msi.dll")] static extern uint MsiCloseHandle(IntPtr handle);
    [DllImport("msi.dll")] static extern uint MsiDatabaseCommit(IntPtr database);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiDatabaseGenerateTransformW(IntPtr database, IntPtr reference, string transform, int reserved1, int reserved2);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiCreateTransformSummaryInfoW(IntPtr database, IntPtr reference, string transform, int errorConditions, int validation);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiDatabaseApplyTransformW(IntPtr database, string transform, int errorConditions);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiDatabaseOpenViewW(IntPtr database, string query, out IntPtr view);
    [DllImport("msi.dll")] static extern uint MsiViewExecute(IntPtr view, IntPtr record);
    [DllImport("msi.dll")] static extern uint MsiViewFetch(IntPtr view, out IntPtr record);
    [DllImport("msi.dll")] static extern uint MsiViewModify(IntPtr view, int mode, IntPtr record);
    [DllImport("msi.dll")] static extern IntPtr MsiCreateRecord(uint fields);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiRecordGetStringW(IntPtr record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiRecordSetStringW(IntPtr record, uint field, string value);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiRecordSetStreamW(IntPtr record, uint field, string file);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiGetSummaryInformationW(IntPtr database, string path, uint updateCount, out IntPtr summary);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiSummaryInfoGetPropertyW(IntPtr summary, uint property, out uint type, out int number, ref FILETIME time, StringBuilder value, ref uint length);
    [DllImport("msi.dll", CharSet = CharSet.Unicode)] static extern uint MsiSummaryInfoSetPropertyW(IntPtr summary, uint property, uint type, int number, ref FILETIME time, string value);
    [DllImport("msi.dll")] static extern uint MsiSummaryInfoPersist(IntPtr summary);

    static void Check(uint result, string what)
    {
        if (result != 0) throw new InvalidOperationException(what + " failed: Windows Installer error " + result + ".");
    }

    static IntPtr Open(string path, bool write)
    {
        IntPtr database;
        Check(MsiOpenDatabaseW(path, new IntPtr(write ? 1 : 0), out database), "Opening " + path);
        return database;
    }

    static void Close(IntPtr handle)
    {
        if (handle != IntPtr.Zero) MsiCloseHandle(handle);
    }

    /// <summary>The first column of the first row the query finds, or null.</summary>
    static string Query(IntPtr database, string sql)
    {
        IntPtr view, record;
        Check(MsiDatabaseOpenViewW(database, sql, out view), "Query " + sql);
        try
        {
            Check(MsiViewExecute(view, IntPtr.Zero), "Query " + sql);
            uint fetched = MsiViewFetch(view, out record);
            if (fetched == NoMoreItems) return null;
            Check(fetched, "Query " + sql);
            try
            {
                uint length = 1024;
                var value = new StringBuilder((int)length);
                uint result = MsiRecordGetStringW(record, 1, value, ref length);
                if (result == MoreData)
                {
                    length++;
                    value = new StringBuilder((int)length);
                    result = MsiRecordGetStringW(record, 1, value, ref length);
                }
                Check(result, "Query " + sql);
                return value.ToString();
            }
            finally { Close(record); }
        }
        finally { Close(view); }
    }

    /// <summary>
    /// A transform from the English MSI to a localized one, applicable without validation or error
    /// conditions. False when they do not differ.
    /// </summary>
    public static bool MakeTransform(string englishMsi, string localizedMsi, string transform)
    {
        IntPtr english = Open(englishMsi, false), localized = Open(localizedMsi, false);
        try
        {
            uint result = MsiDatabaseGenerateTransformW(localized, english, transform, 0, 0);
            if (result == NoData) return false;
            Check(result, "Making " + transform);
            Check(MsiCreateTransformSummaryInfoW(localized, english, transform, 0, 0), "Writing the summary of " + transform);
            return true;
        }
        finally { Close(localized); Close(english); }
    }

    /// <summary>Answers to the queries after applying a transform to a scratch copy of an MSI (not saved).</summary>
    public static string[] QueryTransformed(string scratchMsi, string transform, string[] queries)
    {
        IntPtr database = Open(scratchMsi, true);
        try
        {
            Check(MsiDatabaseApplyTransformW(database, transform, 0), "Applying " + transform);
            var answers = new string[queries.Length];
            for (int i = 0; i < queries.Length; i++) answers[i] = Query(database, queries[i]);
            return answers;
        }
        finally { Close(database); }
    }

    public static string QueryMsi(string msi, string query)
    {
        IntPtr database = Open(msi, false);
        try { return Query(database, query); }
        finally { Close(database); }
    }

    /// <summary>
    /// Stores each transform as a substorage of the MSI under its name (a language ID) and sets the
    /// Template summary property to the platform and the languages.
    /// </summary>
    public static string Embed(string msi, string[] names, string[] transforms, string languages)
    {
        IntPtr database = Open(msi, true), view = IntPtr.Zero, summary = IntPtr.Zero;
        try
        {
            Check(MsiDatabaseOpenViewW(database, "SELECT `Name`, `Data` FROM `_Storages`", out view), "Opening _Storages");
            Check(MsiViewExecute(view, IntPtr.Zero), "Opening _Storages");
            for (int i = 0; i < names.Length; i++)
            {
                IntPtr record = MsiCreateRecord(2);
                try
                {
                    Check(MsiRecordSetStringW(record, 1, names[i]), "Naming storage " + names[i]);
                    Check(MsiRecordSetStreamW(record, 2, transforms[i]), "Reading " + transforms[i]);
                    Check(MsiViewModify(view, 3 /* MSIMODIFY_ASSIGN */, record), "Storing " + names[i]);
                }
                finally { Close(record); }
            }
            Close(view);
            view = IntPtr.Zero;

            Check(MsiGetSummaryInformationW(database, null, 1, out summary), "Opening the summary information");
            uint type, length = 256;
            int number;
            var time = new FILETIME();
            var template = new StringBuilder((int)length);
            Check(MsiSummaryInfoGetPropertyW(summary, 7, out type, out number, ref time, template, ref length), "Reading Template");
            string platform = template.ToString().Split(';')[0];
            string value = platform + ";" + languages;
            Check(MsiSummaryInfoSetPropertyW(summary, 7, 30 /* VT_LPSTR */, 0, ref time, value), "Writing Template");
            Check(MsiSummaryInfoPersist(summary), "Saving the summary information");
            Check(MsiDatabaseCommit(database), "Saving " + msi);
            return value;
        }
        finally { Close(summary); Close(view); Close(database); }
    }

    /// <summary>
    /// Turns an MSI (a copy) into another build of the same product: a new ProductCode and package
    /// code, and the given version, or the same one when null. Used to test upgrades and downgrades.
    /// </summary>
    public static void MakeVariant(string msi, string version)
    {
        IntPtr database = Open(msi, true), summary = IntPtr.Zero;
        try
        {
            // PowerShell passes $null to a string parameter as "", so both keep the version.
            if (!string.IsNullOrEmpty(version)) SetProperty(database, "ProductVersion", version);
            SetProperty(database, "ProductCode", "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}");

            Check(MsiGetSummaryInformationW(database, null, 1, out summary), "Opening the summary information");
            var time = new FILETIME();
            Check(MsiSummaryInfoSetPropertyW(summary, 9 /* PID_REVISIONNUMBER: the package code */, 30 /* VT_LPSTR */, 0, ref time,
                "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}"), "Writing the package code");
            Check(MsiSummaryInfoPersist(summary), "Saving the summary information");
            Check(MsiDatabaseCommit(database), "Saving " + msi);
        }
        finally { Close(summary); Close(database); }
    }

    static void SetProperty(IntPtr database, string name, string value)
    {
        IntPtr view;
        Check(MsiDatabaseOpenViewW(database, "UPDATE `Property` SET `Value` = '" + value.Replace("'", "''") + "' WHERE `Property` = '" + name + "'", out view), "Setting " + name);
        try { Check(MsiViewExecute(view, IntPtr.Zero), "Setting " + name); }
        finally { Close(view); }
    }
}
