using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;
using BruceEDR.Core;
using BruceEDR.Driver;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The minifilter's wire protocol as the agent speaks it. Nothing here loads or talks to a
/// driver: the layouts are checked against kernel\BruceFilter\BruceFilter.h itself, so a
/// change on either side that the other did not follow fails here first.
/// </summary>
public sealed class MinifilterClientTests
{
    private static string Header()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "kernel", "BruceFilter", "BruceFilter.h");
            if (File.Exists(probe)) return File.ReadAllText(probe);
        }
        throw new InvalidOperationException("kernel/BruceFilter/BruceFilter.h was not found above " + AppContext.BaseDirectory);
    }

    private static long Define(string header, string name)
    {
        var m = Regex.Match(header, @"#define\s+" + name + @"\s+(0x[0-9A-Fa-f]+|\d+)u?\b");
        Assert.True(m.Success, name + " is not defined in BruceFilter.h");
        var text = m.Groups[1].Value;
        return text.StartsWith("0x") ? Convert.ToInt64(text[2..], 16) : long.Parse(text);
    }

    private static int EnumValue(string header, string name)
    {
        var m = Regex.Match(header, @"\b" + name + @"\s*=\s*(\d+)");
        Assert.True(m.Success, name + " is not in BruceFilter.h");
        return int.Parse(m.Groups[1].Value);
    }

    private static int SizePin(string header, string type)
    {
        var m = Regex.Match(header, @"sizeof\(" + type + @"\)\s*==\s*(\d+)");
        Assert.True(m.Success, "BruceFilter.h pins no size for " + type);
        return int.Parse(m.Groups[1].Value);
    }

    [Fact]
    public void The_Constants_And_Sizes_Match_The_Driver_Header()
    {
        var h = Header();
        Assert.Equal(MinifilterClient.ProtocolVersion, (uint)Define(h, "BRUCE_PROTOCOL_VERSION"));
        Assert.Equal(MinifilterClient.MaxPath, (int)Define(h, "BRUCE_MAX_PATH"));
        Assert.Equal(MinifilterClient.MaxStores, (int)Define(h, "BRUCE_MAX_ENTRIES"));
        Assert.Equal(MinifilterClient.MaxTrusted, (int)Define(h, "BRUCE_MAX_TRUSTED"));
        Assert.Equal(MinifilterClient.AnyStore, (uint)Define(h, "BRUCE_ANY_PREFIX"));
        Assert.Contains("L\"" + MinifilterClient.PortName.Replace(@"\", @"\\") + "\"", h);

        Assert.Equal(MinifilterClient.MessageSize, SizePin(h, "BRUCE_MESSAGE"));
        Assert.Equal(MinifilterClient.StatusSize, SizePin(h, "BRUCE_STATUS"));
        Assert.Equal(MinifilterClient.NotificationSize, SizePin(h, "BRUCE_NOTIFICATION"));

        Assert.Equal((int)MinifilterClient.Command.SetBlocking, EnumValue(h, "BruceSetBlocking"));
        Assert.Equal((int)MinifilterClient.Command.AddSensitivePath, EnumValue(h, "BruceAddSensitivePath"));
        Assert.Equal((int)MinifilterClient.Command.ClearPolicy, EnumValue(h, "BruceClearPolicy"));
        Assert.Equal((int)MinifilterClient.Command.AddTrustedImage, EnumValue(h, "BruceAddTrustedImage"));
        Assert.Equal((int)MinifilterClient.Command.CommitPolicy, EnumValue(h, "BruceCommitPolicy"));
        Assert.Equal((int)MinifilterClient.Command.QueryStatus, EnumValue(h, "BruceQueryStatus"));

        Assert.Equal((int)KernelOperation.Open, EnumValue(h, "BruceOpOpen"));
        Assert.Equal((int)KernelOperation.Rename, EnumValue(h, "BruceOpRename"));
        Assert.Equal((int)KernelOperation.Link, EnumValue(h, "BruceOpLink"));
        Assert.Equal((int)KernelOperation.Reopen, EnumValue(h, "BruceOpReopen"));
    }

    [Fact]
    public void A_Message_Carries_Command_Flag_And_A_Terminated_Path_In_Place()
    {
        var bytes = MinifilterClient.EncodeMessage(MinifilterClient.Command.AddTrustedImage, 7, @"\Device\X\a.exe");
        Assert.Equal(528, bytes.Length);
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0)));
        Assert.Equal(7u, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)));
        Assert.Equal(@"\Device\X\a.exe", Encoding.Unicode.GetString(bytes, 8, 2 * 15));
        Assert.All(bytes.Skip(8 + 2 * 15), b => Assert.Equal(0, b));
    }

    [Fact]
    public void A_Path_That_Would_Arrive_Cut_Short_Is_Refused()
    {
        // A truncated fragment is a broader one, and a truncated image path names another file.
        Assert.True(MinifilterClient.IsWireText(new string('a', 259)));
        Assert.False(MinifilterClient.IsWireText(new string('a', 260)));
        Assert.False(MinifilterClient.IsWireText(""));
        Assert.False(MinifilterClient.IsWireText(null));
        Assert.False(MinifilterClient.IsWireText("\\a\0b\\"));
        Assert.Throws<ArgumentException>(() =>
            MinifilterClient.EncodeMessage(MinifilterClient.Command.AddSensitivePath, 0, new string('a', 260)));

        var log = new Logger();
        using var client = new MinifilterClient(log);
        Assert.False(client.AddSensitivePath(new string('a', 300)));
        Assert.False(client.AddTrustedImage(@"\Device\X\a.exe", -2));
    }

    [Fact]
    public void A_Status_Reply_Reads_Every_Field()
    {
        var reply = new byte[32];
        uint[] values = { 2, 1, 6, 3, 41, 5, 9, 0 };
        for (int i = 0; i < values.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(i * 4), values[i]);
        var status = MinifilterClient.DecodeStatus(reply);
        Assert.Equal(new KernelStatus(2, true, 6, 3, 41, 5, 9), status);
        Assert.Null(MinifilterClient.DecodeStatus(new byte[31]));
    }

    private static byte[] Notification(uint version, uint operation, uint pid, uint store, string path, string image)
    {
        var body = new byte[1056];
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(0), version);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), operation);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(8), pid);
        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(12), store);
        Encoding.Unicode.GetBytes(path, body.AsSpan(16));
        Encoding.Unicode.GetBytes(image, body.AsSpan(16 + 520));
        return body;
    }

    [Fact]
    public void A_Notification_Reads_Operation_Process_Store_Path_And_Image()
    {
        var body = Notification(2, 2, 4242, 1,
            @"\Device\HarddiskVolume3\Users\bob\AppData\Local\Microsoft\Edge\User Data",
            @"\Device\HarddiskVolume3\Users\bob\Downloads\tool.exe");
        var denial = MinifilterClient.DecodeNotification(body);
        Assert.NotNull(denial);
        Assert.Equal(KernelOperation.Rename, denial!.Operation);
        Assert.Equal(4242, denial.ProcessId);
        Assert.Equal(1, denial.StoreIndex);
        Assert.EndsWith(@"\Edge\User Data", denial.Path);
        Assert.EndsWith(@"\tool.exe", denial.Image);
    }

    [Fact]
    public void An_Unresolved_Name_Has_No_Store()
    {
        var denial = MinifilterClient.DecodeNotification(Notification(2, 4, 8, 0xFFFFFFFF, "", ""));
        Assert.Equal(-1, denial!.StoreIndex);
        Assert.Equal(KernelOperation.Reopen, denial.Operation);
        Assert.Equal("", denial.Path);
    }

    [Fact]
    public void Anything_But_A_Version_2_Notification_Is_Dropped()
    {
        Assert.Null(MinifilterClient.DecodeNotification(Notification(1, 1, 8, 0, "x", "y")));
        Assert.Null(MinifilterClient.DecodeNotification(Notification(2, 0, 8, 0, "x", "y")));
        Assert.Null(MinifilterClient.DecodeNotification(Notification(2, 5, 8, 0, "x", "y")));
        Assert.Null(MinifilterClient.DecodeNotification(Notification(2, 1, 0x80000000, 0, "x", "y")));
        Assert.Null(MinifilterClient.DecodeNotification(new byte[1055]));
    }

    [Fact]
    public void A_Field_Without_A_Terminator_Is_Read_To_Its_End()
    {
        var body = Notification(2, 1, 8, 0, "", "");
        Encoding.Unicode.GetBytes(new string('p', 260), body.AsSpan(16));
        Assert.Equal(new string('p', 260), MinifilterClient.DecodeNotification(body)!.Path);
    }

    [Fact]
    public void Without_The_Driver_Every_Call_Fails_Cleanly()
    {
        // Proves the interop signatures load and return, and nothing more: on a machine with
        // no BruceFilter loaded (or as a process the port refuses) the connect is refused.
        var log = new Logger();
        var client = new MinifilterClient(log);
        if (!client.TryConnect())
        {
            Assert.False(client.Connected);
            Assert.False(client.SetBlocking(false));
            Assert.False(client.ClearPolicy());
            Assert.Null(client.QueryStatus());
            Assert.False(client.StartNotifications(_ => { }));
        }
        client.Dispose();
        client.Dispose();
        Assert.False(client.Connected);
        Assert.False(client.CommitPolicy());
    }
}
