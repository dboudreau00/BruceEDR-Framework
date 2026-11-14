using System.Text.RegularExpressions;
using System.Xml.Linq;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Static lint over the WPF XAML.
///
/// The XAML compiler catches structural mistakes, but <c>StaticResource</c> keys are
/// resolved at RUNTIME: a typo in a brush or style key compiles cleanly and then throws
/// the moment the tab is opened. Since the GUI needs Administrator rights to launch (ETW
/// and process access), that class of bug is easy to ship and hard to notice, so it is
/// checked here instead — no WPF, no window, no elevation.
/// </summary>
public class GuiResourceTests
{
    private static readonly Regex StaticResourceRef =
        new(@"\{StaticResource\s+([A-Za-z0-9_.]+)\s*\}", RegexOptions.Compiled);

    /// <summary>Walks up from the test binaries to the GUI project. Null when not in a source tree.</summary>
    private static string? GuiDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "gui", "BruceEDR.Gui");
            if (Directory.Exists(probe)) return probe;
        }
        return null;
    }

    private static IReadOnlyList<string> XamlFiles(string guiDir)
        => Directory.GetFiles(guiDir, "*.xaml", SearchOption.AllDirectories)
                    .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

    /// <summary>Every x:Key defined anywhere in the GUI's XAML.</summary>
    private static HashSet<string> DefinedKeys(IReadOnlyList<string> files)
    {
        XNamespace x = "http://schemas.microsoft.com/winfx/2006/xaml";
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var file in files)
        {
            XDocument doc;
            try { doc = XDocument.Load(file); }
            catch { continue; }   // a malformed file is reported by its own test below
            foreach (var el in doc.Descendants())
            {
                var key = el.Attribute(x + "Key")?.Value;
                if (!string.IsNullOrWhiteSpace(key)) keys.Add(key.Trim());
            }
        }
        return keys;
    }

    [Fact]
    public void Every_Xaml_File_Is_Well_Formed()
    {
        var gui = GuiDirectory();
        if (gui is null) return;   // running from a published layout without sources

        foreach (var file in XamlFiles(gui))
        {
            var ex = Record.Exception(() => XDocument.Load(file));
            Assert.True(ex is null, $"{Path.GetFileName(file)} is not well-formed XML: {ex?.Message}");
        }
    }

    [Fact]
    public void Every_StaticResource_Reference_Resolves_To_A_Defined_Key()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        var files = XamlFiles(gui);
        Assert.NotEmpty(files);

        var defined = DefinedKeys(files);
        Assert.NotEmpty(defined);

        var missing = new List<string>();
        foreach (var file in files)
        {
            string text = File.ReadAllText(file);
            foreach (Match m in StaticResourceRef.Matches(text))
            {
                string key = m.Groups[1].Value;
                if (!defined.Contains(key)) missing.Add($"{Path.GetFileName(file)} -> {{StaticResource {key}}}");
            }
        }

        Assert.True(missing.Count == 0,
            "XAML references resource keys that are never defined; these throw at runtime when the view loads:\n  " +
            string.Join("\n  ", missing));
    }

    [Fact]
    public void Every_Navigation_Tab_Points_At_A_View_That_Exists()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        string mainWindow = Path.Combine(gui, "MainWindow.xaml");
        Assert.True(File.Exists(mainWindow), "MainWindow.xaml is missing");

        // Tabs are declared as <v:SomeView/>, where v maps to the Views namespace.
        var referenced = Regex.Matches(File.ReadAllText(mainWindow), @"<v:([A-Za-z0-9_]+)\s*/?>")
                              .Select(m => m.Groups[1].Value)
                              .Distinct(StringComparer.Ordinal)
                              .ToArray();

        Assert.NotEmpty(referenced);
        foreach (var view in referenced)
        {
            Assert.True(File.Exists(Path.Combine(gui, "Views", view + ".xaml")),
                $"MainWindow references <v:{view}/> but Views/{view}.xaml does not exist");
            Assert.True(File.Exists(Path.Combine(gui, "Views", view + ".xaml.cs")),
                $"Views/{view}.xaml has no code-behind, so InitializeComponent is never generated");
        }
    }

    [Fact]
    public void The_New_Surface_And_Coverage_Tabs_Are_Wired_Into_The_Shell()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        string xaml = File.ReadAllText(Path.Combine(gui, "MainWindow.xaml"));
        Assert.Contains("<v:SurfaceView", xaml, StringComparison.Ordinal);
        Assert.Contains("<v:CoverageView", xaml, StringComparison.Ordinal);
    }

    [Fact]
    public void Incident_Triage_Leads_The_Sidebar()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        string xaml = File.ReadAllText(Path.Combine(gui, "MainWindow.xaml"));
        var first = Regex.Match(xaml, @"<TabItem\b[^>]*>");
        Assert.True(first.Success, "MainWindow.xaml declares no tabs");
        Assert.Contains("Header=\"Incident triage\"", first.Value, StringComparison.Ordinal);
        int next = xaml.IndexOf("<TabItem", first.Index + 1, StringComparison.Ordinal);
        Assert.Contains("<v:TriageView", xaml[first.Index..(next < 0 ? xaml.Length : next)], StringComparison.Ordinal);
    }

    /// <summary>The owner wants the key out of the way: last in Settings, folded shut.</summary>
    [Fact]
    public void The_Assistant_Key_Is_The_Last_Thing_In_Settings_And_Starts_Folded()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        string xaml = File.ReadAllText(Path.Combine(gui, "Views", "SettingsView.xaml"));
        int fold = xaml.IndexOf("AutomationProperties.Name=\"Assistant settings\"", StringComparison.Ordinal);
        int end = xaml.IndexOf("</ScrollViewer>", StringComparison.Ordinal);
        Assert.True(fold > 0 && end > fold, "the Assistant section is missing or outside the scrolled settings");

        string tail = xaml[fold..end];
        Assert.Single(Regex.Matches(tail, @"Style=""\{StaticResource SectionCard\}"""));
        Assert.Contains("Visibility=\"{Binding AssistantOpen", tail, StringComparison.Ordinal);
        int key = xaml.IndexOf("<PasswordBox", StringComparison.Ordinal);
        Assert.True(key > fold && key < end, "the API key field must sit inside the folded Assistant section");
    }

    /// <summary>
    /// Public property names declared in a C# source file. Matched textually rather than by
    /// reflection: referencing the WPF GUI assembly from this test project would force
    /// UseWPF on it, which changes the implicit-using set and breaks every unrelated test.
    /// </summary>
    private static readonly Regex PublicProperty =
        new(@"public\s+(?:static\s+)?[A-Za-z0-9_<>\[\],\.\?\s]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|=>)",
            RegexOptions.Compiled);

    private static HashSet<string> PropertiesDeclaredIn(string guiDir, params string[] relativeSources)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rel in relativeSources)
        {
            string path = Path.Combine(guiDir, rel);
            if (!File.Exists(path)) continue;
            foreach (Match m in PublicProperty.Matches(File.ReadAllText(path)))
                names.Add(m.Groups[1].Value);
        }
        return names;
    }

    [Fact]
    public void Views_Bind_Only_To_Properties_The_View_Model_Actually_Exposes()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        // Only the two new top-level views are checked. They bind to MainViewModel at the
        // page level and to the row types inside item templates, so both sets are allowed.
        string[] checkedViews = { "SurfaceView.xaml", "CoverageView.xaml" };
        var known = PropertiesDeclaredIn(gui,
            Path.Combine("ViewModels", "MainViewModel.cs"),
            Path.Combine("ViewModels", "SurfaceRows.cs"),
            Path.Combine("ViewModels", "Rows.cs"));

        Assert.Contains("Surface", known);        // sanity: the scrape actually found properties
        Assert.Contains("Techniques", known);

        var unknown = new List<string>();
        foreach (var name in checkedViews)
        {
            string path = Path.Combine(gui, "Views", name);
            if (!File.Exists(path)) continue;

            foreach (Match m in Regex.Matches(File.ReadAllText(path), @"\{Binding\s+([A-Za-z0-9_]+)\s*\}"))
            {
                string prop = m.Groups[1].Value;
                if (!known.Contains(prop)) unknown.Add($"{name} -> {{Binding {prop}}}");
            }
        }

        Assert.True(unknown.Count == 0,
            "XAML binds to properties that do not exist on the view model or the row types " +
            "(these silently render blank):\n  " + string.Join("\n  ", unknown));
    }

    [Fact]
    public void The_Triage_View_Binds_Only_To_Members_That_Exist()
    {
        var gui = GuiDirectory();
        if (gui is null) return;

        string view = Path.Combine(gui, "Views", "TriageView.xaml");
        Assert.True(File.Exists(view), "Views/TriageView.xaml is missing");
        string triage = Path.Combine("..", "..", "Assistant", "Triage.cs");
        var known = PropertiesDeclaredIn(gui, Path.Combine("ViewModels", "TriageViewModel.cs"), triage);
        foreach (Match record in Regex.Matches(File.ReadAllText(Path.Combine(gui, triage)), @"record\s+\w+\(([^)]*)\)"))
            foreach (var parameter in record.Groups[1].Value.Split(','))
                known.Add(parameter.Trim().Split(' ').Last());
        known.Add("Count");
        Assert.Contains("NarrationState", known);   // sanity: the scrape found the view model
        Assert.Contains("Glyph", known);            // and the positional Persona record

        var paths = new List<string>();
        string xaml = File.ReadAllText(view);
        foreach (Match m in Regex.Matches(xaml, @"\{Binding(?:\s+([^{}]*))?\}"))
        {
            string body = m.Groups[1].Value.Trim();
            string path = body.Split(',')[0].Trim();
            if (path.StartsWith("Path=", StringComparison.Ordinal)) path = path[5..];
            if (path.Length == 0 || path.Contains('=')) continue;
            if (Regex.IsMatch(body, @"\b(ElementName|Source)=")) continue;
            if (body.Contains("RelativeSource=", StringComparison.Ordinal))
            {
                // Rows reach the page's commands through the UserControl's DataContext.
                if (!body.Contains("AncestorType=UserControl", StringComparison.Ordinal) ||
                    !path.StartsWith("DataContext.", StringComparison.Ordinal)) continue;
                path = path["DataContext.".Length..];
            }
            paths.Add(path);
        }
        foreach (Match m in Regex.Matches(xaml, @"<Binding\s+Path=""([^""]+)""([^>]*)>"))
            if (!Regex.IsMatch(m.Groups[2].Value, @"\b(ElementName|RelativeSource)="))
                paths.Add(m.Groups[1].Value);

        Assert.NotEmpty(paths);
        var unknown = paths.Where(p => p.Split('.').Any(segment => !known.Contains(segment))).Distinct().ToList();
        Assert.True(unknown.Count == 0,
            "TriageView.xaml binds to members that do not exist (they render blank):\n  " + string.Join("\n  ", unknown));
    }
}
