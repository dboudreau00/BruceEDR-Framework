using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Assistant;
using BruceEDR.Gui.Services;

namespace BruceEDR.Gui.ViewModels;

/// <summary>
/// Which provider and model explain incidents, and whether the digest is redacted. Persisted in
/// ui-state.json; the key itself lives in the DPAPI store, never here.
/// </summary>
public sealed class AssistantSettings : ViewModelBase
{
    private readonly UiState? _ui;
    public ApiKeyStore Keys { get; }

    public AssistantSettings(UiState? ui, ApiKeyStore keys)
    {
        _ui = ui;
        Keys = keys;
        if (ui is not null && Enum.TryParse<LlmProvider>(ui.AssistantProvider, out var p)) _provider = p;
        _redact = ui?.AssistantRedact ?? true;
    }

    public IReadOnlyList<LlmProvider> Providers { get; } = Enum.GetValues<LlmProvider>();

    private LlmProvider _provider = LlmProvider.Claude;
    public LlmProvider Provider
    {
        get => _provider;
        set
        {
            if (!Set(ref _provider, value)) return;
            if (_ui is not null) { _ui.AssistantProvider = value.ToString(); _ui.Save(); }
            OnPropertyChanged(nameof(Model));
            RaiseKey();
        }
    }

    public string Model
    {
        get => _ui?.AssistantModels.TryGetValue(_provider.ToString(), out var m) == true && LlmWire.IsValidModel(m)
            ? m! : LlmWire.DefaultModel(_provider);
        set
        {
            if (_ui is null || !LlmWire.IsValidModel(value)) return;
            _ui.AssistantModels[_provider.ToString()] = value.Trim();
            _ui.Save();
            OnPropertyChanged();
        }
    }

    private bool _redact = true;
    public bool Redact
    {
        get => _redact;
        set
        {
            if (!Set(ref _redact, value)) return;
            if (_ui is not null) { _ui.AssistantRedact = value; _ui.Save(); }
        }
    }

    public bool HasKey => Keys.Has(_provider);
    public string ProviderName => LlmWire.DisplayName(_provider);
    public string Vendor => LlmWire.Vendor(_provider);

    public void RaiseKey()
    {
        OnPropertyChanged(nameof(HasKey));
        OnPropertyChanged(nameof(ProviderName));
        OnPropertyChanged(nameof(Vendor));
    }
}

/// <summary>A recorded detection in the library list.</summary>
public sealed class IncidentItem : ViewModelBase
{
    public IncidentCase Case { get; private set; }

    public IncidentItem(IncidentCase c) => Case = c;

    public void Update(IncidentCase c)
    {
        Case = c;
        OnPropertyChanged(string.Empty);
    }

    public string Key => Case.Key;
    public string Title => Case.ProcessName;
    public int Pid => Case.Pid;
    public int Score => Case.Score;
    public string State => Case.State;
    public string Severity => Case.State is "Contained" or "Would contain" || Case.Score >= Case.ContainAt ? "threat" : "watch";
    public bool IsReplay => Case.IsReplay;
    public string SourceLabel => Case.IsReplay ? "REPLAY" : "LIVE";
    public string Source => Case.Source;
    public string TimeLabel => Case.FirstSeenUtc.ToLocalTime().ToString("MMM d  HH:mm", CultureInfo.CurrentCulture);
    public int StepCount => Case.Steps.Count;
    public int TechniqueCount => Case.Techniques.Count;
    public IReadOnlyList<string> Stages => Case.Steps.Select(s => s.Stage).Distinct().ToArray();

    private IReadOnlyList<Persona> _answered = Array.Empty<Persona>();
    /// <summary>Readers this incident already has a saved answer for.</summary>
    public IReadOnlyList<Persona> Answered { get => _answered; set { if (Set(ref _answered, value)) OnPropertyChanged(nameof(HasAnswers)); } }
    public bool HasAnswers => _answered.Count > 0;
}

/// <summary>One log step of the selected incident, and one node of the scene.</summary>
public sealed class StepItem : ViewModelBase
{
    public IncidentStep Step { get; }

    public StepItem(IncidentStep s) => Step = s;

    public int Number => Step.Number;
    public string Time => Step.TimeUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture);
    public string Stage => Step.Stage;
    public string Points => (Step.Points >= 0 ? "+" : "") + Step.Points.ToString(CultureInfo.CurrentCulture);
    public int ScoreAfter => Step.ScoreAfter;
    public string Title => Step.Title;
    public IReadOnlyList<string> Evidence => Step.Evidence;
    public IReadOnlyList<string> Techniques => Step.Techniques;
    /// <summary>threat | watch | info, from the points the step added.</summary>
    public string Severity => Step.Points >= 60 ? "threat" : Step.Points >= 25 ? "watch" : "info";

    private string _explanation = "";
    /// <summary>The reader-facing explanation once the model has written it, else empty.</summary>
    public string Explanation
    {
        get => _explanation;
        set { if (Set(ref _explanation, value)) { OnPropertyChanged(nameof(IsExplained)); OnPropertyChanged(nameof(Caption)); } }
    }
    public bool IsExplained => _explanation.Length > 0;
    /// <summary>What the scene caption shows: the explanation, or the engine's own words until there is one.</summary>
    public string Caption => IsExplained ? _explanation : Step.Title;

    private bool _isRevealed;
    public bool IsRevealed { get => _isRevealed; set => Set(ref _isRevealed, value); }

    private bool _isCurrent;
    public bool IsCurrent { get => _isCurrent; set => Set(ref _isCurrent, value); }
}

/// <summary>
/// Incident triage: a library of recorded detections, their log steps, and a scene that replays
/// one incident as an animated mind map while a model explains it for the chosen reader. One
/// answer is generated per incident and reader and cached; Refresh regenerates it.
/// </summary>
public sealed class TriageViewModel : ViewModelBase
{
    public const double BaseStepSeconds = 3.6;
    private const double RevealCharsPerSecond = 140;

    private readonly TriageStore _store;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _playTimer;
    private readonly DispatcherTimer _revealTimer;
    private readonly DispatcherTimer _saveTimer;
    private readonly HashSet<string> _dirty = new();
    private readonly Dictionary<string, Run> _runs = new();
    private Run? _attached;
    private int _revealed;

    /// <summary>Produces answers. The offscreen harness swaps in a scripted generator.</summary>
    public ITriageGenerator Generator { get; set; } = new TriageNarrator();

    public AssistantSettings Assistant { get; }

    public ObservableCollection<IncidentItem> Incidents { get; } = new();
    public ObservableCollection<StepItem> Logs { get; } = new();
    public ObservableCollection<StepItem> SceneSteps { get; } = new();
    public ObservableCollection<string> NextSteps { get; } = new();
    public IReadOnlyList<Persona> PersonaOptions => Personas.All;

    public TriageViewModel(TriageStore store, AssistantSettings assistant)
    {
        _store = store;
        Assistant = assistant;
        _dispatcher = Dispatcher.CurrentDispatcher;

        _playTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(BaseStepSeconds) };
        _playTimer.Tick += (_, _) => Advance();
        _revealTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(33) };
        _revealTimer.Tick += (_, _) => RevealTick();
        _saveTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _saveTimer.Tick += (_, _) => FlushSaves();

        OpenLogCommand = new RelayCommandP(p => { if (p is StepItem s) OpenScene(SelectedIncident, s.Number); });
        PlaySceneCommand = new RelayCommand(() => OpenScene(SelectedIncident, 1), () => SelectedIncident is not null);
        BackCommand = new RelayCommand(Back);
        PlayPauseCommand = new RelayCommand(TogglePlay, () => IsSceneOpen);
        RestartCommand = new RelayCommand(() => StartAt(1), () => IsSceneOpen);
        NextStepCommand = new RelayCommand(() => Step(+1), () => IsSceneOpen && CurrentStep < SceneSteps.Count);
        PrevStepCommand = new RelayCommand(() => Step(-1), () => IsSceneOpen && CurrentStep > 1);
        JumpToStepCommand = new RelayCommandP(p => { if (p is StepItem s) JumpTo(s.Number); });
        SetSpeedCommand = new RelayCommandP(p => { if (double.TryParse(p as string, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)) Speed = v; });
        RefreshCommand = new RelayCommand(() => Generate(force: true), () => IsSceneOpen && Assistant.HasKey && !IsGenerating);
        CopyAnswerCommand = new RelayCommand(CopyAnswer, () => NarrationText.Length > 0);
        DeleteIncidentCommand = new RelayCommandP(p => { if (p is IncidentItem i) Delete(i); });
        ClearHistoryCommand = new RelayCommand(ClearHistory, () => Incidents.Count > 0);

        Assistant.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(AssistantSettings.HasKey) or nameof(AssistantSettings.Provider))
            {
                OnPropertyChanged(nameof(ProviderLabel));
                if (IsSceneOpen && NarrationState == "nokey" && Assistant.HasKey) Generate(force: false);
                if (IsSceneOpen && !Assistant.HasKey && NarrationState is "idle") NarrationState = "nokey";
                CommandManager.InvalidateRequerySuggested();
            }
        };

        try
        {
            foreach (var c in _store.LoadIncidents()) Incidents.Add(Decorate(new IncidentItem(c)));
        }
        catch (Exception ex) { AppLog.Error("triage load", ex); }
        OnPropertyChanged(nameof(HasIncidents));
        SelectedIncident = Incidents.FirstOrDefault();
    }

    // ------------------------------------------------------------------ commands
    public ICommand OpenLogCommand { get; }
    public ICommand PlaySceneCommand { get; }
    public ICommand BackCommand { get; }
    public ICommand PlayPauseCommand { get; }
    public ICommand RestartCommand { get; }
    public ICommand NextStepCommand { get; }
    public ICommand PrevStepCommand { get; }
    public ICommand JumpToStepCommand { get; }
    public ICommand SetSpeedCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand CopyAnswerCommand { get; }
    public ICommand DeleteIncidentCommand { get; }
    public ICommand ClearHistoryCommand { get; }

    // ------------------------------------------------------------------ library
    public bool HasIncidents => Incidents.Count > 0;

    private IncidentItem? _selected;
    public IncidentItem? SelectedIncident
    {
        get => _selected;
        set
        {
            if (!Set(ref _selected, value)) return;
            Logs.Clear();
            if (value is not null) foreach (var s in value.Case.Steps) Logs.Add(new StepItem(s));
            OnPropertyChanged(nameof(HasSelection));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool HasSelection => _selected is not null;

    /// <summary>Called by the main view model as profiles change; adds or refreshes a library entry.</summary>
    public void Upsert(IncidentCase c)
    {
        var existing = Incidents.FirstOrDefault(i => i.Key == c.Key);
        bool changed = existing is null || existing.Case.Steps.Count != c.Steps.Count || existing.Case.Score != c.Score
                       || existing.Case.State != c.State;
        if (!changed) return;
        if (existing is null)
        {
            Incidents.Insert(0, Decorate(new IncidentItem(c)));
            OnPropertyChanged(nameof(HasIncidents));
            SelectedIncident ??= Incidents[0];
        }
        else
        {
            existing.Update(c);
            if (ReferenceEquals(existing, _selected))
            {
                Logs.Clear();
                foreach (var s in c.Steps) Logs.Add(new StepItem(s));
            }
        }
        _dirty.Add(c.Key);
        if (!_saveTimer.IsEnabled) _saveTimer.Start();
    }

    public void FlushSaves()
    {
        _saveTimer.Stop();
        foreach (var key in _dirty.ToArray())
        {
            var item = Incidents.FirstOrDefault(i => i.Key == key);
            if (item is null) continue;
            try { _store.SaveIncident(item.Case); }
            catch (Exception ex) { AppLog.Error("triage save", ex); }
        }
        _dirty.Clear();
    }

    private IncidentItem Decorate(IncidentItem item)
    {
        try { item.Answered = _store.AnsweredPersonas(item.Key).Select(Personas.Get).Distinct().ToArray(); }
        catch (Exception ex) { AppLog.Error("triage answers", ex); }
        return item;
    }

    private void Delete(IncidentItem item)
    {
        if (IsSceneOpen && ReferenceEquals(SceneIncident, item)) Back();
        try { _store.DeleteIncident(item.Key); }
        catch (Exception ex)
        {
            AppLog.Error("triage delete", ex);
            MessageBox.Show("The incident could not be deleted: " + ex.Message, "Delete incident",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        Incidents.Remove(item);
        if (ReferenceEquals(_selected, item)) SelectedIncident = Incidents.FirstOrDefault();
        OnPropertyChanged(nameof(HasIncidents));
    }

    private void ClearHistory()
    {
        var answer = MessageBox.Show(
            "This deletes every recorded detection and every saved explanation from this computer.\n\nClear the history?",
            "Clear incident history", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        if (IsSceneOpen) Back();
        try { _store.Clear(); }
        catch (Exception ex)
        {
            AppLog.Error("triage clear", ex);
            MessageBox.Show("The history could not be cleared: " + ex.Message, "Clear incident history",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        Incidents.Clear();
        _dirty.Clear();
        SelectedIncident = null;
        OnPropertyChanged(nameof(HasIncidents));
    }

    // ------------------------------------------------------------------ scene
    private bool _isSceneOpen;
    public bool IsSceneOpen
    {
        get => _isSceneOpen;
        private set { if (Set(ref _isSceneOpen, value)) { OnPropertyChanged(nameof(IsLibraryOpen)); CommandManager.InvalidateRequerySuggested(); } }
    }
    public bool IsLibraryOpen => !_isSceneOpen;

    private IncidentItem? _sceneIncident;
    public IncidentItem? SceneIncident { get => _sceneIncident; private set => Set(ref _sceneIncident, value); }

    private int _currentStep;
    /// <summary>1-based step on stage; 0 before the first.</summary>
    public int CurrentStep
    {
        get => _currentStep;
        private set
        {
            if (!Set(ref _currentStep, value)) return;
            for (int i = 0; i < SceneSteps.Count; i++) SceneSteps[i].IsCurrent = i == value - 1;
            OnPropertyChanged(nameof(Current));
            OnPropertyChanged(nameof(Progress));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public StepItem? Current => _currentStep >= 1 && _currentStep <= SceneSteps.Count ? SceneSteps[_currentStep - 1] : null;
    /// <summary>0 to 100 through the scene, for the scrubber.</summary>
    public double Progress => SceneSteps.Count == 0 ? 0 : 100.0 * _currentStep / SceneSteps.Count;

    private bool _isPlaying;
    public bool IsPlaying { get => _isPlaying; private set => Set(ref _isPlaying, value); }

    private double _speed = 1;
    public double Speed
    {
        get => _speed;
        set
        {
            if (!Set(ref _speed, Math.Clamp(value, 0.5, 4))) return;
            _playTimer.Interval = TimeSpan.FromSeconds(BaseStepSeconds / _speed);
        }
    }

    private bool _isFinished;
    public bool IsFinished { get => _isFinished; private set => Set(ref _isFinished, value); }

    public void OpenScene(IncidentItem? item, int startStep)
    {
        if (item is null) return;
        SceneIncident = item;
        SceneSteps.Clear();
        foreach (var s in item.Case.Steps) SceneSteps.Add(new StepItem(s));
        IsSceneOpen = true;
        LoadNarration();
        StartAt(Math.Clamp(startStep, 1, Math.Max(1, SceneSteps.Count)));
    }

    private void StartAt(int step)
    {
        IsFinished = false;
        for (int i = 0; i < SceneSteps.Count; i++) SceneSteps[i].IsRevealed = i < step;
        CurrentStep = SceneSteps.Count == 0 ? 0 : step;
        IsPlaying = SceneSteps.Count > 0;
        _playTimer.Stop();
        if (IsPlaying) _playTimer.Start();
    }

    private void Advance()
    {
        if (_currentStep >= SceneSteps.Count)
        {
            _playTimer.Stop();
            IsPlaying = false;
            IsFinished = true;
            return;
        }
        JumpTo(_currentStep + 1, keepPlaying: true);
    }

    private void JumpTo(int step, bool keepPlaying = false)
    {
        if (step < 1 || step > SceneSteps.Count) return;
        for (int i = 0; i < SceneSteps.Count; i++)
            if (i < step) SceneSteps[i].IsRevealed = true;
        CurrentStep = step;
        IsFinished = false;
        if (!keepPlaying && IsPlaying) { _playTimer.Stop(); _playTimer.Start(); }
    }

    private void Step(int delta) => JumpTo(_currentStep + delta);

    private void TogglePlay()
    {
        if (IsFinished) { StartAt(1); return; }
        IsPlaying = !IsPlaying;
        if (IsPlaying) _playTimer.Start(); else _playTimer.Stop();
    }

    private void Back()
    {
        _playTimer.Stop();
        IsPlaying = false;
        IsSceneOpen = false;
        Detach();
        if (SceneIncident is not null) Decorate(SceneIncident);
    }

    // ------------------------------------------------------------------ narration
    private Persona _persona = Personas.All[0];
    public Persona SelectedPersona
    {
        get => _persona;
        set
        {
            if (value is null || !Set(ref _persona, value)) return;
            if (IsSceneOpen) LoadNarration();
        }
    }

    private string _state = "idle";
    /// <summary>nokey | waiting | streaming | done | error | refused | idle</summary>
    public string NarrationState
    {
        get => _state;
        private set
        {
            if (!Set(ref _state, value)) return;
            OnPropertyChanged(nameof(IsGenerating));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool IsGenerating => _state is "waiting" or "streaming";

    private string _text = "";
    /// <summary>The answer as revealed so far (raw line format).</summary>
    public string NarrationText { get => _text; private set => Set(ref _text, value); }

    private string _headline = "";
    public string Headline { get => _headline; private set => Set(ref _headline, value); }

    private string _impact = "";
    public string Impact { get => _impact; private set => Set(ref _impact, value); }

    private string _typing = "";
    /// <summary>The line the model is writing right now, for the live caret.</summary>
    public string TypingLine { get => _typing; private set => Set(ref _typing, value); }

    private int _explained;
    public int ExplainedCount { get => _explained; private set => Set(ref _explained, value); }

    private string _error = "";
    public string NarrationError { get => _error; private set => Set(ref _error, value); }

    private bool _isCached;
    public bool IsCached { get => _isCached; private set => Set(ref _isCached, value); }

    private string _answerSource = "";
    /// <summary>"Saved answer · Gemini · model · time" or the live equivalent.</summary>
    public string AnswerSource { get => _answerSource; private set => Set(ref _answerSource, value); }

    private string _elapsed = "";
    public string ElapsedText { get => _elapsed; private set => Set(ref _elapsed, value); }

    public string ProviderLabel => $"{Assistant.ProviderName} · {Assistant.Model}";

    private void LoadNarration()
    {
        Detach();
        ResetNarration();
        var item = SceneIncident;
        if (item is null) return;

        TriageAnswer? cached = null;
        try { cached = _store.LoadAnswer(item.Key, _persona.Id); }
        catch (Exception ex) { AppLog.Error("triage cache", ex); }
        if (cached is not null && cached.Text.Length > 0)
        {
            IsCached = true;
            AnswerSource = $"Saved answer · {cached.Provider} · {cached.Model} · {cached.CreatedUtc.ToLocalTime():MMM d HH:mm}";
            _revealed = cached.Text.Length;
            ApplyText(cached.Text, streaming: false);
            NarrationState = cached.Refused ? "refused" : "done";
            return;
        }
        if (_runs.TryGetValue(RunKey(item.Key, _persona.Id), out var running) && !running.Completed)
        {
            Attach(running);
            return;
        }
        if (!Assistant.HasKey) { NarrationState = "nokey"; return; }
        Generate(force: false);
    }

    private void ResetNarration()
    {
        _revealed = 0;
        NarrationText = "";
        Headline = "";
        Impact = "";
        TypingLine = "";
        ExplainedCount = 0;
        NarrationError = "";
        IsCached = false;
        AnswerSource = "";
        ElapsedText = "";
        NextSteps.Clear();
        foreach (var s in SceneSteps) s.Explanation = "";
        NarrationState = "idle";
    }

    private void Generate(bool force)
    {
        var item = SceneIncident;
        if (item is null) return;
        if (!Assistant.HasKey) { NarrationState = "nokey"; return; }
        string runKey = RunKey(item.Key, _persona.Id);
        if (!force && _runs.TryGetValue(runKey, out var existing) && !existing.Completed) { Attach(existing); return; }

        string? key = Assistant.Keys.Load(Assistant.Provider);
        if (string.IsNullOrEmpty(key))
        {
            NarrationState = "error";
            NarrationError = "The saved API key could not be read. Save it again in Settings, Assistant.";
            return;
        }

        Detach();
        ResetNarration();
        var run = new Run(runKey, item, _persona, Assistant.Provider, Assistant.Model, Assistant.Redact);
        _runs[runKey] = run;
        Attach(run);
        var request = new TriageRequest(run.Provider, run.Model, key, run.Persona, item.Case, run.Redact);
        key = null;
        _ = RunAsync(run, request);
    }

    private async Task RunAsync(Run run, TriageRequest request)
    {
        TriageResult result;
        try
        {
            result = await Task.Run(() => Generator.GenerateAsync(request, chunk =>
            {
                lock (run.Buffer) run.Buffer.Append(chunk);
            }, run.Cancel.Token));
        }
        catch (Exception ex)
        {
            AppLog.Error("triage generate", ex);
            result = new TriageResult(run.Snapshot(), false, "", "The explanation failed: " + ex.Message);
        }
        await _dispatcher.InvokeAsync(() => Complete(run, result));
    }

    private void Complete(Run run, TriageResult result)
    {
        run.Completed = true;
        run.Result = result;
        string text = result.Text;
        if (text.Length > 0 && result.Error.Length == 0)
        {
            var answer = new TriageAnswer
            {
                IncidentKey = run.Item.Key,
                PersonaId = run.Persona.Id,
                Provider = LlmWire.DisplayName(run.Provider),
                Model = run.Model,
                CreatedUtc = DateTime.UtcNow,
                Text = text,
                Refused = result.Refused,
                Redacted = run.Redact,
            };
            try
            {
                _store.SaveAnswer(answer);
                Decorate(run.Item);
            }
            catch (Exception ex) { AppLog.Error("triage cache save", ex); }
        }
        _runs.Remove(run.Key);
        if (!ReferenceEquals(_attached, run)) return;
        if (_revealed >= text.Length || text.Length == 0) Finish(run);
    }

    private void Attach(Run run)
    {
        _attached = run;
        AnswerSource = $"{LlmWire.DisplayName(run.Provider)} · {run.Model}" + (run.Redact ? " · redacted" : "");
        NarrationState = "waiting";
        _revealTimer.Start();
    }

    private void Detach()
    {
        _attached = null;
        _revealTimer.Stop();
    }

    private void RevealTick()
    {
        var run = _attached;
        if (run is null) { _revealTimer.Stop(); return; }
        string buffer = run.Snapshot();
        ElapsedText = $"{(DateTime.UtcNow - run.StartedUtc).TotalSeconds:F0} s";

        if (buffer.Length > _revealed)
        {
            NarrationState = "streaming";
            // Reveal at a steady typing pace, catching up if the provider is far ahead.
            int backlog = buffer.Length - _revealed;
            int step = Math.Max((int)(RevealCharsPerSecond * _revealTimer.Interval.TotalSeconds), backlog / 45);
            _revealed = Math.Min(buffer.Length, _revealed + Math.Max(1, step));
            ApplyText(buffer[.._revealed], streaming: true);
        }
        else if (run.Completed)
        {
            Finish(run);
        }
    }

    private void Finish(Run run)
    {
        _revealTimer.Stop();
        var result = run.Result!;
        ApplyText(result.Text, streaming: false);
        if (result.Error.Length > 0)
        {
            NarrationState = "error";
            NarrationError = result.Error;
        }
        else if (result.Refused && result.Text.Length == 0) NarrationState = "refused";
        else NarrationState = result.Refused ? "refused" : "done";
        if (NarrationState == "done") AnswerSource = $"{LlmWire.DisplayName(run.Provider)} · {run.Model} · just now";
    }

    private void ApplyText(string text, bool streaming)
    {
        NarrationText = text;
        var n = Narration.Parse(text, streaming);
        Headline = n.Headline;
        Impact = n.Impact;
        TypingLine = streaming ? n.Partial : "";
        int count = 0;
        foreach (var s in SceneSteps)
        {
            if (n.Steps.TryGetValue(s.Number, out var line)) { s.Explanation = line; count++; }
        }
        ExplainedCount = count;
        if (NextSteps.Count != n.Next.Count || !NextSteps.SequenceEqual(n.Next))
        {
            NextSteps.Clear();
            foreach (var x in n.Next) NextSteps.Add(x);
        }
    }

    private void CopyAnswer()
    {
        try
        {
            var sb = new StringBuilder();
            if (SceneIncident is not null) sb.AppendLine($"{SceneIncident.Title} (pid {SceneIncident.Pid}), for {_persona.Label}");
            sb.AppendLine(NarrationText);
            Clipboard.SetText(sb.ToString());
        }
        catch (Exception ex) { AppLog.Error("copy answer", ex); }
    }

    private static string RunKey(string incident, string persona) => incident + "|" + persona;

    private sealed class Run
    {
        public Run(string key, IncidentItem item, Persona persona, LlmProvider provider, string model, bool redact)
        {
            Key = key;
            Item = item;
            Persona = persona;
            Provider = provider;
            Model = model;
            Redact = redact;
        }

        public string Key { get; }
        public IncidentItem Item { get; }
        public Persona Persona { get; }
        public LlmProvider Provider { get; }
        public string Model { get; }
        public bool Redact { get; }
        public DateTime StartedUtc { get; } = DateTime.UtcNow;
        public StringBuilder Buffer { get; } = new();
        public CancellationTokenSource Cancel { get; } = new();
        public bool Completed { get; set; }
        public TriageResult? Result { get; set; }

        public string Snapshot() { lock (Buffer) return Buffer.ToString(); }
    }

    /// <summary>Stops in-flight generations and writes pending library changes; called on shutdown.</summary>
    public void CancelAll()
    {
        foreach (var r in _runs.Values) r.Cancel.Cancel();
        FlushSaves();
    }
}
