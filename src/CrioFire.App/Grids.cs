using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CrioFire.Core;

namespace CrioFire.App;

/// <summary>
/// Sorting a list by clicking a column heading: first click ascending, second descending, third
/// back to the page's own order. The page asks <see cref="Apply"/> for its rows in that order
/// (before cutting them into pages), and is told through <c>changed</c> to show them again.
/// </summary>
internal sealed class ColumnSorter<T>
{
    private readonly ListView _list;
    private readonly (string Header, Func<T, object?> Key)[] _columns;
    private string? _header;
    private ListSortDirection _direction;

    /// <param name="columns">The sortable columns: their English heading (shown translated) and what a row sorts by.</param>
    public ColumnSorter(ListView list, Action changed, params (string Header, Func<T, object?> Key)[] columns)
    {
        _list = list;
        _columns = columns;
        list.AddHandler(GridViewColumnHeader.ClickEvent, new RoutedEventHandler((_, e) =>
        {
            if (e.OriginalSource is not GridViewColumnHeader { Column: { } column })
            {
                return;
            }

            var shown = Plain(column.Header as string);
            var header = _columns.FirstOrDefault(c => c.Header == shown || L.T(c.Header) == shown).Header;
            if (header is null)
            {
                return;
            }

            if (_header != header)
            {
                (_header, _direction) = (header, ListSortDirection.Ascending);
            }
            else if (_direction == ListSortDirection.Ascending)
            {
                _direction = ListSortDirection.Descending;
            }
            else
            {
                _header = null;
            }

            ShowArrow();
            changed();
        }));
    }

    /// <summary>The rows in the chosen order; in their own order when no column is chosen.</summary>
    public List<T> Apply(IEnumerable<T> rows)
    {
        var key = _columns.FirstOrDefault(c => c.Header == _header).Key;
        if (_header is null || key is null)
        {
            return [.. rows];
        }

        return _direction == ListSortDirection.Ascending
            ? [.. rows.OrderBy(key, Values.Instance)]
            : [.. rows.OrderByDescending(key, Values.Instance)];
    }

    /// <summary>Marks the sorted column's heading with an arrow.</summary>
    private void ShowArrow()
    {
        if (_list.View is not GridView grid)
        {
            return;
        }

        var sorted = _header is null ? null : L.T(_header);
        foreach (var column in grid.Columns)
        {
            var plain = Plain(column.Header as string);
            if (column.Header is string)
            {
                column.Header = plain == sorted || plain == _header ? $"{plain} {(_direction == ListSortDirection.Ascending ? "▲" : "▼")}" : plain;
            }
        }
    }

    private static string Plain(string? header) =>
        (header ?? string.Empty).Replace(" ▲", string.Empty, StringComparison.Ordinal).Replace(" ▼", string.Empty, StringComparison.Ordinal);

    /// <summary>Text without regard to case, numbers and times by value, nothing before something.</summary>
    private sealed class Values : IComparer<object?>
    {
        public static readonly Values Instance = new();

        public int Compare(object? x, object? y) => (x, y) switch
        {
            (null, null) => 0,
            (null, _) => -1,
            (_, null) => 1,
            (string a, string b) => string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase),
            (IComparable a, { } b) when a.GetType() == b.GetType() => a.CompareTo(b),
            ({ } a, { } b) => string.Compare(a.ToString(), b.ToString(), StringComparison.CurrentCultureIgnoreCase),
        };
    }
}

/// <summary>
/// Shows a long list a page at a time: "Rows 1–50 of 312" with Previous and Next. Put
/// <see cref="View"/> under the list; it hides itself while everything fits on one page.
/// </summary>
internal sealed class Pager
{
    public const int DefaultSize = 50;

    private readonly int _size;
    private readonly Button _previous;
    private readonly Button _next;
    private readonly TextBlock _text;
    private int _page;

    public Pager(Action changed, int size = DefaultSize)
    {
        _size = size;
        _text = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        _previous = new Button { Content = L.T("‹ Previous"), MinHeight = 34, Margin = new Thickness(0, 0, 8, 0) };
        _next = new Button { Content = L.T("Next ›"), MinHeight = 34 };
        if (Application.Current?.TryFindResource("OutlineIceButton") is Style button)
        {
            _previous.Style = _next.Style = button;
        }

        if (Application.Current?.TryFindResource("Muted") is Style muted)
        {
            _text.Style = muted;
        }

        _previous.Click += (_, _) =>
        {
            _page--;
            changed();
        };
        _next.Click += (_, _) =>
        {
            _page++;
            changed();
        };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal };
        buttons.Children.Add(_previous);
        buttons.Children.Add(_next);
        DockPanel.SetDock(buttons, Dock.Right);
        var panel = new DockPanel { Margin = new Thickness(0, 14, 0, 0), Visibility = Visibility.Collapsed };
        panel.Children.Add(buttons);
        panel.Children.Add(_text);
        View = panel;
    }

    public FrameworkElement View { get; }

    /// <summary>Back to the first page: after a new search, filter or sort.</summary>
    public void First() => _page = 0;

    /// <summary>The rows of the current page (the last page, if the list became shorter), and the line that says which.</summary>
    public List<T> Slice<T>(IReadOnlyList<T> all)
    {
        var pages = Math.Max(1, (all.Count + _size - 1) / _size);
        _page = Math.Clamp(_page, 0, pages - 1);
        var rows = all.Skip(_page * _size).Take(_size).ToList();
        View.Visibility = all.Count > _size ? Visibility.Visible : Visibility.Collapsed;
        _previous.IsEnabled = _page > 0;
        _next.IsEnabled = _page < pages - 1;
        _text.Text = Fmt.Rows(_page * _size + 1, _page * _size + rows.Count, all.Count);
        return rows;
    }
}

/// <summary>How a list uses the room it has.</summary>
internal static class GridLayout
{
    /// <summary>
    /// Gives the last column whatever width the other columns leave (never less than
    /// <paramref name="minimum"/>), also after the window or another column is resized.
    /// </summary>
    public static void FillLastColumn(ListView list, double minimum)
    {
        if (list.View is not GridView { Columns.Count: > 1 } grid)
        {
            return;
        }

        var last = grid.Columns[^1];
        var fitting = false;
        void Fit()
        {
            if (fitting || list.ActualWidth <= 0)
            {
                return;
            }

            fitting = true;
            try
            {
                var others = grid.Columns.Take(grid.Columns.Count - 1).Sum(c => c.ActualWidth);
                var width = Math.Max(minimum, list.ActualWidth - others - SystemParameters.VerticalScrollBarWidth - 12);
                if (Math.Abs(last.ActualWidth - width) > 1)
                {
                    last.Width = width;
                }
            }
            finally
            {
                fitting = false;
            }
        }

        list.SizeChanged += (_, _) => Fit();
        list.Loaded += (_, _) => Fit();
        foreach (var column in grid.Columns.Take(grid.Columns.Count - 1))
        {
            ((INotifyPropertyChanged)column).PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(GridViewColumn.ActualWidth))
                {
                    Fit();
                }
            };
        }
    }

    /// <summary>
    /// Makes a page as tall as the window's page area (never less than <paramref name="minimum"/>,
    /// below which the window scrolls), so a list inside it can take the room that is left.
    /// </summary>
    public static void FillHeight(FrameworkElement page, double minimum)
    {
        ScrollViewer? host = null;
        void Fit(object? sender, EventArgs e)
        {
            if (host is not null && host.ViewportHeight > 0)
            {
                page.Height = Math.Max(minimum, host.ViewportHeight);
            }
        }

        page.Loaded += (_, _) =>
        {
            if (host is not null)
            {
                host.SizeChanged -= Fit;
            }

            DependencyObject? parent = page;
            while (parent is not null and not ScrollViewer)
            {
                parent = VisualTreeHelper.GetParent(parent);
            }

            host = parent as ScrollViewer;
            if (host is not null)
            {
                host.SizeChanged += Fit;
                Fit(null, EventArgs.Empty);
            }
        };
        page.Unloaded += (_, _) =>
        {
            if (host is not null)
            {
                host.SizeChanged -= Fit;
                host = null;
            }
        };
    }
}
