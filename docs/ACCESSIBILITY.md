# Accessibility

The CrioFire app (`criofire-ui.exe`) is meant to work for everyone who runs it: from the keyboard
alone, with a screen reader, and with a Windows contrast theme. This page says what is in place
and how to keep it that way.

## Keyboard

| Keys | What they do |
| --- | --- |
| Tab, Shift+Tab | Move between controls; a ring shows where the focus is |
| Enter, Space | Press the focused button, or open the focused Dashboard panel or row |
| Arrow keys | Move within a table, a menu or a set of choices (mode, filters) |
| Shift+F10 or the Menu key | The right-click menu of the selected row |
| Ctrl+1 … Ctrl+6 | Dashboard, Activity, Rules, Connections, Reports, Settings |
| F5 | Reload the open page |
| Ctrl+F | The search box (Activity, Rules) |
| Escape | Close a dialog or the durations list of an alert |

In an Ask-mode alert, Enter or Space on "Allow 1 hour" confirms it, and the Up or Down arrow opens
the other durations. Alerts do not take the focus away from what you are doing; Alt+Tab reaches them.

## Screen readers

- Buttons, switches and fields have names; icon buttons are named after their tooltip.
- The Dashboard's panels and rows that open something are buttons named after their tooltip or
  the program they show, and say what is inside them.
- Table rows read as their main cells ("Chat.exe, Blocked, Outbound, 203.0.113.5, 14:02"), and the
  tables are named after their headings. Page and card titles are headings, so screen readers can
  jump between them.
- Charts are described in words: each bar that has anything, as its tooltip says it.
- Messages ("Allowed Chat.exe."), the panic and changed-program banners, a new version, Ask-mode
  alerts and questions in dialogs are announced as they appear, without moving the focus.

## Contrast themes

With a Windows contrast theme on (Settings → Accessibility → Contrast themes), the app uses that
theme's colors for everything, follows a switch to another contrast theme, turns off its glows,
and hides the light/dark switch. Allowed and blocked keep their words, since they no longer have
their own colors.

## Keeping it accessible

- A new clickable panel uses `ClickableCard` (`src/CrioFire.App/Accessibility.cs`), not a mouse
  handler on a border: it adds the keyboard, the focus ring and the screen-reader button.
- A button showing only an icon gets `AutomationProperties.Name` (an English text, translated
  like the rest).
- A new color goes in Dark.xaml, Light.xaml and HighContrast.xaml (there as a system color), and
  never directly into a page.
- Something that appears on its own (a message, a banner) also goes to `ScreenReader.Say`.
- A new table row type overrides `ToString()` with `RowText.Join(...)`: that is what screen
  readers say for the row.
- Check with Narrator (Ctrl+Win+Enter) and a contrast theme before a release.
