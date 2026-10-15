---
name: TruViq Guard
description: Triage board for every action TruViq Guard blocked, asked about and allowed across a team's coding agents.
colors:
  bar: "#17343b"
  bar-raised: "#1f444c"
  bar-muted: "#b9c8cb"
  bar-line: "#2c5059"
  board: "#f3f4f1"
  surface: "#ffffff"
  sunken: "#f6f7f4"
  ink: "#1b1f23"
  muted: "#56616a"
  line: "#dcdfd9"
  line-strong: "#bcc3bb"
  accent: "#1d5c68"
  accent-hover: "#164a54"
  accent-soft: "#e2eef0"
  deny: "#b3261e"
  deny-soft: "#fbe9e7"
  ask-fill: "#e3a21a"
  ask: "#7d5200"
  ask-ink: "#2b1d00"
  ask-soft: "#fdf2da"
  approve: "#22693f"
  approve-soft: "#e4f2e8"
typography:
  display:
    fontFamily: "Arial, Liberation Sans, Helvetica, sans-serif"
    fontSize: "28px"
    fontWeight: 700
    lineHeight: 1
    fontFeature: "tnum"
  title:
    fontFamily: "Arial, Liberation Sans, Helvetica, sans-serif"
    fontSize: "15px"
    fontWeight: 700
    lineHeight: 1.45
  body:
    fontFamily: "Calibri, Carlito, Segoe UI, Arial, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Arial, Liberation Sans, Helvetica, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.4
  label-caps:
    fontFamily: "Arial, Liberation Sans, Helvetica, sans-serif"
    fontSize: "13px"
    fontWeight: 700
    letterSpacing: "0.06em"
  mono:
    fontFamily: "ui-monospace, Cascadia Mono, Consolas, Liberation Mono, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.4
rounded:
  none: "0px"
spacing:
  xs: "6px"
  sm: "10px"
  md: "12px"
  lg: "16px"
  xl: "24px"
components:
  tag-deny:
    backgroundColor: "{colors.deny}"
    textColor: "{colors.surface}"
    typography: "{typography.label-caps}"
    height: "22px"
    padding: "0 9px 0 13px"
  tag-ask:
    backgroundColor: "{colors.ask-fill}"
    textColor: "{colors.ask-ink}"
    typography: "{typography.label-caps}"
    height: "22px"
    padding: "0 9px 0 13px"
  tag-approve:
    backgroundColor: "{colors.approve}"
    textColor: "{colors.surface}"
    typography: "{typography.label-caps}"
    height: "22px"
    padding: "0 9px 0 13px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.none}"
    padding: "12px 16px 16px"
  chip:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    height: "30px"
    padding: "0 11px"
  chip-active:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
  input-search:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.none}"
    height: "34px"
    padding: "0 10px 0 32px"
  bar-button:
    backgroundColor: "{colors.bar}"
    textColor: "{colors.surface}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "7px 12px"
  bar-button-hover:
    backgroundColor: "{colors.bar-raised}"
  range-option-active:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.bar}"
  link-button:
    textColor: "{colors.accent}"
    typography: "{typography.label-caps}"
  new-mark:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.surface}"
    height: "18px"
    padding: "0 5px"
  result-pass:
    backgroundColor: "{colors.approve-soft}"
    textColor: "{colors.approve}"
    typography: "{typography.label-caps}"
    height: "22px"
    padding: "0 9px"
  result-fail:
    backgroundColor: "{colors.deny-soft}"
    textColor: "{colors.deny}"
    typography: "{typography.label-caps}"
    height: "22px"
    padding: "0 9px"
---

# Design System: TruViq Guard

## Overview

**Creative North Star: "The Triage Board"**

The dashboard is a duty board, not a security console. Every guarded action is sorted on arrival into one of three lanes (asked a person, blocked, allowed with notes) and the whole screen is ordered by that triage, never by time first. A dark slate bar sits over a cool off-white board; square white panels with hairline borders hold the triage strip, the evidence table and the fleet and red-team rail. Colour is spent on risk and nothing else: chrome is slate, grey and one deep teal accent.

Density is that of a working ledger: 13px Arial labels and figures, 15px Calibri running text, one 28px figure size for the lane counts. Depth is flat; structure comes from hairlines, sunken table headers and tinted selected states. The system was chosen for office daylight and projector demos, and every screenshot of it has to stand up in an audit, so state is always told twice: a shape and a word.

The user's confirmed rejections are part of the world: no purple, no gradients, no glassmorphism, no fonts other than Arial and Calibri (with their metric-compatible Liberation Sans and Carlito fallbacks; no web fonts are loaded). The KPI-tiles-plus-trend-chart security console is the explicit anti-reference.

**Key Characteristics:**
- Light board (#f3f4f1) under a slate top bar; one teal accent for interaction and "new".
- Triage red, amber and green reserved for verdicts, severity and results, always with a shape mark and a word.
- Arial for headings, labels, figures and controls; Calibri for running text; exactly three sizes.
- Square corners everywhere, hairline borders, no shadows.
- Signature: the notched triage tag, carried from lane to table row to detail.

## Colors

A restrained slate-and-paper neutral field with one deep teal accent; the only saturated colours on screen are the three triage hues.

### Primary
- **Harbour Teal** (accent): links, focus outlines, pressed chips, the selected lane's underline, the NEW mark and the 3px left rule on unseen rows. Hover deepens to **Deep Harbour** (accent-hover); selected rows and the pressed lane wash in **Teal Mist** (accent-soft).

### Secondary
- **Slate Bar** (bar): the top bar ground, the browser theme colour. **Raised Slate** (bar-raised) is its hover; **Slate Rule** (bar-line) its hairlines; **Fog** (bar-muted) its secondary text.

### Tertiary (triage hues; state only)
- **Stop Red** (deny) with **Red Wash** (deny-soft): DENY tags, Critical severity, failed results, "Not approved", machine problems.
- **Signal Amber** (ask-fill) with **Amber Ink** (ask) for amber text on light ground, **Umber** (ask-ink) for text on the amber fill, and **Amber Wash** (ask-soft): ASK tags, High severity, the "N waiting" lead, inconclusive results, notice banners.
- **Pass Green** (approve) with **Green Wash** (approve-soft): APPROVE tags, PASS results, "Approved by a person", healthy machines.

### Neutral
- **Board** (board): the page ground.
- **Paper** (surface): panels, inputs, chips, the expanded detail row.
- **Sunken** (sunken): table header band, row hover, evidence blocks.
- **Ink** (ink): primary text. **Slate Grey** (muted): secondary text and metadata.
- **Hairline** (line): internal dividers and row rules. **Panel Rule** (line-strong): panel outlines, input and chip strokes, lane divider rows.

### Named Rules
**The Triage Colour Rule.** Stop Red, Signal Amber and Pass Green appear only on verdicts, severity and results (red-team, ASK outcome, machine health), and never alone: every use carries a shape mark (octagon, help circle, check, triangle, square) and a word. Chrome, headings and decoration never borrow them.

**The One Accent Rule.** Harbour Teal is the only non-triage hue. It marks interaction and newness; it never encodes risk.

**The No Purple Rule.** No purple or violet anywhere, at any tint. No gradients, no translucent or blurred glass surfaces.

## Typography

**Display Font:** Arial (with Liberation Sans, Helvetica)
**Body Font:** Calibri (with Carlito, Segoe UI, Arial)
**Label/Mono Font:** Arial for labels and figures; system monospace (ui-monospace, Cascadia Mono, Consolas, Liberation Mono) for paths, evidence, dependency lines and the chat card.

**Character:** Arial carries everything that is read as data (headings, labels, controls, counts, times) with tabular figures; Calibri softens the sentences that explain them. Both are system faces, so the board renders identically offline.

### Hierarchy
- **Display** (700, 28px, line-height 1, tabular): lane counts only.
- **Title** (Arial 700, 15px): lane names, "what happened" titles, finding titles, machine names, brand name.
- **Body** (Calibri 400, 15px, 1.45): summaries, finding text, empty states (max 52ch), banners.
- **Label** (Arial 400, 13px): metadata, times, machine and source lines, buttons, chips, range control, facts lists.
- **Label caps** (Arial 700, 13px, uppercase, 0.05 to 0.06em): panel headings, table headers, lane divider rows, sub-headings in the detail row, verdict and result words.
- **Mono** (13px, 1.4 to 1.5): literal file paths, evidence, dependency diff lines, the chat card.

### Named Rules
**The Three Sizes Rule.** 13px, 15px and 28px. Nothing else. Hierarchy comes from weight, case, family and colour, not from new sizes.

**The Two Faces Rule.** Arial for headings, labels and figures; Calibri for running text. Monospace only for literal machine text (paths, code, evidence). No web fonts.

## Layout

A centred board, max 1480px, with a 24px gap and padding (16px below 560px). At 1181px and up the page is a two-column grid: a fluid main column (triage strip above the events panel) and a 340px right rail stacking Fleet health, Nightly red team and Most frequent detectors.

From 861 to 1180px the rail dissolves into the page grid: Fleet health and Nightly red team sit 2-up between the triage strip and the table, the detectors panel follows the table. At 860px and below everything stacks in one column (triage, fleet, red team, events, detectors), the triage lanes stack and show only their newest item, the top bar wraps, and table rows become two-column cards with the header hidden and lane dividers kept.

The triage strip is three equal lanes divided by hairlines. The events table defaults to triage order with full-width lane divider rows ("Asked a person · waiting for a decision", "Asked a person · decided", "Blocked", "Allowed with notes"); the Verdict header restores that order, severity and time remain sortable. Spacing rhythm: 6px between chips and tokens, 10px small gaps, 12px cell and filter padding, 16px panel padding, 24px between panels.

## Elevation & Depth

Flat. No box shadows, no lifted cards, no blur. Depth is told by tone and line: panels are Paper on Board with a Panel Rule outline; the table header and hovered rows drop to Sunken; the open row and pressed lane take Teal Mist; the expanded detail row closes with a Panel Rule. The only dark inset is the chat-card preview, a slate code block that reproduces what the developer saw.

### Named Rules
**The Hairline Rule.** Structure is drawn with 1px lines (Hairline inside panels, Panel Rule around them), never with shadow. The one heavier line is the 3px Harbour Teal left rule on unseen rows and the 2px teal underline on the pressed lane.

## Shapes

Square material throughout (0px radius) on panels, inputs, chips, buttons, the range control, evidence and dependency tokens. The one non-rectangular silhouette is the triage tag: a label with a notched left point (an 8px chevron cut), no eyelet. Severity marks are small geometric glyphs drawn in CSS: a filled square (Critical), a filled triangle (High), a ring (Medium), an outlined square (Low/Info).

## Components

### Triage Tag (signature)
A notched label (22px high, chevron-cut left edge) with a lucide shape mark (octagon-x, circle-help, circle-check at 13px) and the verdict word in caps. DENY is Stop Red with white text, ASK is Signal Amber with Umber text, APPROVE is Pass Green with white text. The same tag appears in the lane head, the table row and the detail.

### Triage Strip
Three lane buttons, each with tag, lane name, a 28px count and a worded sub-line ("N waiting" leads the ASK lane in Amber Ink). Hover drops to Sunken; the pressed lane filters the table and shows Teal Mist with a 2px teal underline. Below, the three newest items with title and "machine · time ago", and a "Show all N in the table" link.

### Buttons
- **Shape:** square (0px).
- **Bar button:** transparent on slate with a Slate Rule hairline, white 13px Arial, 7px 12px padding; hover Raised Slate; disabled at 55% opacity.
- **Range control:** a segmented hairline group on the slate bar; the active option inverts to white with slate bold text.
- **Link button:** 13px bold Arial in Harbour Teal; underline appears on hover.

### Chips
- **Style:** Paper, Panel Rule stroke, 30px high, 13px Arial label with a bold tabular count.
- **State:** hover turns the stroke teal; pressed fills Harbour Teal with white text.

### Cards / Containers
- **Corner Style:** square (0px).
- **Background:** Paper on Board.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px Panel Rule.
- **Internal Padding:** head 14px 16px 10px with a Hairline under it; body 12px 16px 16px. Panel headings are 13px caps Arial with right-aligned muted metadata.

### Inputs / Fields
- **Style:** 34px high, Paper, Panel Rule stroke, square; search carries a muted magnifier at 10px inset; the select uses an inline chevron.
- **Focus:** global 2px Harbour Teal outline, 2px offset.

### Event Table
Sticky Sunken header in caps; 11px 12px cells on Hairline rules; hover Sunken, open Teal Mist. Columns: verdict tag (with NEW mark and lucide chevron disclosure), severity mark, what happened (bold title, two-line clamped summary, ASK outcome with icon and word), machine, where (literal path in mono, or project in Arial, over a worded source line such as "Shell command", "File write"), when. The detail row reveals findings, evidence, dependency tokens, facts, control tags and the chat-card disclosure; chevrons rotate 90deg over 160ms and the detail fades in over 220ms (ease cubic-bezier(0.22, 1, 0.36, 1)), both off under reduced motion.

### New Since You Looked
A worded NEW mark (teal fill, white caps) plus the 3px teal left rule on the row. It persists until the action is opened or "Mark N as seen" is pressed; a first visit treats everything as new.

### Severity Mark and Result
Severity: CSS shape plus word, Critical additionally in bold Stop Red. Red-team result: a lucide mark plus PASS / FAIL / INCONCLUSIVE in caps, as a washed chip or as plain coloured text in history lines.

## Do's and Don'ts

### Do:
- **Do** pair every triage colour with a shape mark and a word (verdict tags, severity marks, results, ASK outcomes, machine health).
- **Do** keep to three type sizes: 13px, 15px, 28px.
- **Do** set headings, labels, controls and figures in Arial with tabular numerals, and running text in Calibri.
- **Do** keep every surface square (0px) with 1px hairline borders (#bcc3bb around panels, #dcdfd9 inside).
- **Do** order evidence by triage first, with lane divider rows, and let headers re-sort by severity or time.
- **Do** show literal paths in monospace and describe the source in words.
- **Do** use Harbour Teal for interaction, focus and newness only.

### Don't:
- **Don't** use purple, gradients or glassmorphism.
- **Don't** load web fonts or use any face other than Arial and Calibri (system monospace for literal code only).
- **Don't** use red, amber or green on chrome, headings or decoration, or as colour alone.
- **Don't** add shadows or rounded corners to panels, chips, inputs or buttons.
- **Don't** add a fourth type size.
- **Don't** build KPI tiles or trend charts; counts live in the triage lanes.
