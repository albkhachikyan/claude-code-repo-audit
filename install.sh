#!/usr/bin/env bash
# Manual install: symlink this repository into ~/.claude/skills/<skill-name>.
# Prefer the plugin install (see README). Safe to re-run; never overwrites a real folder.
# Set CLAUDE_SKILLS_DIR to install somewhere else.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="$(sed -n 's/^name: *//p' "$SRC/SKILL.md" | head -1)"
[ -n "$NAME" ] || { echo "install: no 'name:' in SKILL.md frontmatter" >&2; exit 1; }
DEST_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
DEST="$DEST_DIR/$NAME"
mkdir -p "$DEST_DIR"

if [ -L "$DEST" ]; then
  if [ "$(readlink "$DEST")" = "$SRC" ]; then
    echo "ok       $NAME -> $SRC"
  else
    echo "updated  $NAME (was $(readlink "$DEST"))"
    ln -sfn "$SRC" "$DEST"
  fi
elif [ -e "$DEST" ]; then
  echo "install: $DEST exists and is not a symlink; move it away first" >&2
  exit 1
else
  ln -s "$SRC" "$DEST"
  echo "linked   $NAME -> $SRC"
fi
echo "Start a new Claude Code session, then run /$NAME"
