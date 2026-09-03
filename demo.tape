# VHS tape for docs/demo.gif — regenerate with:  vhs demo.tape
# VHS: https://github.com/charmbracelet/vhs  (brew install vhs)
#
# Run this from the repo root with the dev venv present (`uv sync`).
# Keep the two runs below in sync with README's demo section: this GIF is a
# recording of real output, and re-recording it is how it stays true.
#
# Width/Height are sized to the *whole* default-set report (52 patterns is
# ~48 lines plus the prompt and exit code). If the report format or the
# pattern count changes, re-check that the score line at the top is still
# on screen in the final frame - the terminal scrolls, so an output taller
# than Height silently pushes the headline result out of the recording.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 860
Set Height 900
Set Padding 18
Set TypingSpeed 35ms
Set Framerate 20
Set Theme "Catppuccin Mocha"

# Setup is hidden: activate the dev venv and use a bare `$ ` prompt.
# The banner is `cat`ed here, not printed by raginject itself: the CLI must
# keep stdout clean for `--output json` and CI logs, so the wordmark lives in
# docs/banner.txt (same art as README's) and only ever appears in this GIF.
Hide
Type "source .venv/bin/activate && export PS1='$ ' && clear && cat docs/banner.txt && echo && echo '  indirect prompt injection testing for RAG pipelines'" Enter
Show

Sleep 2500ms

Hide
Type "clear" Enter
Show
Sleep 800ms

# 1. A naive pipeline: the injected instructions reach the answer, and the
#    --min-score gate fails the build.
Type "raginject run --target-module raginject.demo:vulnerable_rag --min-score 0.8"
Sleep 500ms
Enter
Sleep 3s
Type "echo $?"
Sleep 300ms
Enter
Sleep 2500ms

Hide
Type "clear" Enter
Show
Sleep 500ms

# 2. A pipeline that treats retrieved text as data, never as instructions.
Type "raginject run --target-module raginject.demo:defended_rag --min-score 1.0"
Sleep 500ms
Enter
Sleep 3s
Type "echo $?"
Sleep 300ms
Enter
Sleep 3s
