//go:build race

package probe

// RaceEnabled reports whether this build carries the race detector.
//
// It exists because tosutils-go's TL serializer performs unsafe pointer
// arithmetic that checkptr -- enabled by the race detector -- rejects, so the
// ADNL gateway cannot run under -race at all. Tests that start one skip under
// race and run in a separate non-race pass instead; a skip with no separate
// pass would be coverage quietly disappearing.
const RaceEnabled = true
